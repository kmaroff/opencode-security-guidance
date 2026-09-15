#!/usr/bin/env python3
"""Narrow one-shot bridge between the OpenCode adapter and security core.

stdout is protocol JSON only. Diagnostics are bounded and go to stderr.
"""
from __future__ import annotations

import json
import os
import re
import subprocess
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
HOOKS = ROOT / "hooks"
sys.path.insert(0, str(HOOKS))

from diffstate import (  # noqa: E402
    _append_reviewed_shas,
    _load_reviewed_shas,
    _list_untracked,
    capture_git_baseline,
    compute_v2_review_set,
)
from security_reminder_hook import (  # noqa: E402
    _compute_push_sweep_base,
    _detect_main_branch,
    _git_rev_list_range,
    _PUSH_RANGE_RE,
    _push_section,
)
from extensibility import guidance_block, load_for_session  # noqa: E402
from gitutil import (  # noqa: E402
    GIT_CMD,
    _git_diff_range,
    _git_rev_parse_head,
    _git_toplevel,
    filter_preexisting_from_diff,
    get_git_diff,
    parse_diff_into_files,
)
from reporesolve import COMMIT_SUBCOMMANDS, PUSH_SUBCOMMANDS, toplevel_from_command  # noqa: E402
from patterns import SECURITY_PATTERNS  # noqa: E402
from review_api import filter_by_severity  # noqa: E402
from security_reminder_hook import check_patterns  # noqa: E402

PROTOCOL_VERSION = "1"
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_DIFF_BYTES = 1_000_000
MAX_DIFF_FILES = 200
FULL_SHA_RE = re.compile(r"^[0-9a-f]{40}$", re.I)


class BridgeGitError(RuntimeError):
    def __init__(self, kind: str, message: str):
        super().__init__(message)
        self.kind = kind


def _error(kind: str, message: str) -> dict[str, Any]:
    safe = str(message).replace("\n", " ")[:240]
    return {"protocolVersion": PROTOCOL_VERSION, "ok": False, "error": {"kind": kind, "message": safe}}


def _result(value: Any) -> dict[str, Any]:
    return {"protocolVersion": PROTOCOL_VERSION, "ok": True, "result": value}


def _matches(path: str, content: str, baseline: str | None = None, cwd: str | None = None) -> dict[str, Any]:
    load_for_session(cwd)
    current = check_patterns(path, content or "")
    old = set(rule for rule, _ in check_patterns(path, baseline)) if baseline is not None else set()
    pairs = [(rule, reminder) for rule, reminder in current if rule not in old]
    return {"matches": [{"ruleName": rule, "reminder": reminder} for rule, reminder in pairs]}


def _repo_for_command(cwd: str, command: str, subcommands: set[tuple[str, str]]) -> str | None:
    if not cwd:
        return None
    root = _git_toplevel(cwd)
    command_root = toplevel_from_command(command, cwd, subcommands, root)
    return command_root or root


def _resolve_sha(repo: str, ref: str, kind: str) -> str:
    if not isinstance(ref, str) or not ref:
        raise BridgeGitError(kind, "missing Git ref")
    try:
        result = subprocess.run([*GIT_CMD, "rev-parse", "--verify", "-q", ref], cwd=repo, capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BridgeGitError(kind, "Git ref resolution failed") from exc
    value = result.stdout.decode("utf-8", "replace").strip()
    if result.returncode != 0 or not FULL_SHA_RE.fullmatch(value):
        raise BridgeGitError(kind, "Git ref resolution failed")
    return value


def _rev_list(repo: str, old: str, new: str, kind: str) -> list[str]:
    try:
        result = subprocess.run([*GIT_CMD, "rev-list", "--reverse", f"{old}..{new}"], cwd=repo, capture_output=True, timeout=10)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BridgeGitError(kind, "Git revision range failed") from exc
    if result.returncode != 0:
        raise BridgeGitError(kind, "Git revision range failed")
    return [line for line in result.stdout.decode("utf-8", "replace").splitlines() if FULL_SHA_RE.fullmatch(line)]


def _review_set(request: dict[str, Any]) -> dict[str, Any]:
    cwd = str(request.get("cwd") or "")
    paths, diff_base, repo, untracked, metrics = compute_v2_review_set(
        cwd,
        request.get("baselineSha"),
        request.get("headAtCapture"),
        request.get("untrackedAtBaseline") or {},
    )
    if not repo or not paths:
        return {"repoRoot": repo, "paths": paths, "diffBase": diff_base, "diff": "", "diffFiles": [], "diffAvailable": True, "diffStatus": "VALID_EMPTY_DIFF", "metrics": metrics}
    baseline = request.get("baselineSha") or diff_base
    diff = get_git_diff(repo, baseline, full_context=False, paths=paths, untracked_paths=untracked)
    if diff is None and baseline != diff_base:
        diff = get_git_diff(repo, diff_base, full_context=False, paths=paths, untracked_paths=untracked)
    if diff is None:
        raise BridgeGitError("git_diff_failed", "Git diff extraction failed")
    files = filter_preexisting_from_diff(parse_diff_into_files(diff), repo, baseline)
    return {
        "repoRoot": repo,
        "paths": paths,
        "diffBase": diff_base,
        "diff": diff[:MAX_DIFF_BYTES],
        "diffFiles": [[path, body[:MAX_DIFF_BYTES]] for path, body in files[:MAX_DIFF_FILES]],
        "diffAvailable": True,
        "diffStatus": "VALID_DIFF" if diff else "VALID_EMPTY_DIFF",
        "metrics": metrics,
    }


def _commit_data(request: dict[str, Any]) -> dict[str, Any]:
    cwd = str(request.get("cwd") or "")
    command = str(request.get("command") or "")
    repo = _repo_for_command(cwd, command, COMMIT_SUBCOMMANDS)
    if not repo:
        raise BridgeGitError("commit_target_resolution_failed", "commit repository could not be resolved")
    if request.get("interrupted") or (isinstance(request.get("exitCode"), int) and request["exitCode"] != 0):
        raise BridgeGitError("commit_failed", "commit operation did not succeed")
    before = _resolve_sha(repo, str(request.get("beforeHead") or ""), "commit_target_resolution_failed")
    after = _resolve_sha(repo, "HEAD", "commit_target_resolution_failed")
    if before == after:
        return {"repoRoot": repo, "oldSha": before, "newSha": after, "shas": [], "diffFiles": [], "diffAvailable": True, "diffStatus": "VALID_EMPTY_DIFF", "noOp": True}
    if re.search(r"\b(?:git|gt)\b[^;&|]*(?:commit|create|modify)\b", command, re.I) is None:
        raise BridgeGitError("commit_target_resolution_failed", "commit command semantics were not verified")
    try:
        normal = subprocess.run([*GIT_CMD, "merge-base", "--is-ancestor", before, after], cwd=repo, capture_output=True, timeout=5)
    except (OSError, subprocess.SubprocessError) as exc:
        raise BridgeGitError("commit_target_resolution_failed", "commit ancestry check failed") from exc
    shas = _rev_list(repo, before, after, "commit_target_resolution_failed") if normal.returncode == 0 else [after]
    files: list[tuple[str, str]] = []
    for sha in shas:
        try:
            result = subprocess.run([*GIT_CMD, "show", "-p", "--no-color", "--no-ext-diff", "--no-textconv", sha, "--"], cwd=repo, capture_output=True, timeout=15)
        except (OSError, subprocess.SubprocessError) as exc:
            raise BridgeGitError("git_show_failed", "Git commit extraction failed") from exc
        if result.returncode != 0:
            raise BridgeGitError("git_show_failed", "Git commit extraction failed")
        files.extend(parse_diff_into_files(result.stdout.decode("utf-8", "replace")))
    unique: list[list[str]] = []
    seen_paths: set[str] = set()
    for file_path, body in files:
        if file_path not in seen_paths:
            seen_paths.add(file_path)
            unique.append([file_path, body[:MAX_DIFF_BYTES]])
    return {"repoRoot": repo, "oldSha": before, "newSha": after, "shas": shas, "diffFiles": unique[:MAX_DIFF_FILES], "diffAvailable": True, "diffStatus": "VALID_DIFF" if unique else "VALID_EMPTY_DIFF", "noOp": False}


def _push_data(request: dict[str, Any]) -> dict[str, Any]:
    cwd = str(request.get("cwd") or "")
    command = str(request.get("command") or "")
    output = str(request.get("output") or "")
    repo = _repo_for_command(cwd, command, PUSH_SUBCOMMANDS)
    if not repo:
        raise BridgeGitError("push_target_resolution_failed", "push repository could not be resolved")
    if request.get("interrupted") or (isinstance(request.get("exitCode"), int) and request["exitCode"] != 0):
        raise BridgeGitError("push_failed", "push operation did not succeed")
    section = _push_section(output)
    ranges = list(_PUSH_RANGE_RE.finditer(section))
    if len(ranges) > 1:
        raise BridgeGitError("push_target_resolution_failed", "multiple pushed refs were reported")
    new_branch = re.findall(r"^\s*\*\s+\[new branch\]\s+(\S+)\s+->\s+(\S+)", section, re.M)
    if len(new_branch) > 1:
        raise BridgeGitError("push_target_resolution_failed", "multiple pushed refs were reported")
    if ranges:
        match = ranges[0]
        old_token, new_token, local_ref, remote_ref = match.groups()
        old_sha = _resolve_sha(repo, old_token, "push_target_resolution_failed")
        new_sha = _resolve_sha(repo, local_ref, "push_target_resolution_failed")
        if not new_sha.startswith(new_token.lower()):
            raise BridgeGitError("push_target_resolution_failed", "pushed local ref does not match reported new SHA")
        remote_name = remote_ref if remote_ref.startswith("refs/") else f"refs/heads/{remote_ref}"
    elif new_branch:
        local_ref, remote_ref = new_branch[0]
        old_sha = None
        new_sha = _resolve_sha(repo, local_ref, "push_target_resolution_failed")
        remote_name = remote_ref if remote_ref.startswith("refs/") else f"refs/heads/{remote_ref}"
        main = _detect_main_branch(repo)
        if not main:
            raise BridgeGitError("push_target_resolution_failed", "new branch base could not be resolved")
        try:
            base_result = subprocess.run([*GIT_CMD, "merge-base", new_sha, main], cwd=repo, capture_output=True, timeout=5)
        except (OSError, subprocess.SubprocessError) as exc:
            raise BridgeGitError("push_target_resolution_failed", "new branch base failed") from exc
        if base_result.returncode != 0:
            raise BridgeGitError("push_target_resolution_failed", "new branch base failed")
        old_sha = base_result.stdout.decode("utf-8", "replace").strip()
    elif "everything up-to-date" in section.lower():
        return {"repoRoot": repo, "oldSha": None, "newSha": None, "remoteRef": None, "shas": [], "tail": [], "diffFiles": [], "base": None, "diffAvailable": True, "diffStatus": "VALID_EMPTY_DIFF", "alreadyReviewed": False, "noOp": True}
    else:
        raise BridgeGitError("push_target_resolution_failed", "push success and target were not proven")
    if not old_sha or not FULL_SHA_RE.fullmatch(old_sha):
        raise BridgeGitError("push_target_resolution_failed", "push old SHA was not resolved")
    pushed = _rev_list(repo, old_sha, new_sha, "push_target_resolution_failed")
    reviewed = _load_reviewed_shas(repo)
    base, tail = _compute_push_sweep_base(old_sha, pushed, reviewed)
    if base is None:
        return {"repoRoot": repo, "oldSha": old_sha, "newSha": new_sha, "remoteRef": remote_name, "shas": pushed, "tail": [], "diffFiles": [], "base": None, "diffAvailable": True, "diffStatus": "VALID_EMPTY_DIFF", "alreadyReviewed": True}
    diff = _git_diff_range(repo, base, new_sha)
    if diff is None:
        raise BridgeGitError("git_diff_failed", "Git push diff extraction failed")
    files = parse_diff_into_files(diff)
    return {"repoRoot": repo, "oldSha": old_sha, "newSha": new_sha, "remoteRef": remote_name, "shas": pushed, "tail": tail, "diffFiles": [[p, b[:MAX_DIFF_BYTES]] for p, b in files[:MAX_DIFF_FILES]], "base": base, "diffAvailable": True, "diffStatus": "VALID_DIFF" if diff else "VALID_EMPTY_DIFF", "alreadyReviewed": False}

def _operation_before(request: dict[str, Any]) -> dict[str, Any]:
    cwd = str(request.get("cwd") or "")
    command = str(request.get("command") or "")
    operation = str(request.get("operation") or "")
    subcommands = COMMIT_SUBCOMMANDS if operation == "commit" else PUSH_SUBCOMMANDS
    repo = _repo_for_command(cwd, command, subcommands)
    if not repo:
        kind = "push_target_resolution_failed" if operation == "push" else "commit_target_resolution_failed"
        raise BridgeGitError(kind, "operation repository could not be resolved")
    head = _git_rev_parse_head(repo)
    if not head:
        kind = "push_target_resolution_failed" if operation == "push" else "commit_target_resolution_failed"
        raise BridgeGitError(kind, "operation pre-head could not be resolved")
    return {"repoRoot": repo, "preHead": head}

def _mark_reviewed(request: dict[str, Any]) -> dict[str, Any]:
    repo = str(request.get("repoRoot") or "")
    shas = [s for s in request.get("shas", []) if isinstance(s, str) and FULL_SHA_RE.fullmatch(s)]
    if not repo or not shas:
        return {"acknowledged": False, "shas": []}
    _append_reviewed_shas(repo, shas, vulns_found=int(request.get("findings", 0) or 0))
    current = _load_reviewed_shas(repo)
    missing = [sha for sha in shas if sha not in current]
    if missing:
        raise BridgeGitError("reviewed_sha_ack_failed", "reviewed SHA acknowledgement failed")
    return {"acknowledged": True, "shas": shas}


def dispatch(request: dict[str, Any]) -> Any:
    if not isinstance(request, dict):
        raise ValueError("request must be an object")
    op = request.get("op")
    if op == "ping":
        return {"protocolVersion": PROTOCOL_VERSION, "bridge": "opencode-security-guidance", "healthy": True}
    if op == "core.info":
        return {"upstream": "da823e86c8feef13b73b6712af11eadd38c992f6", "patternRules": len(SECURITY_PATTERNS), "python": sys.version.split()[0]}
    if op == "pattern.scan":
        return _matches(str(request.get("path") or ""), str(request.get("content") or ""), request.get("baselineContent"), request.get("cwd"))
    if op == "review.guidance":
        load_for_session(str(request.get("cwd") or ""))
        return {"guidance": guidance_block()}
    if op == "git.baselineContent":
        baseline = request.get("baselineSha")
        file_path = str(request.get("path") or "")
        cwd = str(request.get("cwd") or "")
        if not baseline or not file_path or not cwd:
            return {"content": None}
        try:
            relative = os.path.relpath(os.path.abspath(file_path), os.path.abspath(cwd))
            result = subprocess.run([*GIT_CMD, "show", f"{baseline}:{relative}"], cwd=cwd, capture_output=True, timeout=5)
            content = result.stdout.decode("utf-8", "replace") if result.returncode == 0 else None
        except (OSError, subprocess.SubprocessError, ValueError):
            content = None
        return {"content": content}
    if op == "git.operationBefore":
        return _operation_before(request)
    if op == "git.capture":
        cwd = str(request.get("cwd") or "")
        return {"baselineSha": capture_git_baseline(cwd), "headAtCapture": _git_rev_parse_head(cwd), "untrackedAtBaseline": _list_untracked(cwd)}
    if op == "git.reviewSet":
        return _review_set(request)
    if op == "git.commitData":
        return _commit_data(request)
    if op == "git.pushData":
        return _push_data(request)
    if op == "git.markReviewed":
        return _mark_reviewed(request)
    if op == "review.accept":
        findings = request.get("findings")
        if not isinstance(findings, list):
            raise ValueError("findings must be an array")
        clean = [dict(item) for item in findings if isinstance(item, dict)]
        return {"findings": filter_by_severity(clean, include_medium=True)}
    raise ValueError(f"unknown operation: {op!r}")



def main() -> int:
    raw = sys.stdin.buffer.read(MAX_REQUEST_BYTES + 1)
    if len(raw) > MAX_REQUEST_BYTES:
        print(json.dumps(_error("request_too_large", "request exceeds limit")), flush=True)
        return 2
    try:
        request = json.loads(raw.decode("utf-8"))
        response = _result(dispatch(request))
    except json.JSONDecodeError as exc:
        response = _error("invalid_json", f"invalid JSON at {exc.pos}")
    except BridgeGitError as exc:
        print(f"bridge error: {exc.kind}", file=sys.stderr, flush=True)
        response = _error(exc.kind, str(exc))
    except Exception as exc:  # bridge boundary: never emit traceback on stdout
        print(f"bridge error: {type(exc).__name__}: {str(exc)[:240]}", file=sys.stderr, flush=True)
        response = _error("bridge_error", type(exc).__name__)
    print(json.dumps(response, ensure_ascii=False, separators=(",", ":")), flush=True)
    return 0 if response.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
