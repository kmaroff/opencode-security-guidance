#!/usr/bin/env python3
"""Narrow one-shot bridge between the OpenCode adapter and security core.

stdout is protocol JSON only. Diagnostics are bounded and go to stderr.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import sys
import time
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
    _detect_prev_upstream,
    _git_rev_list_range,
)
from extensibility import load_for_session  # noqa: E402
from gitutil import (  # noqa: E402
    GIT_CMD,
    _git_diff_range,
    _git_rev_parse_head,
    _git_toplevel,
    filter_preexisting_from_diff,
    get_git_diff,
    parse_diff_into_files,
)
from patterns import SECURITY_PATTERNS  # noqa: E402
from review_api import filter_by_severity  # noqa: E402
from security_reminder_hook import check_patterns  # noqa: E402

PROTOCOL_VERSION = "1"
MAX_REQUEST_BYTES = 2 * 1024 * 1024
MAX_DIFF_BYTES = 1_000_000
SHA_RE = re.compile(r"\b[0-9a-f]{7,40}\b", re.I)


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


def _review_set(request: dict[str, Any]) -> dict[str, Any]:
    cwd = str(request.get("cwd") or "")
    paths, diff_base, repo, untracked, metrics = compute_v2_review_set(
        cwd,
        request.get("baselineSha"),
        request.get("headAtCapture"),
        request.get("untrackedAtBaseline") or {},
    )
    if not repo or not paths:
        return {"repoRoot": repo, "paths": paths, "diffBase": diff_base, "diff": "", "diffFiles": [], "metrics": metrics}
    baseline = request.get("baselineSha") or diff_base
    diff = get_git_diff(repo, baseline, full_context=False, paths=paths, untracked_paths=untracked)
    if diff is None and baseline != diff_base:
        diff = get_git_diff(repo, diff_base, full_context=False, paths=paths, untracked_paths=untracked)
    diff = diff or ""
    files = filter_preexisting_from_diff(parse_diff_into_files(diff), repo, baseline)
    return {
        "repoRoot": repo,
        "paths": paths,
        "diffBase": diff_base,
        "diff": diff[:MAX_DIFF_BYTES],
        "diffFiles": [[path, body] for path, body in files],
        "metrics": metrics,
    }


def _commit_data(request: dict[str, Any]) -> dict[str, Any]:
    cwd = str(request.get("cwd") or "")
    command = str(request.get("command") or "")
    output = str(request.get("output") or "")
    repo = _git_toplevel(cwd) if cwd else None
    if not repo:
        return {"repoRoot": None, "shas": [], "diffFiles": []}
    shas = SHA_RE.findall(output)
    if not shas and re.search(r"(?:\d+\s+files?\s+changed|create mode\s+\d+|nothing to commit)", output, re.I) and re.search(r"(?:^|[;&|])\s*(?:git|gt)\b[^;&|]*(?:commit|create|modify)\b", command):
        # Hidden output is accepted only when Git emitted a success-shaped
        # diffstat. Never infer success from an ambiguous tool failure.
        head = _git_rev_parse_head(repo)
        if head:
            shas = [head]
    full: list[str] = []
    seen: set[str] = set()
    import subprocess
    for sha in reversed(shas):
        try:
            p = subprocess.run([*GIT_CMD, "rev-parse", "--verify", "-q", sha], cwd=repo, capture_output=True, timeout=5)
            resolved = p.stdout.decode("utf-8", "replace").strip() if p.returncode == 0 else ""
        except (OSError, subprocess.SubprocessError):
            resolved = ""
        if resolved and resolved not in seen:
            seen.add(resolved)
            full.append(resolved)
    files: list[tuple[str, str]] = []
    for sha in full:
        try:
            p = subprocess.run([*GIT_CMD, "show", "-p", "--no-color", "--no-ext-diff", "--no-textconv", sha, "--"], cwd=repo, capture_output=True, timeout=15)
            if p.returncode == 0:
                files.extend(parse_diff_into_files(p.stdout.decode("utf-8", "replace")))
        except (OSError, subprocess.SubprocessError):
            continue
    unique: list[list[str]] = []
    seen_paths: set[str] = set()
    for path, body in files:
        if path not in seen_paths:
            seen_paths.add(path)
            unique.append([path, body[:MAX_DIFF_BYTES]])
    return {"repoRoot": repo, "shas": full, "diffFiles": unique}


def _push_data(request: dict[str, Any]) -> dict[str, Any]:
    cwd = str(request.get("cwd") or "")
    output = str(request.get("output") or "")
    repo = _git_toplevel(cwd) if cwd else None
    if not repo:
        return {"repoRoot": None, "shas": [], "diffFiles": [], "base": None}
    previous = _detect_prev_upstream(repo, output)
    if not previous:
        return {"repoRoot": repo, "shas": [], "diffFiles": [], "base": None}
    pushed = _git_rev_list_range(repo, previous, "HEAD")
    reviewed = _load_reviewed_shas(repo)
    base, tail = _compute_push_sweep_base(previous, pushed, reviewed)
    if base is None:
        return {"repoRoot": repo, "shas": pushed, "tail": [], "diffFiles": [], "base": None, "alreadyReviewed": True}
    diff = _git_diff_range(repo, base, "HEAD")
    files = parse_diff_into_files(diff or "")
    return {"repoRoot": repo, "shas": pushed, "tail": tail, "diffFiles": [[p, b[:MAX_DIFF_BYTES]] for p, b in files], "base": base, "alreadyReviewed": False}


def _mark_reviewed(request: dict[str, Any]) -> dict[str, Any]:
    repo = str(request.get("repoRoot") or "")
    shas = [s for s in request.get("shas", []) if isinstance(s, str) and re.fullmatch(r"[0-9a-f]{40}", s)]
    if not repo or not shas:
        return {"acknowledged": not shas, "shas": []}
    _append_reviewed_shas(repo, shas, vulns_found=int(request.get("findings", 0) or 0))
    current = _load_reviewed_shas(repo)
    missing = [sha for sha in shas if sha not in current]
    if missing:
        raise RuntimeError("reviewed SHA acknowledgement failed")
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
    if op == "git.baselineContent":
        import subprocess
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
    except Exception as exc:  # bridge boundary: never emit traceback on stdout
        print(f"bridge error: {type(exc).__name__}: {str(exc)[:240]}", file=sys.stderr, flush=True)
        response = _error("bridge_error", type(exc).__name__)
    print(json.dumps(response, ensure_ascii=False, separators=(",", ":")), flush=True)
    return 0 if response.get("ok") else 2


if __name__ == "__main__":
    raise SystemExit(main())
