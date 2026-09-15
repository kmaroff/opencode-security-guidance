import json
import os
import subprocess
import sys
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "hooks"
BRIDGE = Path(__file__).resolve().parents[1] / "bridge" / "opencode_bridge.py"
sys.path.insert(0, str(HOOKS))
from security_reminder_hook import check_patterns  # noqa: E402


def call(raw, env=None):
    return subprocess.run([sys.executable, str(BRIDGE)], input=raw, text=True, capture_output=True, env=env)


def request(value, env=None):
    result = call(json.dumps(value), env=env)
    return result, json.loads(result.stdout)


def test_ping_and_core_info():
    result, body = request({"op": "ping"})
    assert result.returncode == 0
    assert body["ok"] is True
    assert body["result"]["protocolVersion"] == "1"
    _, info = request({"op": "core.info"})
    assert info["result"]["patternRules"] == 25


def test_invalid_json_and_unknown_operation():
    result = call("{")
    assert result.returncode != 0
    assert json.loads(result.stdout)["error"]["kind"] == "invalid_json"
    result, body = request({"op": "unknown"})
    assert result.returncode != 0
    assert body["error"]["kind"] == "bridge_error"


def test_pattern_match_and_clean_result(tmp_path):
    vulnerable = "import subprocess\nsubprocess.call(user, shell=True)\n"
    result, body = request({"op": "pattern.scan", "cwd": str(tmp_path), "path": "app.py", "content": vulnerable})
    assert result.returncode == 0
    names = {item["ruleName"] for item in body["result"]["matches"]}
    direct = {name for name, _ in check_patterns("app.py", vulnerable)}
    assert names == direct
    _, clean = request({"op": "pattern.scan", "cwd": str(tmp_path), "path": "app.py", "content": "print('safe')\n"})
    assert clean["result"]["matches"] == []


def test_pattern_baseline_suppression(tmp_path):
    content = "import subprocess\nsubprocess.call(user, shell=True)\n"
    _, body = request({"op": "pattern.scan", "cwd": str(tmp_path), "path": "app.py", "content": content, "baselineContent": content})
    assert body["result"]["matches"] == []


def test_native_custom_pattern(tmp_path):
    config = tmp_path / ".opencode"
    config.mkdir()
    (config / "security-patterns.json").write_text(json.dumps({
        "patterns": [{
            "rule_name": "custom-secret",
            "substrings": ["internal-secret-marker"],
            "reminder": "Do not commit this marker.",
        }]
    }))
    env = {**os.environ, "XDG_CONFIG_HOME": str(tmp_path / "user-config")}
    _, body = request({
        "op": "pattern.scan",
        "cwd": str(tmp_path),
        "path": "app.py",
        "content": "internal-secret-marker",
    }, env=env)
    assert any(item["ruleName"] == "user:custom-secret" for item in body["result"]["matches"])


def _git(cwd, *args):
    return subprocess.run(["git", *args], cwd=cwd, check=True, capture_output=True, text=True)


def test_commit_data_and_reviewed_sha_acknowledgement(tmp_path):
    _git(tmp_path, "init", "-q")
    _git(tmp_path, "config", "user.email", "security@example.test")
    _git(tmp_path, "config", "user.name", "Security Test")
    source = tmp_path / "app.py"
    source.write_text("print('new')\n")
    _git(tmp_path, "add", "app.py")
    _git(tmp_path, "commit", "-qm", "add app")
    sha = _git(tmp_path, "rev-parse", "HEAD").stdout.strip()
    _, body = request({
        "op": "git.commitData",
        "cwd": str(tmp_path),
        "command": "git commit -m add app",
        "output": f"[main {sha[:7]}] add app\n 1 file changed, 1 insertion(+)",
    })
    assert body["result"]["shas"] == [sha]
    assert body["result"]["diffFiles"][0][0] == "app.py"
    _, marked = request({"op": "git.markReviewed", "repoRoot": str(tmp_path), "shas": [sha], "findings": 0})
    assert marked["result"] == {"acknowledged": True, "shas": [sha]}
