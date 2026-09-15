import json
import os
import subprocess
import sys
from pathlib import Path

HOOKS = Path(__file__).resolve().parents[1] / "hooks"
BRIDGE = Path(__file__).resolve().parents[1] / "bridge" / "opencode_bridge.py"
sys.path.insert(0, str(HOOKS))
from security_reminder_hook import check_patterns  # noqa: E402


def call(raw):
    return subprocess.run([sys.executable, str(BRIDGE)], input=raw, text=True, capture_output=True)


def request(value):
    result = call(json.dumps(value))
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
