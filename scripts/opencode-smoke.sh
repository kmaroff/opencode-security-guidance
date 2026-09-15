#!/bin/sh
set -eu

ROOT=$(CDPATH= cd -- "$(dirname -- "$0")/.." && pwd)
OPENCODE_BIN=${OPENCODE_BIN:-opencode}

if ! command -v "$OPENCODE_BIN" >/dev/null 2>&1; then
  echo "OpenCode executable not found: $OPENCODE_BIN" >&2
  exit 2
fi

TMP=$(mktemp -d "${TMPDIR:-/tmp}/sg-opencode-smoke.XXXXXX")
SERVER_PID=""
cleanup() {
  if [ -n "$SERVER_PID" ]; then
    kill -TERM "$SERVER_PID" 2>/dev/null || true
    sleep 0.2
    kill -KILL "$SERVER_PID" 2>/dev/null || true
  fi
  sleep 0.2
  rm -rf "$TMP" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

mkdir -p "$TMP/.opencode" "$TMP/state" "$TMP/config"
cat >"$TMP/opencode.json" <<EOF
{
  "plugin": ["$ROOT/dist/plugin.js"]
}
EOF
cat >"$TMP/.opencode/security-guidance.json" <<'EOF'
{
  "enabled": true,
  "patterns": true,
  "stopReview": false,
  "commitReview": false,
  "pushReview": false,
  "debug": true
}
EOF
cat >"$TMP/.opencode/security-patterns.json" <<'EOF'
{
  "patterns": [{
    "rule_name": "smoke-write",
    "substrings": ["security-guidance-smoke-marker"],
    "reminder": "Smoke pattern warning."
  }]
}
EOF

PORT=$(python3 -c 'import socket; s=socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1]); s.close()')
URL="http://127.0.0.1:$PORT"
XDG_STATE_HOME="$TMP/state" XDG_CONFIG_HOME="$TMP/config" \
  "$OPENCODE_BIN" serve --hostname 127.0.0.1 --port "$PORT" --log-level ERROR \
  >"$TMP/server.log" 2>&1 &
SERVER_PID=$!

ready=0
for _ in $(seq 1 100); do
  if curl -fsS "$URL/global/health" >/dev/null 2>&1; then
    ready=1
    break
  fi
  if ! kill -0 "$SERVER_PID" 2>/dev/null; then
    cat "$TMP/server.log" >&2
    exit 1
  fi
  sleep 0.1
done

if [ "$ready" -ne 1 ]; then
  cat "$TMP/server.log" >&2
  echo "OpenCode server did not become healthy on $URL" >&2
  exit 1
fi

if ! python3 -c 'import pathlib, re, sys; text = pathlib.Path(sys.argv[1]).read_text(errors="replace"); sys.exit(1 if re.search(r"failed to load plugin|security-guidance.*(error|exception)", text, re.I) else 0)' "$TMP/server.log"; then
  cat "$TMP/server.log" >&2
  exit 1
fi
RUN_LOG="$TMP/run.log"
if ! XDG_STATE_HOME="$TMP/state" XDG_CONFIG_HOME="$TMP/config" \
  "$OPENCODE_BIN" run --attach "$URL" --dir "$TMP" \
  --model "${OPENCODE_SMOKE_MODEL:-openai/gpt-5.6-luna}" --format json --log-level ERROR --auto \
  "Use the write tool to create $TMP/smoke.txt with exactly security-guidance-smoke-marker, then reply with exactly OPEN_CODE_SECURITY_GUIDANCE_SMOKE_OK." \
  >"$RUN_LOG" 2>&1; then
  cat "$RUN_LOG" >&2
  exit 1
fi
if ! python3 -c 'import pathlib, sys; root = pathlib.Path(sys.argv[1]); run = pathlib.Path(sys.argv[2]); target = root / "smoke.txt"; sys.exit(0 if target.exists() and target.read_text().strip() == "security-guidance-smoke-marker" and "OPEN_CODE_SECURITY_GUIDANCE_SMOKE_OK" in run.read_text(errors="replace") else 1)' "$TMP" "$RUN_LOG"; then
  cat "$RUN_LOG" >&2
  echo "OpenCode prompt/tool smoke did not produce the expected result" >&2
  exit 1
fi

printf 'OpenCode smoke passed: plugin artifact loaded, prompt completed, and isolated server healthy at %s\n' "$URL"
