# OpenCode Security Guidance

Independent alpha port of Anthropic's `security-guidance` plugin for OpenCode 1.18.29. The original project and upstream implementation belong to Anthropic. This repository is not an official Anthropic product, is not endorsed by Anthropic, and does not imply Anthropic support.

## Alpha status

This branch (`port/opencode-v0.1`) contains a working local alpha. It is intentionally not a release, does not touch a canonical OpenCode server, and does not modify LaunchAgents, SSH configuration, or production configuration.

The port keeps the upstream Python checker and Git logic, adds an OpenCode TypeScript plugin lifecycle, and communicates with the Python core through a bounded one-shot bridge.

## Capabilities

- Pattern warnings after OpenCode write/edit tools.
- Baseline-relative review after `session.idle`.
- Strict local validation of structured findings.
- Optional agentic refutation for child-session reviews.
- Commit and push review with reviewed-SHA deduplication.
- Per-session state, per-session serialization, and per-repository locking.
- OpenCode-native policy and custom-pattern files with legacy Claude fallback.

## Install locally

```sh
npm ci
npm run build
```

The build produces the loadable plugin artifact at `dist/plugin.js`. Register that
absolute path in the isolated OpenCode project or user configuration:
```json
{
  "plugin": ["/absolute/path/to/opencode-security-guidance/dist/plugin.js"]
}
```

The plugin is loaded by OpenCode; it does not start or reconfigure an OpenCode server.

## Configuration

Configuration is JSON and applies in this order (later values win):

1. `$XDG_CONFIG_HOME/opencode/security-guidance/config.json`
2. `.opencode/security-guidance.json`
3. `.opencode/security-guidance.local.json`

Example:

```json
{
  "enabled": true,
  "patterns": true,
  "stopReview": true,
  "commitReview": true,
  "pushReview": true,
  "debug": false,
  "reviewer": {
    "provider": "openai",
    "model": "gpt-5.6-luna",
    "inheritParent": false
  }
}
```

Reviewer routing requires both `provider` and `model`, unless `inheritParent` is true and the active session supplies both. Invalid JSON, unknown fields, and invalid types disable the plugin rather than silently changing behavior.

## Native policy and patterns

Native OpenCode files:

- `$XDG_CONFIG_HOME/opencode/security-guidance/security-guidance.md`
- `.opencode/security-guidance.md`
- `.opencode/security-guidance.local.md`
- Matching `security-patterns.yaml`, `security-patterns.yml`, or `security-patterns.json` files in those locations.

Native files win as a group. Legacy `.claude/` files are read only when no native file exists.

## Diagnostics and state

Default locations:

- State: `~/.local/state/opencode/security-guidance/`
- Debug log: `~/.local/state/opencode/security-guidance/logs/runtime.log`

Set `"debug": true` to enable bounded lifecycle diagnostics. Logs contain operation names, error kinds, and session identifiers; they do not contain prompts, diffs, source contents, provider responses, or credentials.

## Security model

Findings are assistive signals, not a guarantee. Reviews can miss vulnerabilities and produce false positives. Continue normal human review and use appropriate SAST, DAST, dependency scanning, and penetration testing.

Changed paths, diff content, policy text, and selected repository context may be sent to the configured reviewer provider. Do not put secrets in policy files or source diffs that should not leave the configured trust boundary. Provider retention and privacy terms apply.

## Verification

The repository includes bridge regressions and retains the upstream Python tests.
Create the development Python environment once, then run:

```sh
python3 -m venv .venv
.venv/bin/python -m pip install -r requirements-dev.txt
npm ci
npm test
```

`npm run smoke:opencode` builds the artifact, starts OpenCode on a dynamically
allocated loopback port, verifies `/global/health`, and tears the server down.
It does not touch the canonical OpenCode server or production configuration.

For architecture, lifecycle invariants, and the parity matrix, see [`docs/architecture.md`](docs/architecture.md) and [`docs/parity.md`](docs/parity.md).

## Upstream and license

Source project: [Anthropic's official `security-guidance` plugin](https://github.com/anthropics/claude-plugins-official/tree/main/plugins/security-guidance).

The imported work is licensed under Apache License 2.0. Attribution and provenance are recorded in [`NOTICE`](NOTICE) and [`UPSTREAM.md`](UPSTREAM.md). This independent derivative is not maintained, sponsored, or approved by Anthropic.
