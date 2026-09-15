# Architecture

`opencode-security-guidance` is an independent OpenCode plugin adapter around the preserved Python security-guidance core.

## Runtime path

1. OpenCode loads `dist/plugin.js`.
2. `chat.message` captures the current Git baseline and parent model in the per-session state file.
3. `tool.execute.before` is a guarded lifecycle boundary. `tool.execute.after` handles write-pattern warnings and commit/push detection using the command's authoritative repository target.
4. `session.idle` performs post-validation. It computes a baseline-relative review set, starts one reviewer child session, validates structured output locally, and queues bounded synthetic feedback.
5. The Python bridge runs one request per process. It owns pattern parity, Git diff/baseline calculations, reviewed-SHA persistence, and severity filtering.
6. Commit/push reviews serialize through a process-local queue and an atomic repository lock under `.git/security-guidance-review.lock`.

## State and failure invariants

- Session state is persisted under `$XDG_STATE_HOME/opencode/security-guidance/` (default `~/.local/state/opencode/security-guidance/`). Writes use a temporary file and rename.
- The baseline is captured at prompt start. Pre-existing untracked files are excluded from later diffs.
- Reviewer failure never advances `reviewedDiffHash` or reviewed SHAs. The next eligible idle/commit/push path can retry, subject to the per-session stop-fire cap.
- Synthetic feedback is accepted only when the OpenCode callback carries the exact generated message ID; its next idle cycle is consumed without recursive review.
- Repository review uses a lock under Git's common directory, so linked worktrees share one lock. Lock ownership is atomic, stale dead owners are reclaimable, and acquisition is bounded.

## Reviewer transport

OpenCode 1.18.29 exposes structured output through its v2 SDK surface. The adapter reuses the transport from the OpenCode plugin client, creates a child session with `parentID`, sends an explicit provider/model, and submits a JSON-schema format. OpenCode rejects schema metadata keywords in this runtime, so `$schema`, `$id`, and `title` are removed only from the wire copy; the canonical strict schemas remain the local validation contract.

The canonical schemas are:

- `schemas/findings.schema.json`
- `schemas/survived.schema.json`

## Configuration precedence

The loader applies, from lowest to highest precedence:

1. `$XDG_CONFIG_HOME/opencode/security-guidance/config.json`
2. `<project>/.opencode/security-guidance.json`
3. `<project>/.opencode/security-guidance.local.json`

Malformed JSON, unknown fields, or wrong types disable the plugin and emit a bounded diagnostic. Reviewer routing requires both `provider` and `model`, unless `inheritParent` is enabled and the current session supplied both identifiers.

## Native extension files

The preserved Python extension loader supports OpenCode-native files before falling back to legacy Claude paths:

- User guidance: `$XDG_CONFIG_HOME/opencode/security-guidance/security-guidance.md`
- Project guidance: `.opencode/security-guidance.md`
- Project-local guidance: `.opencode/security-guidance.local.md`
- Pattern files use the same locations with `security-patterns.yaml`, `.yml`, or `.json` basenames.

Native files win as a group; legacy files are not merged with native files.
