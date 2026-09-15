# Parity Matrix

Status is measured against the requested OpenCode alpha contract and the preserved upstream behavior.

| ID | Contract | Status | Evidence |
|---|---|---|---|
| P1 | OpenCode plugin entry point | done | `src/plugin.ts`, runtime smoke |
| P2 | Target OpenCode 1.18.29 | done | pinned dependencies and runtime probe |
| P3 | Python core preserved | done | upstream tests remain green |
| P4 | One-shot bridge protocol | done | `bridge/opencode_bridge.py`, bridge tests |
| P5 | stdout protocol isolation | done | bridge invalid-input tests |
| P6 | bounded bridge input/diff | done | bridge constants and error path |
| P7 | session baseline capture | done | persisted state and Git capture |
| P8 | pre-existing untracked exclusion | done | baseline snapshot passed to review-set calculation |
| P9 | write-pattern lifecycle | done | `tool.execute.after` runtime warning |
| P10 | upstream pattern parity | done | direct checker comparison test |
| P11 | warning deduplication | done | session warning keys |
| P12 | post-idle validation | done | `session.idle` handler |
| P13 | one review per diff hash | done | persisted `reviewedDiffHash` |
| P14 | strict findings validation | done | AJV 2020-12 canonical schema |
| P15 | strict agentic survivor validation | done | `survived.schema.json` |
| P16 | explicit reviewer routing | done | config resolver and model propagation |
| P17 | parent-linked reviewer child | done | v2 SDK `parentID` |
| P18 | parent-session synthetic feedback | done | marker and async prompt |
| P19 | bounded feedback recursion | done | marker consumption and generation state |
| P20 | commit review trigger | done | commit command parsing and bridge data |
| P21 | push review trigger | done | push sweep bridge operation |
| P22 | reviewed-SHA transaction | done | mark only after successful review |
| P23 | push deduplication | done | reviewed-SHA prefix/tail calculation |
| P24 | repository serialization | done | process queue plus atomic `.git` lock |
| P25 | lock cleanup/stale handling | done | `RepositoryLock.run` finally/stale path |
| P26 | non-Git fail-open | done | `git.capture` smoke result |
| P27 | native config precedence | done | OpenCode paths and native-pattern test |
| P28 | malformed config fail-closed | done | loader disables plugin on diagnostic |
| P29 | secret-safe debug logs | done | bounded logger fields and no content logging |
| P30 | isolated verification | done | build, bridge tests, upstream suite, runtime smoke |

## Known alpha caveats

- The OpenCode v2 structured-output runtime currently rejects JSON Schema metadata keywords. The adapter strips only `$schema`, `$id`, and `title` from the wire copy and validates the returned object against the canonical strict schema locally.
- Reviewer quality, provider retention, latency, and availability remain provider-dependent.
- This alpha does not install or modify a user's canonical OpenCode server, LaunchAgent, SSH configuration, or production config.
- Release packaging and a hosted Draft PR are intentionally outside local verification; the branch remains `port/opencode-v0.1`.
