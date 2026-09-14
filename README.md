# OpenCode Security Guidance

OpenCode Security Guidance is an independent, work-in-progress OpenCode port of Anthropic's `security-guidance` plugin. The original project and its upstream implementation belong to Anthropic. This repository is not an official Anthropic product, is not endorsed by Anthropic, and does not imply Anthropic support.

The repository preserves the initial upstream snapshot first. OpenCode compatibility work will be introduced in separate, reviewable changes rather than mixed into the baseline import.

## Overview

The imported security-guidance implementation provides three layers of security review:

1. Pattern-based warnings for known-dangerous code patterns.
2. LLM-powered review of diffs.
3. Agentic review around commits, with repository context for tracing data flow.

These capabilities are retained as the upstream baseline. The runtime and hook lifecycle still require adaptation to the OpenCode plugin API.

## Status

**Work in progress / Initial OpenCode port**

The current branch is a faithful upstream baseline import. It is not yet a completed or supported OpenCode plugin. Do not treat the current snapshot as proof of OpenCode integration, hook lifecycle compatibility, or production readiness.

## Architecture

The baseline keeps the upstream implementation in a small root-level layout:

- `.claude-plugin/plugin.json` — retained upstream manifest for baseline provenance.
- `hooks/` — upstream Python hook and review implementation.
- `tests/` — upstream tests currently covering repository resolution.
- `LICENSE` — upstream Apache License 2.0 text.

Future port work will adapt the hook entry points, event lifecycle, configuration, and runtime integration to OpenCode's plugin API. Claude-specific files and behavior are intentionally not rewritten in this baseline commit so that later changes remain auditable against the exact upstream snapshot.

## Installation

Installation is not available yet. The OpenCode plugin integration must be completed and verified before this project should be installed on a clean OpenCode environment.

## Configuration

No OpenCode configuration contract is defined yet. The baseline contains upstream Claude-oriented environment variables, including `SECURITY_REVIEW_MODEL`, `ENABLE_PATTERN_RULES`, `ENABLE_CODE_SECURITY_REVIEW`, `ENABLE_STOP_REVIEW`, and `ENABLE_COMMIT_REVIEW`; these names and semantics must not be assumed to be the final OpenCode interface.

When the OpenCode adapter is implemented, this section will document supported configuration, defaults, credential handling, and provider routing.

## Security model

Security findings are assistive signals, not a guarantee. Reviews can miss vulnerabilities and can produce false positives. Use normal human review, dependency scanning, and appropriate SAST/DAST or penetration testing for security-sensitive systems.

Any future LLM review integration must make data flow explicit. Changed paths, diff content, related file contents, and organization-specific policy text may be sent to the configured model endpoint. Do not place secrets in policy files or review inputs. Provider retention and privacy terms apply to the configured endpoint.

The OpenCode port must also verify hook lifecycle behavior, false-positive handling, and commit/push review behavior before release.

## Upstream

The source project is Anthropic's official `security-guidance` plugin:

- Repository: <https://github.com/anthropics/claude-plugins-official>
- Path: [`plugins/security-guidance`](https://github.com/anthropics/claude-plugins-official/tree/main/plugins/security-guidance)
- Initial upstream commit: `da823e86c8feef13b73b6712af11eadd38c992f6`
- Upstream commit date: `2026-09-14T13:20:24-04:00`

See [UPSTREAM.md](UPSTREAM.md) for the review-only update workflow. Upstream changes must be analyzed and ported deliberately; this repository must not merge the entire upstream repository.

## License

The imported upstream work is licensed under the Apache License 2.0. See [LICENSE](LICENSE). Attribution and provenance are recorded in [NOTICE](NOTICE) and [UPSTREAM.md](UPSTREAM.md).

## Credits

- Original `security-guidance` project: Anthropic.
- Original plugin author listed in the upstream manifest: David Dworken.
- OpenCode compatibility work: contributors to this repository.

This project is an independent derivative work and is not maintained, sponsored, or approved by Anthropic.
