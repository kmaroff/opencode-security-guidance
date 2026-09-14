# Upstream

Upstream repository:
https://github.com/anthropics/claude-plugins-official

Upstream path:
plugins/security-guidance

Initial upstream commit:
da823e86c8feef13b73b6712af11eadd38c992f6

Upstream commit date:
2026-09-14T13:20:24-04:00

License:
Apache License 2.0

## Update procedure

Keep the `anthropic-plugins` remote read-only and fetch it when reviewing upstream changes:

```bash
git fetch anthropic-plugins main
```

Compare the security-guidance path from a previously reviewed upstream revision:

```bash
git diff <previous-sha>..anthropic-plugins/main -- plugins/security-guidance
```

Review only `plugins/security-guidance/`. Port relevant changes into this repository deliberately, preserving OpenCode-specific adaptations and attribution. Do not merge `anthropic-plugins/main` or the full `claude-plugins-official` repository into `main`.
