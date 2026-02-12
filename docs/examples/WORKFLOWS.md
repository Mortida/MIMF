# Workflows (MIMF v1.0.0)

These are copy/paste workflows for common usage.

## Workflow A — Offline inspect → bundle → verify
```bash
uv sync
uv run python -m mimf inspect-file README.md
uv run python -m mimf show-normalized README.md
uv run python -m mimf export-bundle README.md --out out_bundle --include-original --pretty
uv run python -m mimf verify-bundle out_bundle
uv run python -m mimf show-bundle out_bundle --events 10


