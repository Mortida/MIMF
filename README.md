# MIMF — Metadata Intelligence & Mutation Framework

MIMF is a modular Python toolkit to **inspect**, **normalize**, and **export** metadata from files (starting with PDFs), with:

- Plugin-based inspectors + normalizers
- Policy-controlled export (redaction / deny)
- Forensic bundles (Merkle root, hash-chained events)
- Optional signing + custody timeline
- CLI + API service mode
- Optional SQLite persistence for contexts

## Install (local)

```bash
pip install -e ".[api]"
```

> `.[api]` installs FastAPI + Uvicorn required for service mode.

## CLI quickstart

Inspect:
```bash
python -m mimf inspect /path/to/file.pdf
```

Export a bundle:
```bash
python -m mimf export-bundle /path/to/file.pdf --out ./bundle_out --pretty
python -m mimf verify-bundle ./bundle_out
```

## API service mode

Run locally:
```bash
export MIMF_API_KEYS="devkey:alice:export:document.basic,export:document.identifying,export:document.tooling,runtime:read,runtime:write"
python -m mimf serve --host 127.0.0.1 --port 8080 --db ./mimf_runtime.db
```

Key endpoints:
- `POST /inspect` (multipart upload)
- `POST /normalize` (multipart upload; policy-controlled)
- `POST /export-bundle` (returns zip bytes)
- `POST /verify-bundle` (upload bundle zip)
- `GET /contexts` *(requires `runtime:read`, only if DB enabled)*
- `GET /contexts/{id}` *(requires `runtime:read`, only if DB enabled)*

### Persistence (SQLite)
If the API is started with `--db <path>` or `MIMF_DB_PATH`, you can persist runtime contexts:

- In API: send `persist=true` to `POST /export-bundle` (requires `runtime:write`).
- In CLI: use `--db <path> --persist`.

## Docker

Build and run:
```bash
docker compose up --build
```

Service listens on `http://localhost:8080`.

Security notes:
- Do **not** use the example `MIMF_API_KEYS` in production.
- The built-in rate limiter is **in-memory** (per-process). For multi-worker deployments, use a shared limiter (e.g., Redis) or run a single worker.

## Security & Compliance

- Security policy: `SECURITY.md`
- Threat model: `docs/THREAT_MODEL.md`
- SBOM notes: `docs/SBOM.md` (helper: `scripts/generate_sbom.sh`)

## CI

A GitHub Actions workflow is included at `.github/workflows/ci.yml` to run linting (ruff) and tests (pytest).
