# Architecture (MIMF v1.0.0)

MIMF is a CLI + API for metadata inspection, normalization, and tamper-evident export.

## Components

### 1) CLI (`python -m mimf ...`)
Primary interface for local use:
- inspection (`inspect-file`)
- normalization (`show-normalized`, `normalize-file`)
- forensic export (`export-bundle`)
- verification (`verify-bundle`, `show-bundle`)
- custody (`append-custody`, `transfer-custody`, `accept-transfer`)
- runtime store (`db-*`)
- API (`serve`, `client`, `demo`)

### 2) Plugins
Plugins implement file-type-specific inspection behavior.
See `docs/cli/PLUGINS.txt` for the exact built-in plugins included in v1.0.0.

### 3) Security controls
- `--sandbox` runs inspectors in a subprocess sandbox for risky inputs.
- `--policy-pack` or boundary/capability flags control what metadata can be exported.
- `--strict` denies export if required capabilities are missing (instead of redacting).

### 4) Bundles
`export-bundle` writes a bundle directory (`--out`) and optionally creates a zip (`--zip`).
Bundles can be signed (`--sign --key ...`) for authenticity and verified using `verify-bundle`.

### 5) Runtime store (optional)
`export-bundle --db ... --persist` stores the RuntimeContext in SQLite for later inspection with `db-*`.

### 6) API (optional)
`serve` runs the FastAPI server. `client` and `demo` interact with the server.
