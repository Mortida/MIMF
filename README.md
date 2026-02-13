# Metadata Intelligence & Mutation Framework (MIMF) — v1.0.0

MIMF is a **CLI-first forensic metadata framework** for working with **untrusted files**.

It helps you:

1) **Inspect** a file safely (extract signals + metadata)  
2) **Normalize** metadata into a stable schema (consistent output across file types)  
3) **Export** a **tamper-evident forensic bundle** (hashes + Merkle root + event log)  
4) Optionally add **signatures** and **chain-of-custody** artifacts  

MIMF is designed for **untrusted inputs**. By default, inspected files are labeled `UNTRUSTED`, exports are **policy-controlled**, and signatures are **“untrusted” unless you verify using a trusted public key**.

---

## Who is MIMF for?

- **Incident response / DFIR**: record what you observed, keep it verifiable later
- **Disputes / evidence packaging**: prove “these bytes + these observations existed”
- **Security research**: safely inspect risky formats using sandbox mode
- **Engineering pipelines**: generate normalized metadata output that stays stable

---

## What you get from MIMF

When you run MIMF on a file, you typically get:

- **Inspection snapshot**: file properties + extracted metadata (plugin-specific)
- **Normalized output**: stable schema (`mimf.document@1.0`) for downstream tooling
- **Forensic bundle**: a folder of artifacts that can be verified later
- Optional: **bundle signature** and **chain-of-custody** addendum + receipts

---

## Requirements

- Python **>= 3.10**
- `uv` installed (recommended)  
  Install from: https://github.com/astral-sh/uv

---

## Install (from repo root)

> “Repo root” means: the directory that contains `pyproject.toml`.

```bash
uv sync
```

---

## Learn the CLI (start here)

Show all available commands:

```bash
uv run python -m mimf --help
```

Get help for one command:

```bash
uv run python -m mimf inspect-file --help
uv run python -m mimf normalize-file --help
uv run python -m mimf show-normalized --help
uv run python -m mimf export-bundle --help
uv run python -m mimf show-bundle --help
uv run python -m mimf verify-bundle --help
uv run python -m mimf keygen --help
uv run python -m mimf append-custody --help
uv run python -m mimf transfer-custody --help
uv run python -m mimf accept-transfer --help
uv run python -m mimf timeline --help
uv run python -m mimf bundle-diff --help
uv run python -m mimf db-init --help
uv run python -m mimf db-list-contexts --help
uv run python -m mimf db-show-context --help
uv run python -m mimf serve --help
uv run python -m mimf client --help
uv run python -m mimf demo --help
```

✅ These are documentation commands. They only print the exact flags supported by your installed version.

---

## 2-minute quickstart (local CLI)

Pick any file (example uses `README.md`).

### 1) Inspect a file

```bash
uv run python -m mimf inspect-file README.md
```

### 2) Print normalized metadata (policy-controlled)

```bash
uv run python -m mimf show-normalized README.md
```

### 3) Export a forensic bundle (directory output)

```bash
uv run python -m mimf export-bundle README.md --out out_bundle --include-original --pretty
```

### 4) Verify bundle integrity (hashes + Merkle)

```bash
uv run python -m mimf verify-bundle out_bundle
```

### 5) Show a human summary + first N events

```bash
uv run python -m mimf show-bundle out_bundle --events 10
```

---

## What is a “forensic bundle”?

`export-bundle` creates a directory like `out_bundle/` containing evidence artifacts such as:

- `manifest.json` (bundle description + integrity references)
- `hashes.txt` (human-readable hashes)
- `objects.jsonl` / `events.jsonl` (runtime object snapshots + event chain)
- `normalized.json` / `sources.json` (normalized view + origin/source mapping)
- Optional `original/<filename>` if `--include-original`
- Optional signing files if you use `--sign`
- Optional custody files if you use custody commands

To view your real output on disk:

```bash
ls -la out_bundle
find out_bundle -maxdepth 2 -print
```

---

## Sandbox mode (recommended for risky files)

Use `--sandbox` for untrusted PDFs/DOCX/etc.  
It runs the inspector in a subprocess sandbox (crash containment / safer parsing).

```bash
uv run python -m mimf inspect-file sample.pdf --sandbox
uv run python -m mimf show-normalized sample.pdf --sandbox
uv run python -m mimf export-bundle sample.pdf --out out_bundle --sandbox
```

---

## Signing bundles (Ed25519)

### 1) Generate a keypair

This writes:

- `<prefix>_private.pem` ✅ keep secret (**DO NOT COMMIT**)
- `<prefix>_public.pem` ✅ shareable

```bash
uv run python -m mimf keygen ./keys --prefix operator-1
```

### 2) Sign during export (PRIVATE key)

```bash
uv run python -m mimf export-bundle README.md \
  --out out_bundle \
  --include-original \
  --pretty \
  --sign \
  --key ./keys/operator-1_private.pem \
  --signer-id operator-1 \
  --embed-pubkey
```

### 3) Verify signature using a trusted PUBLIC key

```bash
uv run python -m mimf verify-bundle out_bundle --pubkey ./keys/operator-1_public.pem
```

**Note about “Signature OK (untrusted)”**  
If you verify without `--pubkey`, MIMF can confirm a signature exists and is internally consistent, but it cannot prove who signed it.

---

## Chain of custody (optional)

### Append a custody event

```bash
uv run python -m mimf append-custody out_bundle CREATED \
  --note "Initial capture" \
  --signer-id operator-1 \
  --key ./keys/operator-1_private.pem \
  --embed-pubkey
```

### Transfer custody (sender signs)

```bash
uv run python -m mimf transfer-custody out_bundle \
  --from-actor sender-1 --to-actor receiver-1 \
  --note "handoff" \
  --signer-id sender-1 \
  --key ./keys/sender-1_private.pem \
  --embed-sender-pubkey
```

### Accept transfer (receiver signs)

```bash
uv run python -m mimf accept-transfer out_bundle \
  --actor-id receiver-1 \
  --signer-id receiver-1 \
  --key ./keys/receiver-1_private.pem \
  --embed-receiver-pubkey
```

### Verify bundle + custody receipts (optional keys)

```bash
uv run python -m mimf verify-bundle out_bundle \
  --pubkey ./keys/operator-1_public.pem \
  --sender-pubkey ./keys/sender-1_public.pem \
  --receiver-pubkey ./keys/receiver-1_public.pem
```

---

## Database (optional)

Initialize DB:

```bash
uv run python -m mimf db-init --db ./mimf.db
```

Persist contexts when exporting:

```bash
uv run python -m mimf export-bundle README.md --out out_bundle --db ./mimf.db --persist
```

List contexts and inspect one:

```bash
uv run python -m mimf db-list-contexts --db ./mimf.db --limit 20
uv run python -m mimf db-show-context --db ./mimf.db <context_id> --events 50
```

(Replace `<context_id>` with a real ID from `db-list-contexts`.)

---

## API server (optional)

To use `serve`/`client`/`demo`, install API extras:

```bash
uv sync --extra api
```

Run the server:

```bash
uv run python -m mimf serve --host 127.0.0.1 --port 8080 --db ./mimf.db
```

Health check:

```bash
uv run python -m mimf client --url http://127.0.0.1:8080 health
```

---

## Documentation

Start here:

- `docs/README.md`

Direct doc paths:

- Install: `docs/getting-started/INSTALL.md`
- Quickstart: `docs/getting-started/QUICKSTART.md`
- Commands (human guide): `docs/cli/COMMANDS.md`
- Commands reference (exact `--help` output): `docs/cli/COMMANDS_REFERENCE.md`
- Architecture: `docs/reference/ARCHITECTURE.md`
- Security model: `docs/reference/SECURITY_MODEL.md`
- Troubleshooting: `docs/reference/TROUBLESHOOTING.md`

---

## Dev / quality checks

```bash
uv run pytest -q
uv run ruff check .
uv run ruff format .
```

---

## Security warning: DO NOT COMMIT PRIVATE KEYS

Never commit:

- `keys/*private*.pem`

Add to `.gitignore`:

```gitignore
keys/
*_private*.pem
```

If you accidentally committed a private key:

- rotate it immediately
- purge it from git history

---

## Minimal README validation (fast)

These commands should work on a clean clone:

```bash
uv sync
uv run python -m mimf --help
uv run python -m mimf inspect-file README.md
uv run python -m mimf export-bundle README.md --out out_bundle --include-original --pretty
uv run python -m mimf verify-bundle out_bundle
uv run python -m mimf show-bundle out_bundle --events 5
```

---

## Known issue you hit before (append-custody crash)

If you see:

`TypeError: to_jsonable() got an unexpected keyword argument 'indent'`

That means the CLI is calling:

```python
to_jsonable(out, indent=2, sort_keys=True, default=str)
```

…but `to_jsonable()` does not accept those arguments.

Fix (exactly what to change):

Open:

`mimf/cli/main.py`

Find `cmd_append_custody` and replace:

```python
print(json.dumps(to_jsonable(out, indent=2, sort_keys=True, default=str)))
```

with:

```python
print(json.dumps(to_jsonable(out), indent=2, sort_keys=True, default=str))
```
