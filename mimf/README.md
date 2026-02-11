# MIMF – Metadata Intelligence & Mutation Framework

MIMF is a modular Python toolkit to **inspect**, **normalize**, and (optionally) **mutate** metadata with **policy enforcement** and **forensic-grade exports**.

## What you can do
- Inspect files into RuntimeObjects (plugins)
- Normalize metadata into a stable `mimf.document@1.0` schema
- Enforce export rules (redaction/deny) based on capabilities
- Export tamper-evident forensic bundles (Merkle root + optional signatures)
- Append chain-of-custody artifacts and render a timeline
- Persist runtime contexts to SQLite and query them later
- Run as a FastAPI service (service mode)

## Install (dev)
```bash
python -m venv .venv
source .venv/bin/activate
pip install -U pip
pip install -e .
```

## Install with API deps
```bash
pip install -e .[api]
```

## CLI quickstart
```bash
# inspect
python -m mimf inspect-file /path/to/file.pdf

# export a forensic bundle
python -m mimf export-bundle /path/to/file.pdf --out ./bundle_out --pretty
python -m mimf verify-bundle ./bundle_out
python -m mimf timeline ./bundle_out
```

## Service mode
```bash
export MIMF_API_KEYS="devkey:alice:export:document.basic,export:document.identifying,export:document.tooling,runtime:read,runtime:write"
python -m mimf serve --host 127.0.0.1 --port 8080
```

## API client + one-command demo
With the server running:
```bash
python -m mimf client health --url http://127.0.0.1:8080 --api-key devkey
python -m mimf client inspect /path/to/file.pdf --url http://127.0.0.1:8080 --api-key devkey
python -m mimf client export-bundle /path/to/file.pdf --out mimf_bundle.zip --url http://127.0.0.1:8080 --api-key devkey
python -m mimf client verify-bundle mimf_bundle.zip --url http://127.0.0.1:8080 --api-key devkey

# end-to-end (inspect → normalize → export → verify)
python -m mimf demo /path/to/file.pdf --out mimf_demo_bundle.zip --url http://127.0.0.1:8080 --api-key devkey
```
