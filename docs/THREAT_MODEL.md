# MIMF Threat Model

## System Overview

MIMF inspects files, normalizes extracted metadata into a stable schema, enforces policy on what can be exported, and produces forensic bundles that are tamper-evident (hashes/Merkle) and optionally authentic (Ed25519 signatures). Bundles may carry chain-of-custody appendices and two-party transfer receipts.

## Assets

- Original files and extracted metadata
- Normalized metadata (`mimf.document@1.0`)
- Runtime events and object snapshots
- Forensic bundles, hashes, signatures, custody entries
- API keys and private signing keys

## Trust Boundaries

- **Untrusted input:** files, bundle zips, and client-provided fields.
- **Policy boundary:** capabilities gate export of identifying/tooling fields.
- **Storage boundary:** SQLite runtime store persists contexts/events.
- **Verifier boundary:** callers must provide trusted public keys; embedded keys are not inherently trusted.

## Adversaries

- Malicious file submitter (crafted PDFs/JSON)
- Malicious bundle tamperer (modifies artifacts after export)
- Insider attempting to exfiltrate redacted metadata
- Replay attacker attempting to reuse signatures/receipts

## Key Threats and Mitigations

### 1) Malicious file parsing
**Threat:** DoS or exploitation via complex file structures.

**Mitigations:**
- Bounded prefix/suffix scanning for PDF signals
- XMP extraction rejects DTD/ENTITY (reduces entity expansion risk)
- Upload size limits + bounded reads
- Avoid full PDF parsing in default inspector

### 2) Metadata leakage
**Threat:** Export reveals PII/identifying fields.

**Mitigations:**
- Export policy redacts by default
- Strict mode can deny instead of redact
- Capabilities required: `export:document.identifying`, `export:document.tooling`

### 3) Bundle tampering
**Threat:** Modify bundle artifacts after export.

**Mitigations:**
- SHA-256 for each artifact
- Merkle root over artifact hashes
- `verify-bundle` recomputes and checks

### 4) Bundle forgery
**Threat:** Attacker produces a fake bundle and claims it is yours.

**Mitigations:**
- Optional Ed25519 signing of canonical bundle summary
- Verifier supplies trusted public key

### 5) Chain-of-custody manipulation
**Threat:** Removing/reordering custody entries.

**Mitigations:**
- Custody addendum hashed and optionally signed
- Two-party receipts bind receiver signature to sender signature

## Residual Risk

- No sandboxing of file inspection code in-process.
- In-memory rate limiting is not globally consistent across multi-worker deployments.
- Advanced PDF parsing for deep metadata extraction is intentionally not included by default.

## Roadmap Hardening (Suggested)

- Run inspectors in a subprocess sandbox (seccomp/AppArmor) for hostile environments.
- Optional Redis-backed rate limiting for multi-worker deployments.
- Add signature transparency log / key rotation policy.
