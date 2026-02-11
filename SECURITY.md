# Security Policy

## Supported Versions

This repository is a security-focused research/engineering project. Only the latest tagged release is considered supported.

## Reporting a Vulnerability

If you believe you've found a security issue:

1. **Do not** open a public issue with exploit details.
2. Provide a minimal report that includes:
   - Affected version/commit
   - Steps to reproduce
   - Impact assessment (what an attacker can do)
   - Any logs/redactions needed
3. If you must share a proof-of-concept, keep it non-destructive and include a safe reproduction dataset.

## Design Security Principles (MIMF)

- **Fail-closed by default:** exports redact sensitive fields unless capabilities explicitly allow them.
- **Bounded parsing:** inspectors avoid full parsing for risky formats and use bounded prefix/suffix scans.
- **Tamper-evident artifacts:** bundles include content hashes + a Merkle root; optional Ed25519 signing proves authenticity.
- **Least privilege:** actor capabilities and security boundaries gate inspection/export behaviors.
- **No implicit trust:** embedded public keys are treated as convenience only; verifiers should supply trusted keys.

## Threat Model Summary

See `docs/THREAT_MODEL.md` for the full model.
