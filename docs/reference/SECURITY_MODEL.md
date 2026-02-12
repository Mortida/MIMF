# Security Model (MIMF v1.0.0)

MIMF processes untrusted files. The goal is to extract metadata while reducing exposure.

## Core principles
- Parse, don’t guess
- Hard limits on extraction (size/entries/etc.)
- Avoid executing embedded content
- Optional subprocess sandbox (`--sandbox`)
- Policy-gated export (`--policy-pack`, boundary/capabilities, `--strict`)
- Tamper evidence via manifests + verification
- Optional authenticity via signing (`--sign` / `verify-bundle --pubkey`)

## Operator recommendations
- Use `--sandbox` for untrusted files
- Verify bundles before relying on them
- Keep keys safe (never commit private keys)
