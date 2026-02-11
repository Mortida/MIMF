# SBOM (Software Bill of Materials)

MIMF is intentionally dependency-light. For deployments that require SBOMs, generate them from the locked environment you ship.

## Option A: CycloneDX (recommended)

1. Install tooling:

```bash
python -m pip install --upgrade pip
python -m pip install cyclonedx-bom
```

2. Generate an SBOM for the installed environment:

```bash
cyclonedx-py -o sbom.json
```

3. (Optional) Generate for requirements produced by your build pipeline (CI):

```bash
pip freeze > requirements.lock
cyclonedx-py -i requirements.lock -o sbom.json
```

## Option B: pip-audit (vulnerability scan)

```bash
python -m pip install pip-audit
pip-audit
```

## Notes

- Treat SBOMs as release artifacts and store them alongside signed bundles.
- Prefer generating SBOMs inside your Docker image build so they match exactly what is deployed.
