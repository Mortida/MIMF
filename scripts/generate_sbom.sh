#!/usr/bin/env bash
set -euo pipefail

# Generate an SBOM for the current environment.
#
# Time:  O(n) where n is number of installed packages
# Space: O(n) for the output file

out="${1:-sbom.json}"

python -m pip install --quiet --disable-pip-version-check cyclonedx-bom >/dev/null

# cyclonedx-py reads current env by default
cyclonedx-py -o "$out"

echo "Wrote $out"
