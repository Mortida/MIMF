"""Forensic export tools.

This package produces tamper-evident export bundles that can be shared with
clients, auditors, or legal teams.

Security notes
- Bundles are evidence containers. Include *only* what you are prepared to disclose.
- Use the normalized export policy hooks to redact/deny sensitive fields.
- Prefer zipping bundles only after manifest + hashes are written (atomic-ish output).
"""

from .bundle import (  # noqa: F401
    BundleArtifact,
    BundleBuildResult,
    build_forensic_bundle,
    verify_forensic_bundle,
    verify_forensic_bundle_details,
)
from .custody import (  # noqa: F401
    accept_transfer_receipt,
    append_custody_event,
    create_transfer_receipt,
    verify_custody_addendum,
)
from .diff import diff_bundles  # noqa: F401
from .timeline import (  # noqa: F401
    TimelineItem,
    load_bundle_timeline,
    render_timeline_text,
)
