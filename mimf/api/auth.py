from __future__ import annotations

import hmac
import os
from dataclasses import dataclass
from typing import Dict, List, Optional


@dataclass(frozen=True, slots=True)
class Actor:
    """Authenticated actor identity for API calls.

    Security notes:
    - Do not trust caller-provided actor_id/capabilities.
    - Capabilities are granted by the server-side key mapping.

    """

    actor_id: str
    capabilities: List[str]


def _parse_api_keys(raw: str) -> Dict[str, Actor]:
    """Parse MIMF_API_KEYS env var into an API key -> Actor mapping.

    Format (semicolon-separated entries):
      <APIKEY>:<ACTOR_ID>:<cap1,cap2,cap3>;

    Example:
      MIMF_API_KEYS="k1:alice:export:document.basic,export:document.identifying;k2:bob:export:document.basic"

    Security notes:
    - Env var is trusted server configuration.
    - Unknown/invalid entries are ignored (fail-closed by omission).

    """

    out: Dict[str, Actor] = {}
    for entry in (raw or "").split(";"):
        entry = entry.strip()
        if not entry:
            continue
        parts = entry.split(":", 2)
        if len(parts) != 3:
            continue
        key, actor_id, caps_raw = parts[0].strip(), parts[1].strip(), parts[2].strip()
        if not key or not actor_id:
            continue
        caps = [c.strip() for c in caps_raw.split(",") if c.strip()]
        out[key] = Actor(actor_id=actor_id, capabilities=caps)
    return out


def load_auth_config() -> Dict[str, Actor]:
    """Load API key mapping from environment.

    Security notes:
    - Keep this server-side only.

    """

    return _parse_api_keys(os.environ.get("MIMF_API_KEYS", ""))


def requires_auth(mapping: Dict[str, Actor]) -> bool:
    """Return True if the API should require authentication.

    Policy:
    - If MIMF_REQUIRE_AUTH=1, always require.
    - Else, require iff at least one API key is configured.

    """

    if os.environ.get("MIMF_REQUIRE_AUTH", "").strip() in {"1", "true", "TRUE", "yes", "YES"}:
        return True
    return bool(mapping)


def authenticate(api_key: Optional[str], mapping: Dict[str, Actor]) -> Optional[Actor]:
    """Authenticate an API key.

    Security notes:
    - Uses constant-time comparison to reduce timing side-channels.
    - Returns None on failure.

    """

    if not api_key:
        return None

    # Constant-time compare: iterate all keys.
    for k, actor in mapping.items():
        if hmac.compare_digest(k, api_key):
            return actor
    return None
