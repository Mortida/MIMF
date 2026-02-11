from __future__ import annotations

import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from mimf.core.runtime.object import RuntimeObject


@dataclass(frozen=True, slots=True)
class SandboxResult:
    """Result of a sandboxed inspector run.

    Security notes:
    - stderr may contain sensitive paths; do not expose it by default.

    Time:  O(1)
    Space: O(1)
    """

    ok: bool
    plugin_id: str
    runtime_object: Optional[RuntimeObject]
    error: Optional[str] = None
    details: Optional[Dict[str, Any]] = None


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return int(default)
    try:
        return int(raw)
    except Exception:
        return int(default)


def inspect_file_sandboxed(
    *,
    plugin_id: str,
    path: str,
    object_id: Optional[str] = None,
    timeout_seconds: Optional[int] = None,
    memory_limit_mb: Optional[int] = None,
) -> SandboxResult:
    """Run a file inspector in a subprocess sandbox.

    The sandbox worker loads built-in plugins, looks up `plugin_id`, inspects `path`,
    and prints a JSON result to stdout.

    Security notes:
    - This is best-effort isolation. It mitigates crashes and limits CPU/memory,
      but it does not provide full OS-level sandboxing.
    - For stronger isolation, run MIMF inside a container or dedicated user.

    Complexity
    - Dominated by inspector cost (typically O(n) hashing)
    - Parent overhead: O(1)
    """

    abs_path = str(Path(path).resolve())
    if timeout_seconds is None:
        timeout_seconds = _env_int("MIMF_SANDBOX_TIMEOUT_SEC", 15)
    if memory_limit_mb is None:
        memory_limit_mb = _env_int("MIMF_SANDBOX_MEM_MB", 256)

    cmd = [
        sys.executable,
        "-m",
        "mimf.core.plugins.sandbox_worker",
        "--plugin-id",
        plugin_id,
        "--path",
        abs_path,
    ]
    if object_id:
        cmd += ["--object-id", object_id]

    # Harden the child environment slightly.
    env = dict(os.environ)
    env["PYTHONNOUSERSITE"] = "1"
    env["PYTHONDONTWRITEBYTECODE"] = "1"

    # Provide limits to the worker.
    env["MIMF_SANDBOX_MEM_MB"] = str(int(memory_limit_mb))

    try:
        proc = subprocess.run(
            cmd,
            input=None,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
            timeout=float(timeout_seconds),
            check=False,
            text=True,
        )
    except subprocess.TimeoutExpired:
        return SandboxResult(
            ok=False,
            plugin_id=plugin_id,
            runtime_object=None,
            error="sandbox_timeout",
            details={"timeout_seconds": timeout_seconds},
        )

    stdout = (proc.stdout or "").strip()
    if not stdout:
        return SandboxResult(
            ok=False,
            plugin_id=plugin_id,
            runtime_object=None,
            error="sandbox_no_output",
            details={"returncode": proc.returncode},
        )

    try:
        payload = json.loads(stdout)
    except Exception:
        return SandboxResult(
            ok=False,
            plugin_id=plugin_id,
            runtime_object=None,
            error="sandbox_bad_json",
            details={"returncode": proc.returncode},
        )

    if not isinstance(payload, dict):
        return SandboxResult(ok=False, plugin_id=plugin_id, runtime_object=None, error="sandbox_bad_payload")

    if not payload.get("ok"):
        return SandboxResult(
            ok=False,
            plugin_id=plugin_id,
            runtime_object=None,
            error=str(payload.get("error") or "sandbox_failed"),
            details={k: v for k, v in payload.items() if k not in {"runtime_object"}},
        )

    snap = payload.get("runtime_object")
    if not isinstance(snap, dict):
        return SandboxResult(ok=False, plugin_id=plugin_id, runtime_object=None, error="sandbox_missing_runtime_object")

    try:
        obj = RuntimeObject.from_snapshot(snap)
    except Exception as e:
        return SandboxResult(ok=False, plugin_id=plugin_id, runtime_object=None, error=f"sandbox_unmarshal_failed: {e}")

    return SandboxResult(ok=True, plugin_id=str(payload.get("plugin_id") or plugin_id), runtime_object=obj)
