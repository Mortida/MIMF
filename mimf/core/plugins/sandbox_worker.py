from __future__ import annotations

import argparse
import json
import os
import sys

from datetime import date, datetime
from pathlib import Path
from uuid import UUID

def _json_default(o):
    if isinstance(o, (datetime, date)):
        return o.isoformat()
    if isinstance(o, Path):
        return str(o)
    if isinstance(o, UUID):
        return str(o)
    if isinstance(o, bytes):
        return o.hex()
    if isinstance(o, set):
        return list(o)
    return str(o)  # safe last resort for sandbox transport


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return int(default)
    try:
        return int(raw)
    except Exception:
        return int(default)


def _apply_resource_limits() -> None:
    """Best-effort resource limits for the sandbox worker.

    Security notes:
    - Limits are best-effort and platform-specific. On Windows, resource module may be missing.

    Time:  O(1)
    Space: O(1)
    """

    try:
        import resource  # type: ignore

        mem_mb = _env_int("MIMF_SANDBOX_MEM_MB", 256)
        # Address space limit in bytes
        mem_bytes = int(mem_mb) * 1024 * 1024
        # Limit CPU seconds (soft/hard)
        cpu_seconds = _env_int("MIMF_SANDBOX_CPU_SEC", 10)

        # RLIMIT_AS is not enforced on all systems; still useful on Linux.
        try:
            resource.setrlimit(resource.RLIMIT_AS, (mem_bytes, mem_bytes))
        except Exception:
            pass

        try:
            resource.setrlimit(resource.RLIMIT_CPU, (cpu_seconds, cpu_seconds))
        except Exception:
            pass

        # Prevent accidental huge file creation.
        try:
            resource.setrlimit(resource.RLIMIT_FSIZE, (10 * 1024 * 1024, 10 * 1024 * 1024))
        except Exception:
            pass

        # Reduce file descriptor abuse.
        try:
            resource.setrlimit(resource.RLIMIT_NOFILE, (64, 64))
        except Exception:
            pass

    except Exception:
        return


def main(argv: list[str] | None = None) -> int:
    """Sandbox worker entrypoint.

    Loads built-in plugins, selects plugin by id, inspects file, prints JSON.

    Time:  dominated by inspector
    Space: inspector-dependent
    """

    _apply_resource_limits()

    parser = argparse.ArgumentParser(prog="mimf-sandbox-worker")
    parser.add_argument("--plugin-id", required=True)
    parser.add_argument("--path", required=True)
    parser.add_argument("--object-id", default=None)
    args = parser.parse_args(argv)

    try:
        from mimf.core.plugins import PluginRegistry, load_builtin_plugins
        from mimf.core.plugins.file_inspector import FileInspectorPlugin
    except Exception as e:
        print(json.dumps({"ok": False, "error": f"import_failed: {e}"}, default=_json_default))
        return 2

    path = args.path
    plugin_id = args.plugin_id

    try:
        reg = PluginRegistry()
        load_builtin_plugins(reg)
        plugin = reg.get(plugin_id)
        if not isinstance(plugin, FileInspectorPlugin):
            raise TypeError(f"plugin_not_file_inspector: {plugin_id}")
        obj = plugin.inspect_file(path, object_id=args.object_id)
        print(json.dumps({"ok": True, "plugin_id": plugin_id, "runtime_object": obj.snapshot()}, default=_json_default))
        return 0
    except Exception as e:
        # Do not print tracebacks by default (may leak paths). Keep it simple.
        print(json.dumps({"ok": False, "plugin_id": plugin_id, "error": str(e)}, default=_json_default))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
