from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple


@dataclass(frozen=True, slots=True)
class PolicyPack:
    """Loaded policy pack configuration.

    This is intentionally minimal: it exists to make policy defaults portable
    (CLI, API, Docker demo) without requiring a full policy DSL.

    Supported schema (YAML/JSON)

    export_policy:
      mode: redact | deny | allow
      allow_capabilities:
        - export:document.basic
        - export:document.identifying
        - export:document.tooling

    Security notes:
    - Treat policy pack files as trusted configuration.
    - In the API, do NOT allow arbitrary filesystem paths by default.

    Complexity
    - load: O(n) time, O(n) space for file size n.
    """

    pack_id: str
    export_mode: str
    allow_capabilities: List[str]


def _strip_comment(line: str) -> str:
    # Remove YAML comments (simple: ignore '#' when not in quotes).
    # For our limited grammar, this is sufficient.
    if "#" in line:
        return line.split("#", 1)[0].rstrip()
    return line.rstrip()


def _parse_minimal_yaml(text: str) -> Dict[str, Any]:
    """Parse a minimal YAML subset used by our policy packs.

    Supports:
    - Nested mappings by indentation (2 spaces)
    - Lists ("- item")
    - Scalar strings

    This is not a general YAML parser.

    Time:  O(n)
    Space: O(n)
    """

    # Tokenize lines
    raw_lines = [ln for ln in (_strip_comment(l) for l in text.splitlines()) if ln.strip()]
    root: Dict[str, Any] = {}
    stack: List[Tuple[int, Dict[str, Any]]] = [(0, root)]

    i = 0
    while i < len(raw_lines):
        line = raw_lines[i]
        indent = len(line) - len(line.lstrip(" "))
        stripped = line.strip()

        # Determine current mapping by indentation
        while stack and indent < stack[-1][0]:
            stack.pop()
        if not stack:
            raise ValueError("Invalid indentation")
        cur = stack[-1][1]

        if stripped.startswith("-"):
            raise ValueError("Top-level list not supported")

        if ":" not in stripped:
            raise ValueError(f"Invalid line (expected key: value): {line}")

        key, rest = stripped.split(":", 1)
        key = key.strip()
        rest = rest.strip()

        if rest == "":
            # Look ahead: if the next indented lines are a list, parse it.
            items: List[str] = []
            j = i + 1
            while j < len(raw_lines):
                nxt = raw_lines[j]
                nxt_indent = len(nxt) - len(nxt.lstrip(" "))
                nxt_stripped = nxt.strip()
                if nxt_indent <= indent:
                    break
                if not nxt_stripped.startswith("-"):
                    break
                item = nxt_stripped[1:].strip()
                if (item.startswith(""") and item.endswith(""")) or (item.startswith("'") and item.endswith("'")):
                    item = item[1:-1]
                items.append(item)
                j += 1

            if items:
                cur[key] = items
                i = j
                continue

            # Start nested mapping
            new_map: Dict[str, Any] = {}
            cur[key] = new_map
            stack.append((indent + 2, new_map))
            i += 1
            continue

        # Scalar assignment
        # Detect list block on next lines (e.g., allow_capabilities:)
        if rest == "[]":
            cur[key] = []
            i += 1
            continue

        # Trim quotes for simple values
        if (rest.startswith("\"") and rest.endswith("\"")) or (rest.startswith("'") and rest.endswith("'")):
            val = rest[1:-1]
        else:
            val = rest

        cur[key] = val
        i += 1

        # If next line is an indented list, attach it (only for this key)
        items: List[str] = []
        while i < len(raw_lines):
            nxt = raw_lines[i]
            nxt_indent = len(nxt) - len(nxt.lstrip(" "))
            nxt_stripped = nxt.strip()
            if nxt_indent <= indent:
                break
            if not nxt_stripped.startswith("-"):
                break
            item = nxt_stripped[1:].strip()
            if (item.startswith("\"") and item.endswith("\"")) or (item.startswith("'") and item.endswith("'")):
                item = item[1:-1]
            items.append(item)
            i += 1

        if items:
            cur[key] = items

    return root


def _parse_json(text: str) -> Dict[str, Any]:
    import json

    obj = json.loads(text)
    if not isinstance(obj, dict):
        raise ValueError("Policy pack JSON must be an object")
    return obj


def load_policy_pack(path: str) -> PolicyPack:
    """Load a policy pack from YAML/JSON.

    Time:  O(n)
    Space: O(n)
    """

    p = Path(path)
    text = p.read_text(encoding="utf-8")
    suffix = p.suffix.lower()

    if suffix in {".json"}:
        data = _parse_json(text)
    elif suffix in {".yaml", ".yml"}:
        data = _parse_minimal_yaml(text)
    else:
        # Try YAML first, then JSON
        try:
            data = _parse_minimal_yaml(text)
        except Exception:
            data = _parse_json(text)

    export = data.get("export_policy")
    if not isinstance(export, dict):
        raise ValueError("policy pack missing export_policy")

    mode = str(export.get("mode", "redact")).strip().lower()
    if mode not in {"redact", "deny", "allow"}:
        raise ValueError(f"invalid export_policy.mode: {mode}")

    caps = export.get("allow_capabilities", [])
    if caps is None:
        caps = []
    if not isinstance(caps, list) or not all(isinstance(x, str) for x in caps):
        raise ValueError("export_policy.allow_capabilities must be a list of strings")

    return PolicyPack(pack_id=p.stem, export_mode=mode, allow_capabilities=list(caps))


def resolve_policy_pack_path(
    pack: str,
    *,
    base_dir: str,
    allow_arbitrary_paths: bool = False,
) -> str:
    """Resolve a policy pack reference to a safe filesystem path.

    - If pack is an existing path and allow_arbitrary_paths is True, return it.
    - Otherwise, treat pack as a basename within base_dir.

    Security notes:
    - Prevent path traversal by forcing resolution under base_dir.

    Time:  O(1)
    Space: O(1)
    """

    p = Path(pack)
    if allow_arbitrary_paths and p.exists():
        return str(p)

    base = Path(base_dir).resolve()
    candidate = (base / pack).resolve()
    if base not in candidate.parents and candidate != base:
        raise ValueError("policy pack path traversal blocked")
    # Convenience: allow passing a pack name without extension (default -> default.yaml)
    if not candidate.exists() and candidate.suffix == "":
        for ext in (".yaml", ".yml", ".json"):
            c2 = Path(str(candidate) + ext).resolve()
            if base in c2.parents or c2 == base:
                if c2.exists():
                    candidate = c2
                    break
    if not candidate.exists():
        raise FileNotFoundError(str(candidate))
    return str(candidate)
