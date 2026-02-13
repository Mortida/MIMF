from __future__ import annotations

import re
from pathlib import Path

# Remove single lines that mention complexity in comments/docstrings.
SINGLE_LINE = [
    re.compile(r"^\s*#\s*(time|space)\s+complexity\s*:.*$", re.I),
    re.compile(r"^\s*#\s*(time|space)\s*:\s*.*$", re.I),
    re.compile(r"^\s*(time|space)\s+complexity\s*:.*$", re.I),
    re.compile(r"^\s*(time|space)\s*:\s*.*$", re.I),
    re.compile(r"^\s*[-*]\s*(time|space)\s+complexity\s*:.*$", re.I),
    re.compile(r"^\s*[-*]\s*(time|space)\s*:\s*.*$", re.I),
    # Generic "Complexity" heading lines
    re.compile(r"^\s*(#\s*)?complexity\s*:?\s*$", re.I),
    re.compile(r"^\s*(#\s*)?complexities\s*:?\s*$", re.I),
    # Bullet lines like "- O(1) time, O(1) space"
    re.compile(r"^\s*[-*]\s*O\([^)]*\).*?(time|space).*?$", re.I),
    # Non-bullet "O(1) time, O(1) space"
    re.compile(r"^\s*O\([^)]*\).*?(time|space).*?$", re.I),
]


def is_blank(line: str) -> bool:
    return line.strip() == ""


def drop_single_line(line: str) -> bool:
    return any(p.match(line) for p in SINGLE_LINE)


def clean_text(text: str) -> str:
    lines = text.splitlines(True)  # keep newlines
    out: list[str] = []

    i = 0
    while i < len(lines):
        line = lines[i]

        # Drop explicit single-line matches
        if drop_single_line(line):
            i += 1
            # If we dropped a "Complexity" heading, also drop immediate related bullet lines
            # until a blank line or docstring terminator is reached.
            while i < len(lines):
                nxt = lines[i]
                if is_blank(nxt):
                    break
                # stop if we reached end of docstring
                if nxt.lstrip().startswith(('"""', "'''")):
                    break
                # Drop likely complexity bullets/lines under the heading.
                if re.match(r"^\s*[-*]\s*O\([^)]*\)", nxt, re.I) or re.match(
                    r"^\s*O\([^)]*\)", nxt, re.I
                ):
                    i += 1
                    continue
                # Also drop bullets mentioning time/space
                if re.search(r"\b(time|space)\b", nxt, re.I) and re.search(r"\bO\(", nxt):
                    i += 1
                    continue
                break
            continue

        out.append(line)
        i += 1

    cleaned = "".join(out)
    cleaned = re.sub(r"\n{4,}", "\n\n\n", cleaned)
    return cleaned


def main() -> int:
    root = Path(".")
    files = [
        p for p in root.rglob("*.py") if ".venv" not in p.parts and "site-packages" not in p.parts
    ]

    changed = 0
    for p in files:
        original = p.read_text(encoding="utf-8")
        updated = clean_text(original)
        if updated != original:
            p.write_text(updated, encoding="utf-8")
            changed += 1

    print(f"Updated {changed} file(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
