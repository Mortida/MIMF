from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


def _parse_dt(s: str) -> Optional[datetime]:
    """Parse ISO8601-ish datetimes produced by MIMF."""

    if not isinstance(s, str) or not s.strip():
        return None
    try:
        # Most of the project uses datetime.now(timezone.utc).isoformat() -> has offset.
        return datetime.fromisoformat(s)
    except Exception:
        return None


@dataclass(frozen=True, slots=True)
class TimelineItem:
    """A single time-ordered record from a forensic bundle."""

    created_at: str
    kind: str
    label: str
    details: Dict[str, Any]


def _read_jsonl(path: Path, *, limit: int) -> Iterable[Dict[str, Any]]:
    """Read up to `limit` JSONL objects."""

    if not path.exists():
        return []
    out: List[Dict[str, Any]] = []
    with path.open("r", encoding="utf-8") as f:
        for i, line in enumerate(f):
            if limit and i >= limit:
                break
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except Exception:
                continue
    return out


def load_bundle_timeline(
    bundle_dir: str,
    *,
    limit_events: int = 500,
    limit_custody: int = 500,
) -> List[TimelineItem]:
    """Load a chronological timeline from bundle events + custody artifacts.

    Sources:
    - events.jsonl
    - custody/addendum.json (and referenced custody entries/receipts)

    Security notes:
    - Treat all JSON inputs as untrusted. We parse with best-effort.
    - Timeline is a viewer; it does not modify bundle files.

    """

    root = Path(bundle_dir)
    items: List[TimelineItem] = []

    # 1) Runtime/events timeline
    for ev in _read_jsonl(root / "events.jsonl", limit=limit_events):
        created_at = str(ev.get("created_at") or "")
        items.append(
            TimelineItem(
                created_at=created_at,
                kind="event",
                label=str(ev.get("event_type") or "EVENT"),
                details={
                    "event_id": ev.get("event_id"),
                    "event_type": ev.get("event_type"),
                    "payload": ev.get("payload"),
                },
            )
        )

    # 2) Custody timeline (entries + receipts)
    add_path = root / "custody" / "addendum.json"
    if add_path.exists():
        try:
            add = json.loads(add_path.read_text(encoding="utf-8"))
        except Exception:
            add = {}
        custody = add.get("custody") if isinstance(add.get("custody"), dict) else {}

        entries = custody.get("entries") if isinstance(custody.get("entries"), dict) else {}
        receipts = custody.get("receipts") if isinstance(custody.get("receipts"), dict) else {}

        # Preserve insertion order (dict order is stable in Python 3.7+)
        for i, rel in enumerate(list(entries.keys())[: (limit_custody or len(entries))]):
            p = root / str(rel)
            if not p.exists():
                continue
            try:
                obj = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue
            created_at = str(obj.get("created_at") or "")
            items.append(
                TimelineItem(
                    created_at=created_at,
                    kind="custody",
                    label=str(obj.get("action") or "CUSTODY"),
                    details={
                        "relpath": str(rel),
                        "actor_id": obj.get("actor_id"),
                        "note": obj.get("note"),
                        "prev_entry_sha256": obj.get("prev_entry_sha256"),
                    },
                )
            )

        for i, rel in enumerate(list(receipts.keys())[: (limit_custody or len(receipts))]):
            p = root / str(rel)
            if not p.exists():
                continue
            try:
                obj = json.loads(p.read_text(encoding="utf-8"))
            except Exception:
                continue

            transfer = obj.get("transfer") if isinstance(obj.get("transfer"), dict) else {}
            created_at = str(transfer.get("created_at") or obj.get("created_at") or "")

            sigs = obj.get("signatures") if isinstance(obj.get("signatures"), dict) else {}
            sender = sigs.get("sender") if isinstance(sigs.get("sender"), dict) else {}
            receiver = sigs.get("receiver") if isinstance(sigs.get("receiver"), dict) else None

            items.append(
                TimelineItem(
                    created_at=created_at,
                    kind="receipt",
                    label="TRANSFER",
                    details={
                        "relpath": str(rel),
                        "from_actor_id": transfer.get("from_actor_id"),
                        "to_actor_id": transfer.get("to_actor_id"),
                        "note": transfer.get("note"),
                        "sender_signer_id": sender.get("signer_id"),
                        "receiver_present": receiver not in (None, {}, ""),
                        "receiver_signer_id": (
                            receiver.get("signer_id") if isinstance(receiver, dict) else None
                        ),
                    },
                )
            )

    # Sort by timestamp (unknown timestamps sink to the end, but remain stable).
    def _key(it: TimelineItem):
        dt = _parse_dt(it.created_at)
        return (dt is None, dt or datetime.max)

    items.sort(key=_key)
    return items


def render_timeline_text(items: List[TimelineItem], *, limit: int = 0) -> str:
    """Render timeline into a human-friendly text report."""

    lines: List[str] = []
    for i, it in enumerate(items):
        if limit and i >= limit:
            break
        when = it.created_at or "(unknown time)"
        if it.kind == "event":
            lines.append(f"{when}  [EVENT]   {it.label}")
        elif it.kind == "custody":
            actor = it.details.get("actor_id")
            lines.append(f"{when}  [CUSTODY] {it.label}  actor={actor}")
        elif it.kind == "receipt":
            frm = it.details.get("from_actor_id")
            to = it.details.get("to_actor_id")
            recv = "accepted" if it.details.get("receiver_present") else "pending"
            lines.append(f"{when}  [TRANSFER] {frm} -> {to}  ({recv})")
        else:
            lines.append(f"{when}  [{it.kind.upper()}] {it.label}")
    return "\n".join(lines) + ("\n" if lines else "")
