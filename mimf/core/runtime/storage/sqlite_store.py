from __future__ import annotations

import json
import sqlite3
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from ..context import RuntimeContext
from ..object import RuntimeObject
from ..events import RuntimeEvent
from ..event_factory import event_from_record

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
    raise TypeError(f"not JSON serializable: {type(o)!r}")


def _json_dumps(obj: Any) -> str:
    """Deterministic JSON serialization.

    Security notes:
    - Do not serialize arbitrary objects; this function expects JSON-safe values.
    """

    return json.dumps(obj, sort_keys=True, separators=(",", ":"), default=_json_default)


def _json_loads(text: str) -> Any:
    """Parse JSON text.

    Security: input is untrusted; json.loads is safe for data but may be large.

    Time:  O(n)
    Space: O(n)
    """

    return json.loads(text)


def _dt_to_iso(dt: datetime) -> str:
    """Serialize datetime to ISO8601.

    Time:  O(1)
    Space: O(1)
    """

    return dt.isoformat()


def _dt_from_iso(text: str) -> datetime:
    """Parse ISO8601 datetime.

    Time:  O(1)
    Space: O(1)
    """

    return datetime.fromisoformat(text)


@dataclass(slots=True)
class SQLiteRuntimeStore:
    """SQLite persistence for RuntimeContext, objects and events.

    Security notes:
    - Treat all values read from the database as untrusted.
    - This store does NOT encrypt data at rest.
      If you need encryption, place the DB on an encrypted volume.

    Complexity
    - save_context: O(o + e) inserts, where o=#objects, e=#events
    - load_context: O(o + e)
    - Storage size: O(total payload sizes)
    """

    db_path: Path

    def __post_init__(self) -> None:
        self.db_path = Path(self.db_path)

    def connect(self) -> sqlite3.Connection:
        """Open a SQLite connection.

        Time:  O(1)
        Space: O(1)
        """

        con = sqlite3.connect(str(self.db_path))
        con.execute("PRAGMA foreign_keys = ON")
        return con

    def init_schema(self) -> None:
        """Create tables if missing.

        Time:  O(1)
        Space: O(1)
        """

        with self.connect() as con:
            con.executescript(
                """
                CREATE TABLE IF NOT EXISTS contexts (
                    context_id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    actor_id TEXT,
                    parent_context_id TEXT,
                    operation_name TEXT
                );

                CREATE TABLE IF NOT EXISTS objects (
                    context_id TEXT NOT NULL,
                    object_id TEXT NOT NULL,
                    object_type TEXT NOT NULL,
                    origin_json TEXT NOT NULL,
                    metadata_json TEXT NOT NULL,
                    labels_json TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    snapshot_hash TEXT NOT NULL,
                    PRIMARY KEY (context_id, object_id),
                    FOREIGN KEY (context_id) REFERENCES contexts(context_id) ON DELETE CASCADE
                );

                CREATE TABLE IF NOT EXISTS events (
                    context_id TEXT NOT NULL,
                    idx INTEGER NOT NULL,
                    event_type TEXT NOT NULL,
                    payload_json TEXT NOT NULL,
                    event_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    previous_event_hash TEXT,
                    event_hash TEXT,
                    PRIMARY KEY (context_id, idx),
                    FOREIGN KEY (context_id) REFERENCES contexts(context_id) ON DELETE CASCADE
                );
                """
            )

    def save_context(self, ctx: RuntimeContext, *, overwrite: bool = False) -> None:
        """Persist a RuntimeContext.

        Security: ctx is trusted in-process; DB writes are controlled.

        Time:  O(o + e)
        Space: O(1) extra (streaming inserts)
        """

        self.init_schema()

        with self.connect() as con:
            cur = con.cursor()

            if overwrite:
                cur.execute("DELETE FROM contexts WHERE context_id = ?", (ctx.context_id,))

            cur.execute(
                "INSERT INTO contexts(context_id, created_at, actor_id, parent_context_id, operation_name) VALUES(?,?,?,?,?)",
                (
                    ctx.context_id,
                    _dt_to_iso(ctx.created_at),
                    ctx.actor_id,
                    ctx.parent_context_id,
                    ctx.operation_name,
                ),
            )

            # Objects
            for obj in ctx.get_objects().values():
                cur.execute(
                    """INSERT INTO objects(
                        context_id, object_id, object_type, origin_json, metadata_json, labels_json, created_at, snapshot_hash
                    ) VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        ctx.context_id,
                        obj.object_id,
                        obj.object_type,
                        _json_dumps(obj.origin),
                        _json_dumps(obj.metadata),
                        _json_dumps(sorted(obj.labels)),
                        _dt_to_iso(obj.created_at),
                        obj.snapshot_hash,
                    ),
                )

            # Events (ordered)
            for idx, ev in enumerate(ctx.get_events()):
                payload = ev.to_payload()
                cur.execute(
                    """INSERT INTO events(
                        context_id, idx, event_type, payload_json, event_id, created_at, previous_event_hash, event_hash
                    ) VALUES(?,?,?,?,?,?,?,?)""",
                    (
                        ctx.context_id,
                        idx,
                        ev.event_type,
                        _json_dumps(payload),
                        str(ev.event_id),
                        _dt_to_iso(ev.created_at),
                        ev.previous_event_hash,
                        ev.event_hash,
                    ),
                )

            con.commit()

    
    def list_contexts(
        self,
        *,
        limit: int = 50,
        offset: int = 0,
        actor_id: Optional[str] = None,
        operation_name: Optional[str] = None,
        created_after: Optional[str] = None,
        created_before: Optional[str] = None,
    ) -> List[Dict[str, Any]]:
        """List recent contexts (with object/event counts) with optional filters.

        Filters
        - actor_id: exact match
        - operation_name: exact match
        - created_after / created_before: ISO8601 strings (inclusive bounds)

        Pagination
        - limit: max rows (bounded)
        - offset: skip rows

        Security notes:
        - Inputs are treated as untrusted; query is parameterized.

        Time:  O(limit)
        Space: O(limit)
        """

        self.init_schema()
        limit_i = max(1, min(500, int(limit)))
        offset_i = max(0, int(offset))

        where = []
        params: List[Any] = []

        if actor_id:
            where.append("c.actor_id = ?")
            params.append(str(actor_id))

        if operation_name:
            where.append("c.operation_name = ?")
            params.append(str(operation_name))

        if created_after:
            # ISO string compare works with consistent formatting (we store isoformat()).
            where.append("c.created_at >= ?")
            params.append(str(created_after))

        if created_before:
            where.append("c.created_at <= ?")
            params.append(str(created_before))

        where_sql = ("WHERE " + " AND ".join(where)) if where else ""

        query = f"""
            SELECT
                c.context_id,
                c.created_at,
                c.actor_id,
                c.parent_context_id,
                c.operation_name,
                (SELECT COUNT(*) FROM objects o WHERE o.context_id = c.context_id) AS object_count,
                (SELECT COUNT(*) FROM events e WHERE e.context_id = c.context_id) AS event_count
            FROM contexts c
            {where_sql}
            ORDER BY c.created_at DESC
            LIMIT ? OFFSET ?
        """

        params.extend([limit_i, offset_i])

        with self.connect() as con:
            rows = con.execute(query, tuple(params)).fetchall()

        return [
            {
                "context_id": r[0],
                "created_at": r[1],
                "actor_id": r[2],
                "parent_context_id": r[3],
                "operation_name": r[4],
                "object_count": int(r[5]),
                "event_count": int(r[6]),
            }
            for r in rows
        ]
    def load_context(self, context_id: str) -> RuntimeContext:
        """Load a RuntimeContext and reconstruct objects/events.

        Security notes:
        - Treat DB content as untrusted.
        - Event reconstruction is whitelisted by type.

        Time:  O(o + e)
        Space: O(o + e)
        """

        self.init_schema()

        with self.connect() as con:
            row = con.execute(
                "SELECT context_id, created_at, actor_id, parent_context_id, operation_name FROM contexts WHERE context_id = ?",
                (context_id,),
            ).fetchone()
            if row is None:
                raise KeyError(f"context_id not found: {context_id}")

            ctx = RuntimeContext(
                context_id=row[0],
                created_at=_dt_from_iso(row[1]),
                actor_id=row[2],
                parent_context_id=row[3],
                operation_name=row[4],
            )

            # Objects
            obj_rows = con.execute(
                """SELECT object_id, object_type, origin_json, metadata_json, labels_json, created_at, snapshot_hash
                   FROM objects WHERE context_id = ? ORDER BY object_id""",
                (context_id,),
            ).fetchall()

            for r in obj_rows:
                origin = _json_loads(r[2])
                metadata = _json_loads(r[3])
                labels = frozenset(_json_loads(r[4]))
                created_at = _dt_from_iso(r[5])

                # Recompute hash to validate consistency
                obj = RuntimeObject.create(
                    object_id=r[0],
                    object_type=r[1],
                    origin=origin,
                    metadata=metadata,
                    labels=labels,
                    created_at=created_at,
                )

                if obj.snapshot_hash != r[6]:
                    raise ValueError(f"Object snapshot_hash mismatch for {obj.object_id}")

                ctx.add_object(obj)

            # Events
            ev_rows = con.execute(
                """SELECT idx, event_type, payload_json, event_id, created_at, previous_event_hash, event_hash
                   FROM events WHERE context_id = ? ORDER BY idx""",
                (context_id,),
            ).fetchall()

            for r in ev_rows:
                payload = _json_loads(r[2])
                rec = {
                    "event_type": r[1],
                    "payload": payload,
                    "event_id": r[3],
                    "created_at": r[4],
                    "previous_event_hash": r[5],
                    "event_hash": r[6],
                }
                ev = event_from_record(rec)

                # We bypass RuntimeContext.emit_event to avoid re-hashing; we load sealed events.
                ctx._events.append(ev)  # trusted internal restore

            # Verify chain integrity after restore
            if not ctx.verify_integrity():
                raise ValueError("Loaded event chain failed integrity check")

        return ctx
