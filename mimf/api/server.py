from __future__ import annotations

import logging
import os
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import Depends, FastAPI, File, Form, Header, HTTPException, Response, UploadFile
from fastapi.responses import FileResponse
from starlette.requests import Request

from mimf.api.auth import Actor, authenticate, load_auth_config, requires_auth
from mimf.api.middleware import AccessLogMiddleware, RequestIdMiddleware
from mimf.api.models import (
    ContextDetailOut,
    ContextSummaryOut,
    FileInfoOut,
    InspectOut,
    NormalizeOut,
    VerifyBundleOut,
)
from mimf.api.rate_limit import TokenBucketRateLimiter
from mimf.core.normalization import apply_normalized_export_policy, normalize_runtime_object
from mimf.core.plugins import (
    PluginRegistry,
    inspect_file_sandboxed,
    load_builtin_plugins,
    select_file_inspector,
)
from mimf.core.plugins.file_info import sniff_file_info
from mimf.core.policy_engine.policy_pack import load_policy_pack, resolve_policy_pack_path
from mimf.core.runtime.context import RuntimeContext
from mimf.core.runtime.inspection import Inspector
from mimf.core.runtime.object import RuntimeObject
from mimf.core.runtime.storage.sqlite_store import SQLiteRuntimeStore
from mimf.core.security.boundaries import SecurityBoundary
from mimf.forensic.bundle import build_forensic_bundle, verify_forensic_bundle_details

log = logging.getLogger("mimf.api")


@dataclass(frozen=True, slots=True)
class ServiceConfig:
    """Configuration for the API service.

    Security notes:
    - db_path is optional. If not provided, persistence endpoints are disabled.

    """

    db_path: Optional[Path] = None
    max_upload_bytes: int = 25 * 1024 * 1024
    sandbox_inspectors: bool = True
    sandbox_timeout_sec: int = 15
    sandbox_mem_mb: int = 256
    policy_pack: Optional[str] = None
    allow_policy_pack_paths: bool = False


def _env_int(name: str, default: int) -> int:
    """Read an integer environment variable.

    Security notes:
    - Env vars are treated as trusted server configuration.

    """

    raw = os.environ.get(name, "").strip()
    if not raw:
        return int(default)
    try:
        return int(raw)
    except Exception:
        return int(default)


def create_app(*, db_path: Optional[str] = None) -> FastAPI:
    """Create the FastAPI app."""

    cfg = ServiceConfig(
        db_path=Path(db_path) if db_path else None,
        max_upload_bytes=_env_int("MIMF_MAX_UPLOAD_BYTES", 25 * 1024 * 1024),
        sandbox_inspectors=bool(int(os.environ.get("MIMF_SANDBOX_INSPECTORS", "1"))),
        sandbox_timeout_sec=_env_int("MIMF_SANDBOX_TIMEOUT_SEC", 15),
        sandbox_mem_mb=_env_int("MIMF_SANDBOX_MEM_MB", 256),
        policy_pack=(os.environ.get("MIMF_POLICY_PACK") or None),
        allow_policy_pack_paths=bool(int(os.environ.get("MIMF_ALLOW_POLICY_PACK_PATHS", "0"))),
    )
    mapping = load_auth_config()
    must_auth = requires_auth(mapping)

    # Logging: safe defaults (no request bodies), can be configured by host app.
    log.setLevel(os.environ.get("MIMF_LOG_LEVEL", "INFO").upper())

    app = FastAPI(title="MIMF API", version="0.1")

    app.state.cfg = cfg
    app.state.must_auth = must_auth

    # Request correlation + basic access logs.
    app.add_middleware(RequestIdMiddleware)
    app.add_middleware(AccessLogMiddleware)

    # Best-effort in-memory rate limiting (per actor_id or client IP).
    app.state.rate_limiter = TokenBucketRateLimiter.from_env()

    # Optional persistence store
    if cfg.db_path is not None:
        store = SQLiteRuntimeStore(cfg.db_path)
        store.init_schema()
        app.state.store = store
    else:
        app.state.store = None

    def get_actor(
        request: Request,
        x_mimf_api_key: Optional[str] = Header(default=None),
    ) -> Actor:
        """Authenticate request.

        Security notes:
        - If auth is required and missing/invalid, fail closed (401).

        """

        if not must_auth:
            # Dev mode fallback (no key configured)
            actor = Actor(actor_id="anonymous", capabilities=[])
        else:
            actor = authenticate(x_mimf_api_key, mapping)
            if actor is None:
                raise HTTPException(status_code=401, detail="unauthorized")

        # Attach actor for downstream middleware/logging.
        request.state.actor_id = actor.actor_id

        # Rate limit (best-effort, in-memory)
        limiter: TokenBucketRateLimiter = app.state.rate_limiter
        ident = actor.actor_id
        if ident == "anonymous":
            client = getattr(request, "client", None)
            if client and getattr(client, "host", None):
                ident = f"ip:{client.host}"

        decision = limiter.check(ident)
        if not decision.allowed:
            raise HTTPException(
                status_code=429,
                detail="rate_limited",
                headers={"Retry-After": str(int(decision.retry_after_seconds))},
            )

        return actor

    @app.get("/health")
    def health() -> Dict[str, Any]:
        return {
            "ok": True,
            "auth_required": must_auth,
            "db": str(cfg.db_path) if cfg.db_path else None,
        }

    def _require_db() -> SQLiteRuntimeStore:
        """Return the configured SQLiteRuntimeStore or raise 404.

        Security notes:
        - If DB not configured, do not expose persistence endpoints.

        """

        store = getattr(app.state, "store", None)
        if store is None:
            raise HTTPException(status_code=404, detail="persistence_disabled")
        return store

    def _require_cap(actor: Actor, cap: str) -> None:
        """Ensure the actor has a capability.

        Security notes:
        - Fail closed (403) if missing.

        """

        if cap not in (actor.capabilities or []):
            raise HTTPException(status_code=403, detail="forbidden")

    @app.get("/contexts", response_model=List[ContextSummaryOut])
    def list_contexts_endpoint(
        response: Response,
        actor: Actor = Depends(get_actor),
        limit: int = 50,
        offset: int = 0,
        actor_id: Optional[str] = None,
        operation_name: Optional[str] = None,
        created_after: Optional[str] = None,
        created_before: Optional[str] = None,
    ) -> List[ContextSummaryOut]:
        """List persisted contexts (paged) with optional filters.

        Requires capability: runtime:read

        Pagination
        - limit: max rows (bounded server-side)
        - offset: skip rows

        Filters
        - actor_id: exact match
        - operation_name: exact match
        - created_after / created_before: ISO8601 strings

        Returns a list, with pagination hints in headers:
        - X-Next-Offset: next offset if more rows likely
        - X-Has-More: true/false

        """

        _require_cap(actor, "runtime:read")
        store = _require_db()
        rows = store.list_contexts(
            limit=int(limit),
            offset=int(offset),
            actor_id=actor_id,
            operation_name=operation_name,
            created_after=created_after,
            created_before=created_before,
        )

        # Best-effort "has more": if we returned limit rows, assume there may be more.
        lim = max(1, min(500, int(limit)))
        off = max(0, int(offset))
        has_more = len(rows) == lim
        response.headers["X-Has-More"] = "true" if has_more else "false"
        if has_more:
            response.headers["X-Next-Offset"] = str(off + lim)

        return [ContextSummaryOut(**r) for r in rows]

    @app.get("/contexts/{context_id}", response_model=ContextDetailOut)
    def get_context_endpoint(
        context_id: str,
        actor: Actor = Depends(get_actor),
        events_limit: int = 200,
        objects_limit: int = 200,
    ) -> ContextDetailOut:
        """Fetch one persisted context with objects/events (bounded).

        Requires capability: runtime:read

        Security notes:
        - Context content may include sensitive metadata.
        - Capability gate prevents accidental leakage.

        """

        _require_cap(actor, "runtime:read")
        store = _require_db()
        try:
            ctx = store.load_context(context_id)
        except KeyError:
            raise HTTPException(status_code=404, detail="context_not_found")

        # Build summary (counts can be derived).
        summary = ContextSummaryOut(
            context_id=ctx.context_id,
            created_at=ctx.created_at.isoformat(),
            actor_id=ctx.actor_id,
            parent_context_id=ctx.parent_context_id,
            operation_name=ctx.operation_name,
            object_count=len(ctx.get_objects()),
            event_count=len(ctx.get_events()),
        )

        objs = []
        for i, obj in enumerate(ctx.get_objects().values()):
            if i >= int(objects_limit):
                break
            objs.append(obj.snapshot())

        evs = []
        for i, ev in enumerate(ctx.get_events()):
            if i >= int(events_limit):
                break
            evs.append(
                {
                    "event_type": ev.event_type,
                    "event_id": str(ev.event_id),
                    "created_at": ev.created_at.isoformat(),
                    "payload": ev.to_payload(),
                    "previous_event_hash": ev.previous_event_hash,
                    "event_hash": ev.event_hash,
                }
            )

        return ContextDetailOut(
            context=summary,
            objects=objs,
            events=evs,
            integrity_ok=bool(ctx.verify_integrity()),
        )

    def _save_upload_to_temp(upload: UploadFile) -> Path:
        """Persist an UploadFile to a temporary file on disk.

        Security notes:
        - Never trust filename for path; we use a temp directory.
        - Reads in chunks to avoid memory blow-ups.

        """

        tmpdir = Path(tempfile.mkdtemp(prefix="mimf_api_"))
        # Never trust client filename: basename only + length cap.
        safe_name = os.path.basename(upload.filename or "input")[:255]
        out = tmpdir / safe_name
        total = 0
        with out.open("wb") as f:
            while True:
                chunk = upload.file.read(1024 * 1024)
                if not chunk:
                    break
                total += len(chunk)
                if total > cfg.max_upload_bytes:
                    raise HTTPException(status_code=413, detail="upload_too_large")
                f.write(chunk)
        return out

    def _inspect_runtime_object(path: Path, *, labels: List[str]) -> "RuntimeObject":
        """Inspect a path into a RuntimeObject, optionally using a subprocess sandbox.

        Security notes:
        - Sandbox is best-effort; still treat plugins as trusted code.

        """

        registry = PluginRegistry()
        load_builtin_plugins(registry)
        plugin = select_file_inspector(registry, str(path))

        # Optional subprocess sandbox (safer default for API)
        if bool(getattr(cfg, "sandbox_inspectors", False)):
            res = inspect_file_sandboxed(
                plugin_id=plugin.metadata.plugin_id,
                path=str(path),
                timeout_seconds=int(getattr(cfg, "sandbox_timeout_sec", 15)),
                memory_limit_mb=int(getattr(cfg, "sandbox_mem_mb", 256)),
            )
            if not res.ok or res.runtime_object is None:
                raise HTTPException(
                    status_code=400, detail={"error": "sandbox_failed", "reason": res.error}
                )
            runtime_object = res.runtime_object
        else:
            runtime_object = plugin.inspect_file(str(path))

        if labels:
            runtime_object = runtime_object.with_labels(set(labels))

        return runtime_object

    def _effective_export_boundary_and_strict(
        *,
        boundary_id: str,
        boundary_caps_csv: Optional[str],
        strict_hint: bool,
        policy_pack: Optional[str],
    ) -> tuple[SecurityBoundary, bool]:
        """Compute effective boundary + strictness, optionally from a policy pack.

        Security notes:
        - request-provided caps are only hints; we filter to an allowlist.
        - policy packs are resolved under the project policy_packs directory by default.

        """

        allowlist = {
            "export:document.basic",
            "export:document.identifying",
            "export:document.tooling",
        }

        # Default: filter request caps
        requested = [c.strip() for c in (boundary_caps_csv or "").split(",") if c.strip()]
        safe_boundary_caps = [c for c in requested if c in allowlist] or ["export:document.basic"]
        strict_effective = bool(strict_hint)

        # Optional: policy pack overrides
        ref = (policy_pack or getattr(cfg, "policy_pack", None) or "").strip() or None
        if ref:
            base_dir = str(Path(__file__).resolve().parents[2] / "policy_packs")
            pack_path = resolve_policy_pack_path(
                ref,
                base_dir=base_dir,
                allow_arbitrary_paths=bool(getattr(cfg, "allow_policy_pack_paths", False)),
            )
            pack = load_policy_pack(pack_path)
            safe_boundary_caps = [c for c in (pack.allow_capabilities or []) if c in allowlist] or [
                "export:document.basic"
            ]
            strict_effective = pack.export_mode == "deny"

        boundary = SecurityBoundary.from_names(
            boundary_id=boundary_id, capability_names=safe_boundary_caps
        )
        return boundary, strict_effective

    def _inspect_path(path: Path, *, labels: List[str]) -> InspectOut:
        """Inspect a file path via plugin system."""

        runtime_object = _inspect_runtime_object(path, labels=labels)

        # Emit inspection event into a short-lived context
        context = RuntimeContext(
            context_id=f"api-{os.getpid()}-{int(os.times().elapsed)}",
            actor_id=None,
            operation_name="API:inspect",
        )
        context.add_object(runtime_object)
        Inspector.inspect(runtime_object, context)

        info = sniff_file_info(str(path))
        md = dict(runtime_object.metadata or {})
        return InspectOut(
            file=FileInfoOut(
                filename=os.path.basename(str(path)),
                extension=info.extension,
                mime_type=info.mime_type,
                mime_confidence=info.mime_confidence,
                size_bytes=int(path.stat().st_size),
                sha256=md.get("sha256"),
            ),
            object_id=runtime_object.object_id,
            object_type=runtime_object.object_type,
            labels=sorted(list(runtime_object.labels)),
            metadata=md,
            inspector_plugin_id=md.get("inspector_plugin_id"),
        )

    @app.post("/inspect", response_model=InspectOut)
    def inspect_endpoint(
        actor: Actor = Depends(get_actor),
        file: UploadFile = File(...),
        labels: Optional[str] = Form(default=None),
    ) -> InspectOut:
        """Inspect a file.

        Security notes:
        - Returns only plugin-produced metadata signals (no file bytes).

        """

        path = _save_upload_to_temp(file)
        try:
            label_list = [x.strip() for x in (labels or "").split(",") if x.strip()]
            return _inspect_path(path, labels=label_list)
        finally:
            shutil.rmtree(path.parent, ignore_errors=True)

    @app.post("/normalize", response_model=NormalizeOut)
    def normalize_endpoint(
        actor: Actor = Depends(get_actor),
        file: UploadFile = File(...),
        labels: Optional[str] = Form(default=None),
        boundary_id: str = Form(default="api-export"),
        boundary_caps: Optional[str] = Form(default="export:document.basic"),
        strict: bool = Form(default=False),
        policy_pack: Optional[str] = Form(default=None),
    ) -> NormalizeOut:
        """Normalize a file and apply export policy.

        Security notes:
        - Actor capabilities come from auth mapping.
        - Boundary capabilities come from server-side defaults + request hint.
          We treat request caps as a *hint* and filter them to a safe allowlist.

        """

        path = _save_upload_to_temp(file)
        try:
            label_list = [x.strip() for x in (labels or "").split(",") if x.strip()]
            runtime_object = _inspect_runtime_object(path, labels=label_list)

            info = sniff_file_info(str(path))
            md0 = dict(runtime_object.metadata or {})
            file_out = FileInfoOut(
                filename=os.path.basename(str(path)),
                extension=info.extension,
                mime_type=info.mime_type,
                mime_confidence=info.mime_confidence,
                size_bytes=int(path.stat().st_size),
                sha256=md0.get("sha256"),
            )
            dispatch, normalized, sources = normalize_runtime_object(runtime_object, info)

            # Effective boundary + strictness (request hints + optional policy pack)
            boundary, strict_effective = _effective_export_boundary_and_strict(
                boundary_id=boundary_id,
                boundary_caps_csv=boundary_caps,
                strict_hint=bool(strict),
                policy_pack=policy_pack,
            )

            export_res = apply_normalized_export_policy(
                normalized=normalized,
                target_labels=runtime_object.labels,
                boundary=boundary,
                actor_capabilities=actor.capabilities,
                strict=bool(strict_effective),
            )

            out_norm: Dict[str, Any]
            if export_res.decision.status.value == "DENY":
                out_norm = {
                    "error": "export denied by policy",
                    "policy": export_res.decision.to_dict(),
                }
            else:
                out_norm = dict(export_res.redacted)

            return NormalizeOut(
                file=file_out,
                normalizer_id=dispatch.normalizer_id,
                schema_version=dispatch.schema_version,
                normalized=out_norm,
                export_policy=export_res.decision.to_dict(),
                redacted_fields=list(export_res.redacted_fields or []),
            )
        finally:
            shutil.rmtree(path.parent, ignore_errors=True)

    @app.post("/export-bundle")
    def export_bundle_endpoint(
        actor: Actor = Depends(get_actor),
        file: UploadFile = File(...),
        include_original: bool = Form(default=False),
        persist: bool = Form(default=False),
        strict: bool = Form(default=False),
        policy_pack: Optional[str] = Form(default=None),
        boundary_id: str = Form(default="api-export"),
        boundary_caps: Optional[str] = Form(default="export:document.basic"),
    ):
        """Export a forensic bundle zip.

        Returns: application/zip bytes.

        Security notes:
        - Default is NOT to include original bytes.
        - Normalized fields are policy-controlled.

        """

        path = _save_upload_to_temp(file)
        tmp_bundle_dir = Path(tempfile.mkdtemp(prefix="mimf_bundle_"))
        try:
            runtime_object = _inspect_runtime_object(path, labels=[])

            context = RuntimeContext(
                context_id=f"api-bundle-{int(os.times().elapsed)}",
                actor_id=actor.actor_id,
                operation_name="API:export-bundle",
            )
            context.add_object(runtime_object)
            Inspector.inspect(runtime_object, context)

            # Optional persistence (SQLite): persist the runtime context for later retrieval.
            # Security: require explicit runtime:write capability (fail closed).
            if bool(persist):
                _require_cap(actor, "runtime:write")
                store = _require_db()
                store.save_context(context, overwrite=False)

            boundary, strict_effective = _effective_export_boundary_and_strict(
                boundary_id=boundary_id,
                boundary_caps_csv=boundary_caps,
                strict_hint=bool(strict),
                policy_pack=policy_pack,
            )

            result = build_forensic_bundle(
                input_path=str(path),
                runtime_object=runtime_object,
                context=context,
                out_dir=str(tmp_bundle_dir),
                include_original=bool(include_original),
                include_absolute_path=False,
                boundary=boundary,
                actor_capabilities=actor.capabilities,
                strict_export=bool(strict_effective),
            )

            zip_base = str(tmp_bundle_dir)
            zip_path = shutil.make_archive(zip_base, "zip", root_dir=str(tmp_bundle_dir))

            # Add metadata in headers for client convenience.
            headers = {
                "X-MIMF-Context-Id": context.context_id,
                "X-MIMF-Bundle-Id": result.bundle_id,
                "X-MIMF-Merkle-Root": result.merkle_root,
            }
            return FileResponse(
                zip_path,
                media_type="application/zip",
                filename=f"mimf_bundle_{result.bundle_id}.zip",
                headers=headers,
            )
        finally:
            shutil.rmtree(path.parent, ignore_errors=True)
            shutil.rmtree(tmp_bundle_dir, ignore_errors=True)

    @app.post("/verify-bundle", response_model=VerifyBundleOut)
    def verify_bundle_endpoint(
        actor: Actor = Depends(get_actor),
        bundle_zip: UploadFile = File(...),
        public_key: Optional[UploadFile] = File(default=None),
        custody_public_key: Optional[UploadFile] = File(default=None),
        sender_public_key: Optional[UploadFile] = File(default=None),
        receiver_public_key: Optional[UploadFile] = File(default=None),
    ) -> VerifyBundleOut:
        """Verify a forensic bundle zip (integrity + optional signatures).

        Security notes:
        - Bundle zip and provided public keys are untrusted input.
        - We extract into a temp directory and recompute hashes + Merkle root.
        - Authenticity is verified ONLY when a trusted public key is provided.

        """

        zpath = _save_upload_to_temp(bundle_zip)
        out_dir = Path(tempfile.mkdtemp(prefix="mimf_verify_"))
        key_dir = Path(tempfile.mkdtemp(prefix="mimf_keys_"))
        try:
            shutil.unpack_archive(str(zpath), str(out_dir), format="zip")

            def _save_key(u: Optional[UploadFile], name: str) -> Optional[str]:
                if u is None:
                    return None
                # Small bound: public keys should be tiny.
                p = key_dir / name
                total = 0
                with p.open("wb") as f:
                    while True:
                        chunk = u.file.read(64 * 1024)
                        if not chunk:
                            break
                        total += len(chunk)
                        if total > 1024 * 1024:
                            raise HTTPException(status_code=413, detail="key_too_large")
                        f.write(chunk)
                return str(p)

            pub_path = _save_key(public_key, "public_key.pem")
            custody_pub_path = _save_key(custody_public_key, "custody_public_key.pem")
            sender_pub_path = _save_key(sender_public_key, "sender_public_key.pem")
            receiver_pub_path = _save_key(receiver_public_key, "receiver_public_key.pem")

            details = verify_forensic_bundle_details(
                str(out_dir),
                public_key_path=pub_path,
                custody_public_key_path=custody_pub_path,
                sender_public_key_path=sender_pub_path,
                receiver_public_key_path=receiver_pub_path,
            )
            ok = bool(details.get("ok"))
            return VerifyBundleOut(ok=ok, details=details)
        except HTTPException:
            raise
        except Exception as e:
            return VerifyBundleOut(ok=False, details={"error": str(e)})
        finally:
            shutil.rmtree(zpath.parent, ignore_errors=True)
            shutil.rmtree(out_dir, ignore_errors=True)
            shutil.rmtree(key_dir, ignore_errors=True)

    return app


def app_from_env() -> FastAPI:
    """Factory used by Uvicorn / Docker entrypoints.

    Reads:
    - MIMF_DB_PATH: optional SQLite database path

    """

    db_path = os.environ.get("MIMF_DB_PATH", "").strip() or None
    return create_app(db_path=db_path)


# Default ASGI app (importable as mimf.api.server:app)
app = app_from_env()
