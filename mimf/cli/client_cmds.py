from __future__ import annotations

import argparse
import json
import os
import sys
from typing import Dict

from mimf.client.http import MIMFHttpClient


def _print_json(obj: object) -> None:
    """Print JSON to stdout."""
    print(json.dumps(obj, indent=2, sort_keys=True, default=str))


def cmd_client_health(args: argparse.Namespace) -> int:
    """Call GET /health.

    Security notes:
    - Treat server response as untrusted.

    """
    c = MIMFHttpClient(args.url, api_key=args.api_key, max_upload_bytes=args.max_upload_bytes)
    r = c.get("/health")
    if r.status >= 400:
        print(r.body_bytes.decode("utf-8", errors="replace"), file=sys.stderr)
        return 2
    _print_json(r.json())
    return 0


def cmd_client_inspect(args: argparse.Namespace) -> int:
    """Upload a file to POST /inspect."""
    c = MIMFHttpClient(args.url, api_key=args.api_key, max_upload_bytes=args.max_upload_bytes)
    fields = {}
    if args.labels:
        fields["labels"] = args.labels
    r = c.post_multipart(
        "/inspect",
        fields=fields,
        file_field=("file", os.path.basename(args.file)),
        file_path=args.file,
    )
    if r.status >= 400:
        print(r.body_bytes.decode("utf-8", errors="replace"), file=sys.stderr)
        return 2
    _print_json(r.json())
    return 0


def cmd_client_normalize(args: argparse.Namespace) -> int:
    """Upload a file to POST /normalize."""
    c = MIMFHttpClient(args.url, api_key=args.api_key, max_upload_bytes=args.max_upload_bytes)
    fields = {
        "boundary_id": args.boundary_id,
        "boundary_caps": args.boundary_caps,
        "strict": "true" if args.strict else "false",
    }
    if args.labels:
        fields["labels"] = args.labels
    r = c.post_multipart(
        "/normalize",
        fields=fields,
        file_field=("file", os.path.basename(args.file)),
        file_path=args.file,
    )
    if r.status >= 400:
        print(r.body_bytes.decode("utf-8", errors="replace"), file=sys.stderr)
        return 2
    _print_json(r.json())
    return 0


def cmd_client_export_bundle(args: argparse.Namespace) -> int:
    """Upload a file to POST /export-bundle and save the returned zip.

    Security notes:
    - The returned zip is untrusted until verified.

    """
    c = MIMFHttpClient(args.url, api_key=args.api_key, max_upload_bytes=args.max_upload_bytes)
    fields = {
        "include_original": "true" if args.include_original else "false",
        "persist": "true" if args.persist else "false",
        "strict": "true" if args.strict else "false",
        "boundary_id": args.boundary_id,
        "boundary_caps": args.boundary_caps,
    }
    r = c.post_multipart(
        "/export-bundle",
        fields=fields,
        file_field=("file", os.path.basename(args.file)),
        file_path=args.file,
    )
    if r.status >= 400:
        print(r.body_bytes.decode("utf-8", errors="replace"), file=sys.stderr)
        return 2

    out_path = args.out
    if not out_path:
        # Use server-suggested filename if present
        disp = r.headers.get("Content-Disposition") or r.headers.get("content-disposition")
        if disp and "filename=" in disp:
            out_path = disp.split("filename=", 1)[1].strip('" ')
        else:
            out_path = "mimf_bundle.zip"

    with open(out_path, "wb") as f:
        f.write(r.body_bytes)

    meta = {
        "saved_to": os.path.abspath(out_path),
        "context_id": r.headers.get("X-MIMF-Context-Id") or r.headers.get("x-mimf-context-id"),
        "bundle_id": r.headers.get("X-MIMF-Bundle-Id") or r.headers.get("x-mimf-bundle-id"),
        "merkle_root": r.headers.get("X-MIMF-Merkle-Root") or r.headers.get("x-mimf-merkle-root"),
    }
    _print_json(meta)
    return 0


def cmd_client_verify_bundle(args: argparse.Namespace) -> int:
    """Upload a bundle zip to POST /verify-bundle."""
    c = MIMFHttpClient(args.url, api_key=args.api_key, max_upload_bytes=args.max_upload_bytes)
    fields: Dict[str, str] = {}
    extra: Dict[str, str] = {}
    if args.public_key:
        extra["public_key"] = args.public_key
    if args.custody_public_key:
        extra["custody_public_key"] = args.custody_public_key
    if args.sender_public_key:
        extra["sender_public_key"] = args.sender_public_key
    if args.receiver_public_key:
        extra["receiver_public_key"] = args.receiver_public_key

    r = c.post_multipart(
        "/verify-bundle",
        fields=fields,
        file_field=("bundle_zip", os.path.basename(args.bundle_zip)),
        file_path=args.bundle_zip,
        extra_files=extra if extra else None,
    )
    if r.status >= 400:
        print(r.body_bytes.decode("utf-8", errors="replace"), file=sys.stderr)
        return 2
    _print_json(r.json())
    return 0


def cmd_demo_api(args: argparse.Namespace) -> int:
    """One-command demo against a running API.

    Steps:
    1) inspect
    2) normalize
    3) export-bundle
    4) verify-bundle

    """
    c = MIMFHttpClient(args.url, api_key=args.api_key, max_upload_bytes=args.max_upload_bytes)

    # Inspect
    r1 = c.post_multipart(
        "/inspect",
        fields={"labels": args.labels or ""},
        file_field=("file", os.path.basename(args.file)),
        file_path=args.file,
    )
    if r1.status >= 400:
        print(r1.body_bytes.decode("utf-8", errors="replace"), file=sys.stderr)
        return 2

    # Normalize
    r2 = c.post_multipart(
        "/normalize",
        fields={
            "labels": args.labels or "",
            "boundary_id": args.boundary_id,
            "boundary_caps": args.boundary_caps,
            "strict": "true" if args.strict else "false",
        },
        file_field=("file", os.path.basename(args.file)),
        file_path=args.file,
    )
    if r2.status >= 400:
        print(r2.body_bytes.decode("utf-8", errors="replace"), file=sys.stderr)
        return 2

    # Export
    r3 = c.post_multipart(
        "/export-bundle",
        fields={
            "include_original": "true" if args.include_original else "false",
            "persist": "true" if args.persist else "false",
            "strict": "true" if args.strict else "false",
            "boundary_id": args.boundary_id,
            "boundary_caps": args.boundary_caps,
        },
        file_field=("file", os.path.basename(args.file)),
        file_path=args.file,
    )
    if r3.status >= 400:
        print(r3.body_bytes.decode("utf-8", errors="replace"), file=sys.stderr)
        return 2

    zip_path = args.out or "mimf_bundle.zip"
    with open(zip_path, "wb") as f:
        f.write(r3.body_bytes)

    # Verify
    r4 = c.post_multipart(
        "/verify-bundle",
        fields={},
        file_field=("bundle_zip", os.path.basename(zip_path)),
        file_path=zip_path,
        extra_files={
            k: v
            for k, v in {
                "public_key": args.public_key,
                "custody_public_key": args.custody_public_key,
                "sender_public_key": args.sender_public_key,
                "receiver_public_key": args.receiver_public_key,
            }.items()
            if v
        }
        or None,
    )
    if r4.status >= 400:
        print(r4.body_bytes.decode("utf-8", errors="replace"), file=sys.stderr)
        return 2

    out = {
        "inspect": r1.json(),
        "normalize": r2.json(),
        "export": {
            "saved_zip": os.path.abspath(zip_path),
            "context_id": r3.headers.get("X-MIMF-Context-Id")
            or r3.headers.get("x-mimf-context-id"),
            "bundle_id": r3.headers.get("X-MIMF-Bundle-Id") or r3.headers.get("x-mimf-bundle-id"),
            "merkle_root": r3.headers.get("X-MIMF-Merkle-Root")
            or r3.headers.get("x-mimf-merkle-root"),
        },
        "verify": r4.json(),
    }
    _print_json(out)
    return 0


def register_client_commands(sub: argparse._SubParsersAction) -> None:
    """Register the `client` and `demo` commands."""

    client = sub.add_parser("client", help="MIMF API client (talk to a running server)")
    client.add_argument("--url", default="http://127.0.0.1:8080", help="Base API URL")
    client.add_argument("--api-key", default=None, help="API key (X-MIMF-API-Key)")
    client.add_argument(
        "--max-upload-bytes", type=int, default=25 * 1024 * 1024, help="Client-side upload cap"
    )
    csub = client.add_subparsers(dest="client_cmd", required=True)

    h = csub.add_parser("health", help="Check server health")
    h.set_defaults(func=cmd_client_health)

    ins = csub.add_parser("inspect", help="Upload a file for inspection")
    ins.add_argument("file", help="Path to local file")
    ins.add_argument("--labels", default=None, help="Comma-separated labels")
    ins.set_defaults(func=cmd_client_inspect)

    norm = csub.add_parser("normalize", help="Upload a file for normalization (policy-controlled)")
    norm.add_argument("file", help="Path to local file")
    norm.add_argument("--labels", default=None, help="Comma-separated labels")
    norm.add_argument("--boundary-id", default="api-export", help="Boundary id")
    norm.add_argument(
        "--boundary-caps",
        default="export:document.basic",
        help="Comma-separated boundary caps (hint)",
    )
    norm.add_argument("--strict", action="store_true", help="Deny instead of redact")
    norm.set_defaults(func=cmd_client_normalize)

    exp = csub.add_parser("export-bundle", help="Export a forensic bundle zip (from API)")
    exp.add_argument("file", help="Path to local file")
    exp.add_argument("--out", default=None, help="Output zip file path")
    exp.add_argument(
        "--include-original", action="store_true", help="Include original bytes in bundle"
    )
    exp.add_argument(
        "--persist",
        action="store_true",
        help="Persist context in server DB (requires runtime:write)",
    )
    exp.add_argument("--boundary-id", default="api-export", help="Boundary id")
    exp.add_argument(
        "--boundary-caps",
        default="export:document.basic",
        help="Comma-separated boundary caps (hint)",
    )
    exp.add_argument("--strict", action="store_true", help="Deny instead of redact")
    exp.set_defaults(func=cmd_client_export_bundle)

    vb = csub.add_parser("verify-bundle", help="Verify a bundle zip via API")
    vb.add_argument("bundle_zip", help="Path to bundle .zip")
    vb.add_argument(
        "--public-key", default=None, help="Path to Ed25519 public key for bundle signature"
    )
    vb.add_argument("--custody-public-key", default=None, help="Public key for custody addendum")
    vb.add_argument("--sender-public-key", default=None, help="Sender pubkey for transfer receipts")
    vb.add_argument(
        "--receiver-public-key", default=None, help="Receiver pubkey for transfer receipts"
    )
    vb.set_defaults(func=cmd_client_verify_bundle)

    demo = sub.add_parser("demo", help="End-to-end demo against a running API")
    demo.add_argument("file", help="Path to local file")
    demo.add_argument("--url", default="http://127.0.0.1:8080", help="Base API URL")
    demo.add_argument("--api-key", default=None, help="API key")
    demo.add_argument("--labels", default=None, help="Comma-separated labels")
    demo.add_argument("--out", default="mimf_bundle.zip", help="Output bundle zip filename")
    demo.add_argument(
        "--include-original", action="store_true", help="Include original bytes in bundle"
    )
    demo.add_argument(
        "--persist",
        action="store_true",
        help="Persist context in server DB (requires runtime:write)",
    )
    demo.add_argument("--boundary-id", default="api-export", help="Boundary id")
    demo.add_argument(
        "--boundary-caps",
        default="export:document.basic",
        help="Comma-separated boundary caps (hint)",
    )
    demo.add_argument("--strict", action="store_true", help="Deny instead of redact")
    demo.add_argument(
        "--max-upload-bytes", type=int, default=25 * 1024 * 1024, help="Client-side upload cap"
    )
    demo.add_argument("--public-key", default=None, help="Bundle signature pubkey (optional)")
    demo.add_argument("--custody-public-key", default=None, help="Custody pubkey (optional)")
    demo.add_argument("--sender-public-key", default=None, help="Sender receipt pubkey (optional)")
    demo.add_argument(
        "--receiver-public-key", default=None, help="Receiver receipt pubkey (optional)"
    )
    demo.set_defaults(func=cmd_demo_api)
