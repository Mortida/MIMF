from __future__ import annotations

import json
import mimetypes
import os
import ssl
import uuid
from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Tuple
from urllib.error import HTTPError, URLError
from urllib.parse import urljoin
from urllib.request import Request, urlopen


@dataclass(frozen=True, slots=True)
class HttpResponse:
    """HTTP response wrapper.

    Security notes:
    - Treat `body_bytes` as untrusted.

    """

    status: int
    headers: Mapping[str, str]
    body_bytes: bytes

    def json(self) -> Any:
        """Decode body as JSON."""

        return json.loads(self.body_bytes.decode("utf-8", errors="strict"))


class MIMFHttpClient:
    """Minimal stdlib-only HTTP client for MIMF API.

    Supports multipart uploads without external dependencies.

    Security notes:
    - Enforces a max upload size to avoid accidental huge memory usage.
    - Does NOT disable TLS verification.

    Time/Space: depends on request size.
    """

    def __init__(
        self, base_url: str, api_key: Optional[str] = None, max_upload_bytes: int = 25 * 1024 * 1024
    ):
        self.base_url = base_url.rstrip("/") + "/"
        self.api_key = api_key
        self.max_upload_bytes = int(max_upload_bytes)

    def get(self, path: str) -> HttpResponse:
        """HTTP GET."""

        url = urljoin(self.base_url, path.lstrip("/"))
        req = Request(url=url, method="GET")
        if self.api_key:
            req.add_header("X-MIMF-API-Key", self.api_key)
        return _do_request(req)

    def post_multipart(
        self,
        path: str,
        *,
        fields: Mapping[str, str],
        file_field: Optional[Tuple[str, str]] = None,
        file_path: Optional[str] = None,
        file_mime: Optional[str] = None,
        extra_files: Optional[Dict[str, str]] = None,
    ) -> HttpResponse:
        """HTTP POST multipart/form-data.

        Args:
          fields: form fields (string values)
          file_field: (field_name, filename) for primary upload file
          file_path: local file path for primary upload file
          file_mime: optional MIME for primary file
          extra_files: mapping field_name -> file_path for additional file uploads


        Security notes:
        - This builds the full multipart body in memory. For safety, a size cap is enforced.
        """

        url = urljoin(self.base_url, path.lstrip("/"))

        files: List[Tuple[str, str, bytes, str]] = []
        if file_field and file_path:
            field_name, filename = file_field
            data = _read_file_bounded(file_path, self.max_upload_bytes)
            ct = file_mime or mimetypes.guess_type(filename)[0] or "application/octet-stream"
            files.append((field_name, filename, data, ct))

        if extra_files:
            for fname, fpath in extra_files.items():
                bname = os.path.basename(fpath)
                data = _read_file_bounded(fpath, self.max_upload_bytes)
                ct = mimetypes.guess_type(bname)[0] or "application/octet-stream"
                files.append((fname, bname, data, ct))

        body, boundary = _encode_multipart(fields=dict(fields), files=files)
        req = Request(url=url, data=body, method="POST")
        req.add_header("Content-Type", f"multipart/form-data; boundary={boundary}")
        req.add_header("Content-Length", str(len(body)))
        if self.api_key:
            req.add_header("X-MIMF-API-Key", self.api_key)
        return _do_request(req)


def _read_file_bounded(path: str, max_bytes: int) -> bytes:
    """Read file bytes up to a maximum."""

    st = os.stat(path)
    if st.st_size > max_bytes:
        raise ValueError(f"file too large for client upload cap: {st.st_size} > {max_bytes}")
    with open(path, "rb") as f:
        data = f.read()
    if len(data) > max_bytes:
        raise ValueError("file too large for client upload cap")
    return data


def _encode_multipart(
    *, fields: Dict[str, str], files: List[Tuple[str, str, bytes, str]]
) -> Tuple[bytes, str]:
    """Encode multipart/form-data.


    Security notes:
    - Caller should enforce size limits.
    """

    boundary = "----mimf-" + uuid.uuid4().hex
    crlf = "\r\n"
    parts: List[bytes] = []

    for name, value in fields.items():
        parts.append(f"--{boundary}{crlf}".encode("utf-8"))
        parts.append(f'Content-Disposition: form-data; name="{name}"{crlf}{crlf}'.encode("utf-8"))
        parts.append(str(value).encode("utf-8"))
        parts.append(crlf.encode("utf-8"))

    for field_name, filename, data, content_type in files:
        parts.append(f"--{boundary}{crlf}".encode("utf-8"))
        parts.append(
            f'Content-Disposition: form-data; name="{field_name}"; filename="{filename}"{crlf}'.encode(
                "utf-8"
            )
        )
        parts.append(f"Content-Type: {content_type}{crlf}{crlf}".encode("utf-8"))
        parts.append(data)
        parts.append(crlf.encode("utf-8"))

    parts.append(f"--{boundary}--{crlf}".encode("utf-8"))
    body = b"".join(parts)
    return body, boundary


def _do_request(req: Request) -> HttpResponse:
    """Execute a request.


    Security notes:
    - Uses default SSL context (verification ON).
    """

    try:
        ctx = ssl.create_default_context()
        with urlopen(req, context=ctx) as resp:
            body = resp.read()
            headers = {k: v for k, v in resp.headers.items()}
            return HttpResponse(status=int(resp.status), headers=headers, body_bytes=body)
    except HTTPError as e:
        body = e.read() if hasattr(e, "read") else b""
        headers = dict(getattr(e, "headers", {}) or {})
        return HttpResponse(
            status=int(getattr(e, "code", 0) or 0), headers=headers, body_bytes=body
        )
    except URLError as e:
        raise RuntimeError(f"network error: {e}") from e
