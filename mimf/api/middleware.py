from __future__ import annotations

import logging
import time
from typing import Callable, Optional
from uuid import uuid4

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import Response

log = logging.getLogger("mimf.api")


class RequestIdMiddleware(BaseHTTPMiddleware):
    """Attach a request id to every response.

    Header:
      - X-Request-ID

    Security notes:
    - If a client supplies X-Request-ID, we accept it only if it is short.
      Otherwise we generate our own to reduce header abuse/log injection.

    """

    def __init__(self, app, *, header_name: str = "X-Request-ID", max_len: int = 128):
        super().__init__(app)
        self._header_name = header_name
        self._max_len = max_len

    async def dispatch(self, request: Request, call_next: Callable):
        rid = request.headers.get(self._header_name)
        if not rid or len(rid) > self._max_len:
            rid = uuid4().hex
        request.state.request_id = rid
        response: Response = await call_next(request)
        response.headers[self._header_name] = rid
        return response


class AccessLogMiddleware(BaseHTTPMiddleware):
    """Structured access logging.

    Security notes:
    - Avoid logging full request bodies or file names.
    - Log request_id to correlate with server-side events.

    """

    async def dispatch(self, request: Request, call_next: Callable):
        start = time.monotonic()
        response: Optional[Response] = None
        try:
            response = await call_next(request)
            return response
        finally:
            dur_ms = int((time.monotonic() - start) * 1000)
            rid = getattr(request.state, "request_id", None)
            actor_id = getattr(request.state, "actor_id", None)
            status_code = getattr(response, "status_code", None)

            log.info(
                "api_request",
                extra={
                    "request_id": rid,
                    "actor_id": actor_id,
                    "method": request.method,
                    "path": request.url.path,
                    "status_code": status_code,
                    "duration_ms": dur_ms,
                },
            )
