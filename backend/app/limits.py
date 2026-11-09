"""Bound request bodies before framework JSON parsing or upload processing."""
from starlette.responses import JSONResponse


class BodyLimitMiddleware:
    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope.get("method") not in {"POST", "PATCH", "PUT"}:
            await self.app(scope, receive, send)
            return
        limit = 20_000_000 if scope.get("path") == "/api/ingest/pcap" else 3_000_000
        headers = dict(scope.get("headers", []))
        declared = headers.get(b"content-length")
        if declared is not None:
            try:
                length = int(declared)
                if length < 0:
                    raise ValueError
            except ValueError:
                await JSONResponse({"detail": "Invalid Content-Length"}, status_code=400)(scope, receive, send)
                return
            if length > limit:
                await JSONResponse({"detail": f"Request body exceeds {limit:,} bytes"}, status_code=413)(scope, receive, send)
                return
        # ASGI streams may omit Content-Length. Stop collecting at the same bound.
        # The framework receives only a complete bounded body, so JSON allocation is bounded too.
        body = bytearray()
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            chunk = message.get("body", b"")
            if len(body) + len(chunk) > limit:
                await JSONResponse({"detail": f"Request body exceeds {limit:,} bytes"}, status_code=413)(scope, receive, send)
                return
            body.extend(chunk)
            if not message.get("more_body", False):
                break
        consumed = False

        async def bounded_receive():
            nonlocal consumed
            if not consumed:
                consumed = True
                return {"type": "http.request", "body": bytes(body), "more_body": False}
            return await receive()

        await self.app(scope, bounded_receive, send)
