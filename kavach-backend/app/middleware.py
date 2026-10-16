import time
import uuid
from collections import defaultdict, deque

from starlette.responses import JSONResponse

from app.config import get_settings


class RequestGuard:
    def __init__(self, app):
        self.app = app
        self.windows = defaultdict(deque)
        self.last_cleanup = time.monotonic()

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http":
            return await self.app(scope, receive, send)
        request_id = str(uuid.uuid4())
        scope.setdefault("state", {})["request_id"] = request_id
        settings = get_settings()

        async def guarded_send(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend(
                    [
                        (b"x-request-id", request_id.encode()),
                        (b"x-content-type-options", b"nosniff"),
                        (b"x-frame-options", b"DENY"),
                        (b"referrer-policy", b"no-referrer"),
                        (b"cache-control", b"no-store"),
                        (b"permissions-policy", b"camera=(), microphone=(), geolocation=()"),
                    ]
                )
                if settings.environment == "production":
                    headers.append((b"strict-transport-security", b"max-age=31536000; includeSubDomains"))
                message["headers"] = headers
            await send(message)

        async def reject(status, code, message, headers=None):
            response = JSONResponse(
                {"error": {"code": code, "message": message, "request_id": request_id}},
                status_code=status,
                headers=headers,
            )
            await response(scope, receive, guarded_send)

        path = scope.get("path", "")
        now = time.monotonic()
        if now - self.last_cleanup > 60:
            self.windows = defaultdict(
                deque, {key: value for key, value in self.windows.items() if value and value[-1] > now - 60}
            )
            self.last_cleanup = now
        if path not in {"/health", "/health/ready"} and scope["method"] != "OPTIONS":
            client = (scope.get("client") or ("unknown",))[0]
            category = "scan" if path.startswith("/api/v1/audits/") else "general"
            limit = settings.scan_limit_per_minute if category == "scan" else settings.rate_limit_per_minute
            if path.startswith("/api/v1/auth/") and scope["method"] == "POST":
                category, limit = "auth", min(limit, 15)
            window = self.windows[(client, category)]
            while window and window[0] <= now - 60:
                window.popleft()
            if len(window) >= limit:
                retry = max(1, int(61 - (now - window[0])))
                return await reject(
                    429, "rate_limited", "Too many requests; try again shortly", {"Retry-After": str(retry)}
                )
            window.append(now)
        try:
            length = dict(scope.get("headers", [])).get(b"content-length")
            if length is not None and int(length) > settings.max_request_bytes:
                return await reject(413, "payload_too_large", "Request body is too large")
        except ValueError:
            return await reject(400, "invalid_request", "Invalid Content-Length header")
        # Buffer only a bounded body, including chunked requests without Content-Length.
        chunks = []
        size = 0
        while True:
            message = await receive()
            if message["type"] == "http.disconnect":
                return
            size += len(message.get("body", b""))
            if size > settings.max_request_bytes:
                return await reject(413, "payload_too_large", "Request body is too large")
            chunks.append(message)
            if not message.get("more_body", False):
                break
        position = 0

        async def replay():
            nonlocal position
            if position < len(chunks):
                chunk = chunks[position]
                position += 1
                return chunk
            return await receive()

        await self.app(scope, replay, guarded_send)
