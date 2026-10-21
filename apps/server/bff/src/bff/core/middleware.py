from starlette.requests import Request

from bff.core.security import CSRF_COOKIE, SESSION_COOKIE
from bff.exception_handlers import problem_response


class BrowserSecurityMiddleware:
    def __init__(self, app) -> None:
        self.app = app

    async def __call__(self, scope, receive, send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return
        request = Request(scope, receive)

        async def send_headers(message):
            if message["type"] == "http.response.start":
                headers = list(message.get("headers", []))
                headers.extend([(b"x-content-type-options", b"nosniff"), (b"referrer-policy", b"same-origin")])
                if scope["path"].startswith("/api/"):
                    headers = [(k, v) for k, v in headers if k.lower() != b"cache-control"]
                    headers.append((b"cache-control", b"no-store"))
                message["headers"] = headers
            await send(message)

        async def reject(status, detail):
            await problem_response(status, detail)(scope, receive, send_headers)

        if scope["path"].startswith("/api/"):
            security = scope["app"].state.security
            settings = security.settings
            raw_cookies = [part.split("=", 1)[0].strip() for header in request.headers.getlist("cookie") for part in header.split(";")]
            if any(raw_cookies.count(name) > 1 for name in (SESSION_COOKIE, CSRF_COOKIE)):
                await reject(400, "Ambiguous session cookies")
                return
            # Bound the body before FastAPI parses JSON, including login/password input.
            chunks = bytearray()
            more = True
            while more:
                message = await receive()
                if message["type"] == "http.disconnect":
                    return
                chunk = message.get("body", b"")
                if len(chunks) + len(chunk) > settings.max_request_bytes:
                    await reject(413, "Request body exceeds the configured limit")
                    return
                chunks.extend(chunk)
                more = message.get("more_body", False)
            if chunks:
                content_type = request.headers.get("content-type", "").split(";", 1)[0].strip().lower()
                if content_type != "application/json":
                    await reject(415, "Use application/json")
                    return
            delivered = False

            async def buffered_receive():
                nonlocal delivered
                if delivered:
                    return await receive()
                delivered = True
                return {"type": "http.request", "body": bytes(chunks), "more_body": False}

            await self.app(scope, buffered_receive, send_headers)
        else:
            await self.app(scope, receive, send_headers)
