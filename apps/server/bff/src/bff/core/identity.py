from typing import Literal
from uuid import UUID

import httpx
from pydantic import AwareDatetime, BaseModel, Field, SecretStr, ValidationError

from bff.core.security import BffSettings
from bff.exceptions import BffError


class TokenResponse(BaseModel):
    access_token: SecretStr = Field(min_length=1, max_length=16384)
    refresh_token: SecretStr = Field(min_length=1, max_length=512)
    token_type: Literal["bearer"]
    expires_in: int = Field(gt=0, le=86400)
    session_id: UUID
    refresh_expires_at: AwareDatetime


class IdentityUser(BaseModel):
    user_id: UUID


class PasskeyCredentialDescriptor(BaseModel):
    type: Literal["public-key"]
    id: str


class PasskeyAuthenticationOptions(BaseModel):
    challenge: str = Field(min_length=1)
    rpId: str = Field(min_length=1)
    timeout: int = Field(gt=0)
    allowCredentials: list[PasskeyCredentialDescriptor]
    userVerification: Literal["required"]


class PasskeyOptionsResponse(BaseModel):
    challenge_id: UUID
    public_key: PasskeyAuthenticationOptions


class IdentityClient:
    def __init__(self, client: httpx.AsyncClient, settings: BffSettings) -> None:
        self.client = client
        self.settings = settings

    async def request(self, method: str, path: str, *, access_token: str | None = None,
                      body: bytes = b"", query: bytes = b"", upstream: str | None = None) -> httpx.Response:
        base = upstream or self.settings.identity_base_url
        url = httpx.URL(base).copy_with(path=path, query=query)
        headers = {"Accept": "application/json", "Accept-Encoding": "identity"}
        if body:
            headers["Content-Type"] = "application/json"
        if access_token is not None:
            headers["Authorization"] = f"Bearer {access_token}"
        request = self.client.build_request(method, url, headers=headers, content=body)
        # Even if an upstream sets cookies, never share them across browser sessions.
        request.headers.pop("cookie", None)
        try:
            response = await self.client.send(request, stream=True, follow_redirects=False)
            try:
                content = bytearray()
                async for chunk in response.aiter_bytes():
                    if len(content) + len(chunk) > self.settings.max_response_bytes:
                        raise BffError(502, "Upstream response exceeds the configured limit")
                    content.extend(chunk)
                buffered = httpx.Response(response.status_code, headers=response.headers,
                                          content=bytes(content), request=request)
            finally:
                await response.aclose()
                self.client.cookies.clear()
        except httpx.TimeoutException:
            raise BffError(504, "Upstream request timed out") from None
        except httpx.HTTPError:
            raise BffError(503, "Upstream service is unavailable") from None
        if 300 <= buffered.status_code < 400:
            raise BffError(502, "Upstream redirects are not accepted")
        return buffered

    @staticmethod
    def require_success(response: httpx.Response) -> None:
        if response.status_code < 400:
            return
        headers = {}
        if response.status_code == 429 and response.headers.get("retry-after", "").isdigit():
            headers["Retry-After"] = response.headers["retry-after"]
        detail = "Upstream service rejected the request"
        try:
            payload = response.json()
            # Validation messages use fixed labels; never reflect input, ctx, msg,
            # or arbitrary field names from upstream errors.
            if isinstance(payload, dict):
                if isinstance(payload.get("detail"), str):
                    detail = payload["detail"][:512]
                elif response.status_code == 422 and isinstance(payload.get("detail"), list):
                    labels = {"email": "Email address", "username": "Username", "password": "Password",
                              "new_password": "New password", "token": "Token"}
                    messages = {"missing": "is required", "string_type": "must be text",
                                "string_too_short": "is too short", "string_too_long": "is too long",
                                "too_short": "is too short", "too_long": "is too long",
                                "string_pattern_mismatch": "has an invalid format", "value_error": "is invalid"}
                    issues = []
                    for error in payload["detail"][:8]:
                        if not isinstance(error, dict):
                            continue
                        location = error.get("loc")
                        field = location[-1] if isinstance(location, list) and location else None
                        label = labels.get(field) if isinstance(field, str) else None
                        error_type = error.get("type")
                        if not isinstance(error_type, str):
                            error_type = "unknown"
                        if field in ("password", "new_password") and error_type in ("string_too_short", "too_short"):
                            issues.append(f"{label} must contain at least 8 characters.")
                        elif label:
                            issues.append(f"{label} {messages.get(error_type, 'is invalid')}.")
                        else:
                            issues.append("Check the supplied form fields.")
                    if issues:
                        detail = " ".join(dict.fromkeys(issues))[:512]
        except ValueError:
            pass
        raise BffError(response.status_code, detail, headers=headers)

    async def tokens(self, path: str, body: dict) -> TokenResponse:
        import json

        response = await self.request("POST", path, body=json.dumps(body).encode())
        self.require_success(response)
        try:
            return TokenResponse.model_validate_json(response.content)
        except ValidationError:
            raise BffError(502, "Identity returned an invalid token response") from None

    async def user(self, access_token: str) -> UUID:
        response = await self.request("GET", "/api/users/me", access_token=access_token)
        self.require_success(response)
        try:
            return IdentityUser.model_validate_json(response.content).user_id
        except ValidationError:
            raise BffError(502, "Identity returned an invalid user response") from None

    async def passkey_options(self, browser_binding: str) -> PasskeyOptionsResponse:
        import json

        response = await self.request("POST", "/api/auth/passkey/options",
                                      body=json.dumps({"browser_binding": browser_binding}).encode())
        self.require_success(response)
        try:
            return PasskeyOptionsResponse.model_validate_json(response.content)
        except ValidationError:
            raise BffError(502, "Identity returned invalid passkey options") from None
