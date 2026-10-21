from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
import re
import secrets
from urllib.parse import urlsplit

from cryptography.fernet import Fernet, MultiFernet
from sqlalchemy.engine import make_url

SESSION_COOKIE = "__Host-bff-session"
CSRF_COOKIE = "__Host-bff-csrf"
SECRET_PATTERN = re.compile(r"[A-Za-z0-9_-]{43}\Z")


def origin_url(value: str, *, https: bool = False) -> str:
    parts = urlsplit(value)
    if (parts.scheme not in ({"https"} if https else {"http", "https"}) or not parts.hostname
            or parts.username or parts.password or parts.path not in {"", "/"}
            or parts.query or parts.fragment):
        raise ValueError("Use an absolute origin URL without credentials, path, query, or fragment")
    # Accessing port also rejects invalid port numbers.
    parts.port
    return value.rstrip("/")


@dataclass(frozen=True)
class BffSettings:
    database_url: str = field(repr=False)
    public_origin: str
    identity_base_url: str
    session_hmac_key: bytes = field(repr=False)
    token_encryption_keys: tuple[bytes, ...] = field(repr=False)
    session_ttl_seconds: int = 2592000
    session_idle_seconds: int = 86400
    refresh_margin_seconds: int = 30
    cleanup_interval_seconds: int = 60
    retention_seconds: int = 2592000
    max_request_bytes: int = 1048576
    max_response_bytes: int = 4194304
    upstreams: dict[str, str] = field(default_factory=dict)

    def __post_init__(self) -> None:
        url = make_url(self.database_url)
        if url.drivername != "postgresql+asyncpg" or not url.database or url.database in {"postgres", "template0", "template1"}:
            raise ValueError("BFF_DB_URL must use postgresql+asyncpg and an application database")
        if origin_url(self.public_origin, https=True) != self.public_origin:
            raise ValueError("BFF_PUBLIC_ORIGIN must be an HTTPS origin without a trailing slash")
        origin_url(self.identity_base_url)
        if len(self.session_hmac_key) < 32:
            raise ValueError("BFF_SESSION_HMAC_KEY must contain at least 32 bytes")
        if not self.token_encryption_keys:
            raise ValueError("Set BFF_TOKEN_ENCRYPTION_KEYS to one or more comma-separated Fernet keys")
        for key in self.token_encryption_keys:
            Fernet(key)
        if any(value <= 0 for value in (
            self.session_ttl_seconds, self.session_idle_seconds, self.refresh_margin_seconds,
            self.cleanup_interval_seconds, self.retention_seconds, self.max_request_bytes, self.max_response_bytes,
        )):
            raise ValueError("BFF lifetimes and size limits must be positive")
        for name, upstream in self.upstreams.items():
            if not re.fullmatch(r"[a-z][a-z0-9-]{0,62}", name):
                raise ValueError("Upstream names must be lowercase service names")
            origin_url(upstream)
            if origin_url(upstream) == origin_url(self.identity_base_url):
                raise ValueError("Identity must use the identity gateway, not BFF_UPSTREAMS")

    @classmethod
    def from_env(cls) -> BffSettings:
        try:
            return cls(
                database_url=os.environ["BFF_DB_URL"],
                public_origin=os.environ["BFF_PUBLIC_ORIGIN"],
                identity_base_url=os.environ["BFF_IDENTITY_BASE_URL"],
                session_hmac_key=os.environ["BFF_SESSION_HMAC_KEY"].encode(),
                token_encryption_keys=tuple(key.strip().encode() for key in os.environ["BFF_TOKEN_ENCRYPTION_KEYS"].split(",")),
                **{name: int(os.environ.get(env, str(default))) for name, env, default in (
                    ("session_ttl_seconds", "BFF_SESSION_TTL_SECONDS", 2592000),
                    ("session_idle_seconds", "BFF_SESSION_IDLE_SECONDS", 86400),
                    ("refresh_margin_seconds", "BFF_REFRESH_MARGIN_SECONDS", 30),
                    ("cleanup_interval_seconds", "BFF_CLEANUP_INTERVAL_SECONDS", 60),
                    ("retention_seconds", "BFF_SESSION_RETENTION_SECONDS", 2592000),
                    ("max_request_bytes", "BFF_MAX_REQUEST_BYTES", 1048576),
                    ("max_response_bytes", "BFF_MAX_RESPONSE_BYTES", 4194304),
                )},
                upstreams=json.loads(os.environ.get("BFF_UPSTREAMS", "{}")),
            )
        except KeyError as exc:
            raise ValueError(f"Set {exc.args[0]} before starting BFF") from None


class BffSecurity:
    def __init__(self, settings: BffSettings) -> None:
        self.settings = settings
        self.cipher = MultiFernet([Fernet(key) for key in settings.token_encryption_keys])

    @staticmethod
    def new_secret() -> str:
        return secrets.token_urlsafe(32)

    @staticmethod
    def valid_secret(value: str | None) -> bool:
        return isinstance(value, str) and SECRET_PATTERN.fullmatch(value) is not None

    def session_digest(self, secret: str) -> str:
        return hmac.new(self.settings.session_hmac_key, b"session:" + secret.encode(), hashlib.sha256).hexdigest()

    def passkey_login_binding(self, secret: str) -> str:
        return hmac.new(self.settings.session_hmac_key, b"passkey-login:" + secret.encode(), hashlib.sha256).hexdigest()

    def csrf_token(self, secret: str, *, authenticated: bool) -> str:
        label = b"csrf-session:" if authenticated else b"csrf-anonymous:"
        return hmac.new(self.settings.session_hmac_key, label + secret.encode(), hashlib.sha256).hexdigest()

    def encrypt(self, value: str, *, context: str) -> bytes:
        return self.cipher.encrypt((context + "\x00" + value).encode())

    def decrypt(self, value: bytes, *, context: str) -> str:
        from cryptography.fernet import InvalidToken

        prefix, separator, token = self.cipher.decrypt(value).decode().partition("\x00")
        if not separator or not hmac.compare_digest(prefix, context):
            raise InvalidToken()
        return token
