from dataclasses import dataclass
import ipaddress
import os
from urllib.parse import urlsplit


CHALLENGE_TTL_SECONDS = 300
MFA_TTL_SECONDS = 300


class ChallengeError(Exception):
    def __init__(self, status_code: int, detail: str, *, retry_after: int | None = None):
        self.status_code = status_code
        self.detail = detail
        self.headers = {"Retry-After": str(retry_after)} if retry_after is not None else {}
        if status_code == 401:
            self.headers["WWW-Authenticate"] = "Bearer"
        super().__init__(detail)


@dataclass(frozen=True)
class PasskeySettings:
    rp_id: str
    rp_name: str
    origin: str

    @classmethod
    def from_env(cls):
        rp_id = os.environ.get("WEBAUTHN_RP_ID", "")
        rp_name = os.environ.get("WEBAUTHN_RP_NAME", "Identity")
        origin = os.environ.get("WEBAUTHN_ORIGIN", "")
        try:
            parsed = urlsplit(origin)
            host = parsed.hostname or ""
            port = parsed.port
        except ValueError as exc:
            raise ChallengeError(503, "Passkey relying-party configuration is unavailable") from exc
        try:
            ipaddress.ip_address(rp_id)
        except ValueError:
            pass
        else:
            raise ChallengeError(503, "Passkey relying-party configuration is unavailable")
        valid = (
            bool(rp_id and rp_name and origin) and len(rp_id) <= 253 and len(origin) <= 2048
            and ("." in rp_id or rp_id == "localhost")
            and rp_id == rp_id.lower() and all(label and len(label) <= 63
                and label[0].isalnum() and label[-1].isalnum()
                and all(char.isascii() and (char.isalnum() or char == "-") for char in label)
                for label in rp_id.split("."))
            and (host == rp_id or host.endswith("." + rp_id))
            and (parsed.scheme == "https" or (parsed.scheme == "http" and host == rp_id == "localhost"))
            and parsed.username is None and parsed.password is None and not parsed.path
            and not parsed.query and not parsed.fragment and port != 0
        )
        if not valid:
            raise ChallengeError(503, "Passkey relying-party configuration is unavailable")
        default_port = 443 if parsed.scheme == "https" else 80
        origin = f"{parsed.scheme}://{host}" + (f":{port}" if port and port != default_port else "")
        return cls(rp_id, rp_name, origin)
