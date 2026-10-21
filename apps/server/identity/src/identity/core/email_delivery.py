from html import escape
from importlib.resources import files
from string import Template
from typing import Literal, Protocol
from urllib.parse import quote, urlsplit

from email_delivery import EmailRequest, MailService
from pydantic import EmailStr, HttpUrl, TypeAdapter


class IdentityEmailDelivery(Protocol):
    async def __call__(
        self,
        *,
        email: str,
        purpose: Literal["verify_account", "password_reset", "mfa_email_otp"],
        token: str,
    ) -> None:
        """Deliver the token to this address using the configured trusted channel."""
        ...


class IdentityMailDelivery(IdentityEmailDelivery):
    def __init__(self, mail_service: MailService, *, fr: str, public_origin: str) -> None:
        self.mail_service = mail_service
        self.fr = TypeAdapter(EmailStr).validate_python(fr)
        origin = TypeAdapter(HttpUrl).validate_python(public_origin)
        if (origin.scheme != "https" or origin.username is not None or origin.password is not None
                or origin.path not in (None, "/") or origin.query is not None or origin.fragment is not None):
            raise ValueError("public_origin must be an HTTPS origin without credentials, path, query, or fragment")
        # Validate the literal input too: URL normalization must not discard a supplied path.
        if urlsplit(public_origin).path not in ("", "/"):
            raise ValueError("public_origin must not contain a path")
        self.public_origin = str(origin).rstrip("/")

    async def __call__(
        self,
        *,
        email: str,
        purpose: Literal["verify_account", "password_reset", "mfa_email_otp"],
        token: str,
    ) -> None:
        if purpose == "mfa_email_otp":
            await self.send_otp(email=email, code=token)
            return
        await self._send_template(email=email, purpose=purpose, token=token)

    async def send_otp(self, *, email: str, code: str) -> None:
        if not isinstance(code, str) or len(code) != 6 or not code.isascii() or not code.isdigit():
            raise ValueError("An email OTP must contain exactly six ASCII digits")
        await self._send_template(email=email, purpose="mfa_email_otp", token=code)

    async def _send_template(
        self,
        *,
        email: str,
        purpose: Literal["verify_account", "password_reset", "mfa_email_otp"],
        token: str,
    ) -> None:
        messages = {
            "verify_account": "Verify your email address",
            "password_reset": "Reset your password",
            "mfa_email_otp": "Your security verification code",
        }
        if purpose not in messages:
            raise ValueError("Unsupported identity email purpose")
        if not token:
            raise ValueError("An identity email token is required")
        template = Template(files("identity").joinpath("templates", "email", f"{purpose}.html").read_text(encoding="utf-8"))
        body = template.substitute(
            token=escape(token),
            verification_url=escape(f"{self.public_origin}/verify-email#token={quote(token, safe='')}"),
            reset_url=escape(f"{self.public_origin}/reset-password#token={quote(token, safe='')}"),
        )
        await self.mail_service.send_mail(
            EmailRequest(fr=self.fr, to=email, subject=messages[purpose], body=body, is_html=True)
        )
