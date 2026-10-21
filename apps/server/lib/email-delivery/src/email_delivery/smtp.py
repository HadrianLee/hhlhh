import math

import aiosmtplib

from .base import MailService
from .schemas import EmailRequest


class SmtpMailService(MailService):
    def __init__(self, *, hostname: str = "localhost", port: int = 1025,
                 username: str | None = None, password: str | None = None,
                 use_tls: bool = False, start_tls: bool = False, timeout: float = 10) -> None:
        if not hostname.strip() or any(character in hostname for character in ("\r", "\n", "\x00")):
            raise ValueError("A valid SMTP hostname is required")
        if not 1 <= port <= 65535:
            raise ValueError("SMTP port must be between 1 and 65535")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("SMTP timeout must be positive and finite")
        if use_tls and start_tls:
            raise ValueError("Select implicit TLS or STARTTLS, not both")
        if (username is None) != (password is None):
            raise ValueError("Provide both SMTP username and password")
        if username is not None and not (use_tls or start_tls):
            raise ValueError("SMTP authentication requires TLS")
        self.hostname = hostname
        self.port = port
        self.username = username
        self.password = password
        self.use_tls = use_tls
        self.start_tls = start_tls
        self.timeout = timeout

    async def send_mail(self, request: EmailRequest) -> None:
        message = self.build_message(request)
        await aiosmtplib.send(message, sender=str(request.fr), recipients=[str(request.to)],
            hostname=self.hostname, port=self.port, username=self.username, password=self.password,
            use_tls=self.use_tls, start_tls=self.start_tls, validate_certs=True, timeout=self.timeout)
