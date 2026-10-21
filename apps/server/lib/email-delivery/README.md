# Email delivery

This shared library turns one validated message contract into SMTP or Resend
delivery. The calling application owns templates, verification links, and codes;
changing the transport does not change those account rules.

All commands run from the repository root. Install the locked workspace first:

```bash
uv sync --frozen --directory apps/server --all-packages
```

## Common contract

Both transports implement the same asynchronous contract:

```python
from email_delivery import EmailRequest, MailService

async def deliver(service: MailService, request: EmailRequest) -> None:
    await service.send_mail(request)
```

`MailService` is an ABC: subclasses must implement `async send_mail`.
Its shared `build_message` method constructs a standard-library `EmailMessage`
with From, To, Subject, Date, Message-ID, UTF-8 content, and the correct MIME type.
`EmailRequest` retains `fr`, `to`, `subject`, `body`, and `is_html`.
Addresses are validated, and subjects reject line breaks and null characters.

## SMTP / Mailpit

```python
from email_delivery import EmailRequest, SmtpMailService

service = SmtpMailService(hostname="mailpit", port=1025)
request = EmailRequest(
    fr="identity@example.com",
    to="user@example.com",
    subject="Your verification code",
    body="Your verification code is 123456.",
)
await service.send_mail(request)
```

Use hostname `mailpit` when both containers share a Docker network. Use
`localhost` when an SMTP server's port 1025 is published to the host. The default
constructor uses `localhost:1025`, no authentication, and no TLS, matching local Mailpit.
The MIME message is passed directly to `aiosmtplib.send` with an explicit
sender/recipient envelope. Each call opens and closes its own SMTP connection.

The local Compose overlay exposes only the Mailpit web inbox at
`http://localhost:8025`; Identity reaches SMTP internally at `mailpit:1025`.
The Python snippets with `await` belong inside an async function or an async
application lifespan/request handler.

For authenticated SMTP, explicitly select TLS:

```python
import os

service = SmtpMailService(
    hostname=os.environ["SMTP_HOST"],
    port=587,
    username=os.environ["SMTP_USERNAME"],
    password=os.environ["SMTP_PASSWORD"],
    start_tls=True,
)
```

For implicit TLS, use `use_tls=True` and the server's corresponding port.
TLS certificate verification stays enabled. Authentication without TLS and
selecting both TLS modes are rejected. The default connection timeout is 10 seconds.

## Resend

Configure the SDK's process-wide key once at application startup:

```python
import os
import resend
from email_delivery import ResendMailService

resend.api_key = os.environ["RESEND_API_KEY"]
service = ResendMailService()
await service.send_mail(request)
```

The SDK also reads `RESEND_API_KEY` when imported. Avoid changing its key while
requests are in flight. The sender must be allowed by your Resend account/domain.

This implementation constructs the same `EmailMessage`, then maps From, To,
Subject, and its decoded MIME body into Resend's JSON fields. Plain text uses
`text`; HTML uses `html`. Resend assigns delivery metadata such as its message ID.
Sending uses `resend.Emails.send_async`; the package declares `resend[async]`
so HTTPX is installed even when this library is installed outside the workspace.

Set `is_html=True` to send an HTML body through either transport. Email content
and templates remain the caller's responsibility. Delivery is explicit: importing
or constructing a service does not send email. `send_mail` returns `None` after
the SMTP server/provider accepts the request. Provider errors propagate, and the
library performs no automatic retries.

Identity uses this library through its injectable delivery hook. It currently
selects SMTP at startup; choosing Resend would require wiring that transport
there. Identity retains ownership of token creation, OTPs, purpose, and HTML
templates. See [Identity's email flow](../../identity/README.md#email-links-and-codes).

## Tests

From the repository root:

```sh
uv run --frozen --directory apps/server --package email-delivery python -B -m unittest discover -s lib/email-delivery/tests -v
```

The automated tests mock SMTP and Resend I/O; they do not send external email.
