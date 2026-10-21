import resend

from .base import MailService
from .schemas import EmailRequest


class ResendMailService(MailService):
    async def send_mail(self, request: EmailRequest) -> None:
        # Resend's SDK uses process-wide configuration. Set its API key once at
        # application startup; do not change credentials while sending requests.
        if not resend.api_key or not resend.api_key.strip():
            raise ValueError("Configure RESEND_API_KEY before using ResendMailService")
        message = self.build_message(request)
        params: resend.Emails.SendParams = {
            "from": str(message["From"]),
            "to": [str(message["To"])],
            "subject": str(message["Subject"]),
        }
        if message.get_content_subtype() == "html":
            params["html"] = message.get_content()
        else:
            params["text"] = message.get_content()
        await resend.Emails.send_async(params)
