from abc import ABC, abstractmethod
from email.message import EmailMessage
from email.utils import formatdate, make_msgid

from .schemas import EmailRequest

class MailService(ABC):

    @abstractmethod
    async def send_mail(self, request: EmailRequest) -> None:
        """Submit the message for delivery, raising on transport failure."""

    @staticmethod
    def build_message(request: EmailRequest) -> EmailMessage:
        message = EmailMessage()
        message["From"] = str(request.fr)
        message["To"] = str(request.to)
        message["Subject"] = request.subject
        message["Date"] = formatdate(usegmt=True)
        message["Message-ID"] = make_msgid()
        message.set_content(request.body, subtype="html" if request.is_html else "plain", charset="utf-8")
        return message
