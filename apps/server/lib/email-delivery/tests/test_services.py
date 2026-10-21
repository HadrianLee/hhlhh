import inspect
from email.message import EmailMessage
from unittest import IsolatedAsyncioTestCase, main
from unittest.mock import AsyncMock, patch

from aiosmtplib.errors import SMTPException
from pydantic import ValidationError

from email_delivery import EmailRequest, MailService, ResendMailService, SmtpMailService


class MailServiceChecks(IsolatedAsyncioTestCase):
    def setUp(self):
        self.request = EmailRequest(fr="sender@example.com", to="recipient@example.com",
                                    subject="Verification code ✓", body="Your code is 123456.\n")
        key = patch("email_delivery.resend.resend.api_key", "re_test_only_not_a_real_key")
        key.start()
        self.addCleanup(key.stop)

    def test_base_requires_an_async_send_implementation(self):
        with self.assertRaises(TypeError):
            MailService()
        for service in (SmtpMailService, ResendMailService):
            self.assertTrue(issubclass(service, MailService))
            self.assertTrue(inspect.iscoroutinefunction(service.send_mail))

    def test_shared_builder_creates_plain_or_html_mime(self):
        for is_html, content_type in ((False, "text/plain"), (True, "text/html")):
            with self.subTest(is_html=is_html):
                request = self.request.model_copy(update={"is_html": is_html})
                message = MailService.build_message(request)
                self.assertIsInstance(message, EmailMessage)
                self.assertEqual(message.get_content_type(), content_type)
                self.assertEqual(message.get_content_charset(), "utf-8")
                self.assertEqual(message.get_content(), request.body)
                self.assertEqual(str(message["From"]), request.fr)
                self.assertEqual(str(message["To"]), request.to)
                self.assertEqual(str(message["Subject"]), request.subject)
                self.assertIsNotNone(message["Date"])
                self.assertIsNotNone(message["Message-ID"])

    async def test_smtp_submits_email_message_and_explicit_envelope(self):
        with patch("email_delivery.smtp.aiosmtplib.send", new_callable=AsyncMock) as send:
            send.return_value = ({}, "accepted")
            result = await SmtpMailService().send_mail(self.request)
        self.assertIsNone(result)
        message = send.await_args.args[0]
        self.assertIsInstance(message, EmailMessage)
        self.assertEqual(message.get_content(), self.request.body)
        self.assertEqual(send.await_args.kwargs, {
            "sender": self.request.fr, "recipients": [self.request.to], "hostname": "localhost", "port": 1025,
            "username": None, "password": None, "use_tls": False, "start_tls": False,
            "validate_certs": True, "timeout": 10,
        })

    async def test_smtp_preserves_html_and_configured_tls(self):
        request = self.request.model_copy(update={"body": "<p>Hello ✓</p>\n", "is_html": True})
        service = SmtpMailService(hostname="smtp.example.com", port=587, start_tls=True,
                                  username="test-user", password="test-password", timeout=5)
        with patch("email_delivery.smtp.aiosmtplib.send", new_callable=AsyncMock) as send:
            await service.send_mail(request)
        message = send.await_args.args[0]
        self.assertEqual(message.get_content_type(), "text/html")
        self.assertEqual(message.get_content(), request.body)
        self.assertTrue(send.await_args.kwargs["start_tls"])
        self.assertTrue(send.await_args.kwargs["validate_certs"])

    async def test_smtp_failure_propagates(self):
        with patch("email_delivery.smtp.aiosmtplib.send", new_callable=AsyncMock,
                   side_effect=SMTPException("synthetic failure")):
            with self.assertRaises(SMTPException):
                await SmtpMailService().send_mail(self.request)

    async def test_resend_maps_mime_plain_text_to_api_fields(self):
        with patch("email_delivery.resend.resend.Emails.send_async", new_callable=AsyncMock) as send:
            send.return_value = {"id": "test-email"}
            result = await ResendMailService().send_mail(self.request)
        self.assertIsNone(result)
        send.assert_awaited_once_with({
            "from": self.request.fr, "to": [self.request.to], "subject": self.request.subject,
            "text": self.request.body,
        })

    async def test_resend_maps_decoded_html_without_sending_raw_mime(self):
        request = self.request.model_copy(update={"body": "<p>Hello ✓</p>\n", "is_html": True})
        with patch("email_delivery.resend.resend.Emails.send_async", new_callable=AsyncMock) as send:
            await ResendMailService().send_mail(request)
        params = send.await_args.args[0]
        self.assertEqual(params["html"], request.body)
        self.assertNotIn("text", params)
        self.assertNotIn("Content-Type:", params["html"])

    async def test_resend_sdk_uses_its_async_transport(self):
        import resend

        client = AsyncMock(spec=resend.AsyncHTTPClient)
        client.request.return_value = (b'{"id":"test-email"}', 200, {"content-type": "application/json"})
        with patch("email_delivery.resend.resend.default_async_http_client", client), \
             patch("email_delivery.resend.resend.api_url", "https://api.resend.com"):
            await ResendMailService().send_mail(self.request)
        client.request.assert_awaited_once()
        kwargs = client.request.await_args.kwargs
        self.assertEqual(kwargs["url"], "https://api.resend.com/emails")
        self.assertEqual(kwargs["method"], "post")
        self.assertEqual(kwargs["headers"]["Authorization"], "Bearer re_test_only_not_a_real_key")
        self.assertEqual(kwargs["json"]["text"], self.request.body)

    async def test_resend_requires_a_configured_key_before_network_io(self):
        with patch("email_delivery.resend.resend.api_key", None), \
             patch("email_delivery.resend.resend.Emails.send_async", new_callable=AsyncMock) as send:
            with self.assertRaises(ValueError):
                await ResendMailService().send_mail(self.request)
            send.assert_not_awaited()

    async def test_resend_failure_propagates(self):
        from resend.exceptions import ResendError

        failure = ResendError(code=429, message="synthetic failure", error_type="rate_limit_exceeded",
                              suggested_action="Retry later")
        with patch("email_delivery.resend.resend.Emails.send_async", new_callable=AsyncMock, side_effect=failure):
            with self.assertRaises(ResendError):
                await ResendMailService().send_mail(self.request)

    def test_header_injection_and_invalid_addresses_are_rejected(self):
        fields = self.request.model_dump()
        for subject in ("Hello\rBcc: hidden@example.com", "Hello\nBcc: hidden@example.com", "Hello\x00"):
            with self.subTest(subject=subject), self.assertRaises(ValidationError):
                EmailRequest(**{**fields, "subject": subject})
        for address in ("not-an-email", "valid@example.com\r\nBcc: hidden@example.com"):
            with self.subTest(address=address), self.assertRaises(ValidationError):
                EmailRequest(**{**fields, "to": address})

    def test_invalid_smtp_settings_are_rejected(self):
        for kwargs in (
            {"hostname": ""}, {"port": 0}, {"port": 65536}, {"timeout": 0}, {"timeout": float("inf")},
            {"use_tls": True, "start_tls": True}, {"username": "user"},
            {"username": "user", "password": "secret"},
        ):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                SmtpMailService(**kwargs)


if __name__ == "__main__":
    main()
