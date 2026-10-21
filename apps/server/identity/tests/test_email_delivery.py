import importlib
import os
from pathlib import Path
from tempfile import TemporaryDirectory
import unittest
from unittest.mock import AsyncMock, Mock, patch

from email_delivery import EmailRequest, MailService, SmtpMailService
from fastapi import FastAPI

from identity.core.email_delivery import IdentityMailDelivery


class RecordingMailService(MailService):
    def __init__(self):
        self.messages: list[EmailRequest] = []

    async def send_mail(self, request: EmailRequest) -> None:
        self.messages.append(request)


class IdentityEmailDeliveryChecks(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.mail_service = RecordingMailService()
        self.delivery = IdentityMailDelivery(self.mail_service, fr="identity@example.com", public_origin="https://frontend.example.com")

    async def test_formats_all_identity_purposes_without_changing_tokens(self):
        for purpose, token, subject in (
            ("verify_account", "primary.verification-token", "Verify your email address"),
            ("verify_account", "00000000-0000-0000-0000-000000000001.secondary-token", "Verify your email address"),
            ("password_reset", "password-reset-token", "Reset your password"),
            ("mfa_email_otp", "000123", "Your security verification code"),
        ):
            with self.subTest(purpose=purpose, token=token):
                await self.delivery(email="user@example.com", purpose=purpose, token=token)
                request = self.mail_service.messages[-1]
                self.assertEqual(request.fr, "identity@example.com")
                self.assertEqual(request.to, "user@example.com")
                self.assertEqual(request.subject, subject)
                if purpose == "mfa_email_otp":
                    self.assertIn(f"<code>{token}</code>", request.body)
                else:
                    path = "verify-email" if purpose == "verify_account" else "reset-password"
                    self.assertIn(f'href="https://frontend.example.com/{path}#token={token}"', request.body)
                    self.assertNotIn("<code>", request.body)
                    self.assertNotIn("paste", request.body.lower())
                self.assertTrue(request.is_html)
                self.assertNotIn("${token}", request.body)

    async def test_token_markup_is_escaped_in_html(self):
        token = '<script>alert("unsafe")</script>&'
        await self.delivery(email="user@example.com", purpose="password_reset", token=token)
        body = self.mail_service.messages[-1].body
        self.assertNotIn("<script>", body)
        self.assertIn("%3Cscript%3Ealert%28%22unsafe%22%29%3C%2Fscript%3E%26", body)

    async def test_links_use_the_configured_origin_and_fragment_tokens(self):
        for purpose, path in (("verify_account", "verify-email"), ("password_reset", "reset-password")):
            with self.subTest(purpose=purpose):
                await self.delivery(email="user@example.com", purpose=purpose, token="primary.a+b&c#d")
                body = self.mail_service.messages[-1].body
                self.assertIn(f'href="https://frontend.example.com/{path}#token=primary.a%2Bb%26c%23d"', body)
                self.assertNotIn("?token=", body)

    def test_public_origin_rejects_unsafe_or_non_origin_urls(self):
        for origin in ("", "http://frontend.example.com", "javascript:alert(1)",
                       "https://user:password@frontend.example.com", "https://frontend.example.com/path",
                       "https://frontend.example.com?redirect=elsewhere", "https://frontend.example.com#fragment"):
            with self.subTest(origin=origin), self.assertRaises(ValueError):
                IdentityMailDelivery(self.mail_service, fr="identity@example.com", public_origin=origin)

    async def test_template_is_loaded_and_rendered_when_sending(self):
        with TemporaryDirectory() as directory:
            root = Path(directory)
            template = root / "templates/email/verify_account.html"
            template.parent.mkdir(parents=True)
            template.write_text("<p>First: ${token}</p>", encoding="utf-8")
            with patch("identity.core.email_delivery.files", return_value=root):
                await self.delivery(email="user@example.com", purpose="verify_account", token="one&two")
                self.assertEqual(self.mail_service.messages[-1].body, "<p>First: one&amp;two</p>")
                template.write_text("<p>Updated: ${token}</p>", encoding="utf-8")
                await self.delivery(email="user@example.com", purpose="verify_account", token="three")
                self.assertEqual(self.mail_service.messages[-1].body, "<p>Updated: three</p>")

    async def test_send_otp_preserves_leading_zeroes(self):
        await self.delivery.send_otp(email="user@example.com", code="000123")
        request = self.mail_service.messages[-1]
        self.assertIn("<code>000123</code>", request.body)
        self.assertEqual(request.subject, "Your security verification code")
        self.assertTrue(request.is_html)

    async def test_send_otp_rejects_invalid_codes_without_sending(self):
        for code in ("", "12345", "1234567", "12345a", "１２３４５６", 123456):
            with self.subTest(code=code), self.assertRaises(ValueError):
                await self.delivery.send_otp(email="user@example.com", code=code)
        self.assertEqual(self.mail_service.messages, [])

    async def test_unsupported_purpose_and_empty_token_do_not_send(self):
        with self.assertRaises(ValueError):
            await self.delivery(email="user@example.com", purpose="unsupported", token="secret")
        with self.assertRaises(ValueError):
            await self.delivery(email="user@example.com", purpose="mfa_email_otp", token="")
        self.assertEqual(self.mail_service.messages, [])

    async def test_invalid_recipient_does_not_send(self):
        with self.assertRaises(ValueError):
            await self.delivery(email="invalid", purpose="password_reset", token="secret")
        self.assertEqual(self.mail_service.messages, [])

    def test_sender_is_validated_at_initialization(self):
        with self.assertRaises(ValueError):
            IdentityMailDelivery(self.mail_service, fr="invalid", public_origin="https://frontend.example.com")
        self.assertEqual(self.mail_service.messages, [])

    async def test_transport_failure_is_propagated(self):
        service = Mock(spec=MailService)
        service.send_mail = AsyncMock(side_effect=RuntimeError("synthetic transport failure"))
        delivery = IdentityMailDelivery(service, fr="identity@example.com", public_origin="https://frontend.example.com")
        with self.assertRaises(RuntimeError):
            await delivery(email="user@example.com", purpose="password_reset", token="secret")


class IdentityDeliveryLifespanChecks(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.environment = patch.dict(os.environ, {
            "JWT_ACCESS_TOKEN_TTL_SECONDS": "600", "JWT_KEY_ROTATION_INTERVAL_SECONDS": "3600",
            "JWT_ISSUER": "https://identity.test", "JWT_AUDIENCE": "apps",
            "JWKS_URL": "https://identity.test/.well-known/jwks.json", "JWT_CLOCK_SKEW_SECONDS": "5",
            "IDENTITY_TOKEN_HMAC_KEY": "test-only-key-not-for-production-0123456789",
            "SMTP_HOST": "mailpit.test", "SMTP_PORT": "2525", "IDENTITY_EMAIL_FROM": "configured@example.com",
            "BFF_PUBLIC_ORIGIN": "https://frontend.example.com",
        })
        self.environment.start()
        self.addCleanup(self.environment.stop)
        self.main = importlib.import_module("identity.main")
        self.manager = Mock()
        self.manager.rotate = AsyncMock()

    async def test_lifespan_installs_smtp_and_cleans_up_its_hook(self):
        app = FastAPI()
        with patch.object(self.main, "Database"), \
             patch.object(self.main, "KeyManager", return_value=self.manager), \
             patch("email_delivery.smtp.aiosmtplib.send", new_callable=AsyncMock) as send:
            async with self.main.lifespan(app):
                delivery = app.state.identity_email_delivery
                self.assertIsInstance(delivery, IdentityMailDelivery)
                self.assertIsInstance(delivery.mail_service, SmtpMailService)
                self.assertEqual(delivery.mail_service.hostname, "mailpit.test")
                self.assertEqual(delivery.mail_service.port, 2525)
                self.assertEqual(delivery.fr, "configured@example.com")
                send.assert_not_awaited()
                await delivery(email="user@example.com", purpose="mfa_email_otp", token="000123")
                self.assertIn("000123", send.await_args.args[0].get_content())
                self.assertEqual(send.await_args.args[0].get_content_type(), "text/html")
                self.assertEqual(str(send.await_args.args[0]["From"]), "configured@example.com")
            self.assertFalse(hasattr(app.state, "identity_email_delivery"))
            self.manager.rotate.assert_awaited_once()

    async def test_lifespan_requires_all_smtp_settings_before_database_startup(self):
        for setting in ("SMTP_HOST", "SMTP_PORT", "IDENTITY_EMAIL_FROM", "BFF_PUBLIC_ORIGIN"):
            for value in (None, "", "   "):
                with self.subTest(setting=setting, value=value), patch.dict(os.environ), \
                     patch.object(self.main, "Database") as database:
                    if value is None:
                        os.environ.pop(setting, None)
                    else:
                        os.environ[setting] = value
                    app = FastAPI()
                    with self.assertRaisesRegex(RuntimeError, setting):
                        async with self.main.lifespan(app):
                            self.fail("Startup must reject missing SMTP configuration")
                    database.assert_not_called()
                    self.assertFalse(hasattr(app.state, "identity_email_delivery"))

    async def test_lifespan_rejects_invalid_smtp_settings_as_runtime_errors(self):
        for setting, value in (
            ("SMTP_HOST", "mailpit\r\n"), ("SMTP_PORT", "not-a-port"),
            ("SMTP_PORT", "0"), ("SMTP_PORT", "65536"), ("IDENTITY_EMAIL_FROM", "invalid"),
            ("BFF_PUBLIC_ORIGIN", "http://frontend.example.com"), ("BFF_PUBLIC_ORIGIN", "https://frontend.example.com/extra"),
        ):
            with self.subTest(setting=setting, value=value), patch.dict(os.environ, {setting: value}), \
                 patch.object(self.main, "Database") as database:
                with self.assertRaisesRegex(RuntimeError, "Invalid identity email delivery configuration"):
                    async with self.main.lifespan(FastAPI()):
                        self.fail("Startup must reject invalid SMTP configuration")
                database.assert_not_called()

    async def test_lifespan_allows_a_delivery_hook_after_startup_and_cleans_it_up(self):
        app = FastAPI()
        hook = AsyncMock()
        with patch.object(self.main, "Database"), \
             patch.object(self.main, "KeyManager", return_value=self.manager):
            async with self.main.lifespan(app):
                self.assertIsInstance(app.state.identity_email_delivery, IdentityMailDelivery)
                app.state.identity_email_delivery = hook
                self.assertIs(app.state.identity_email_delivery, hook)
                await app.state.identity_email_delivery(email="user@example.com", purpose="mfa_email_otp", token="000123")
            self.assertFalse(hasattr(app.state, "identity_email_delivery"))
        hook.assert_awaited_once_with(email="user@example.com", purpose="mfa_email_otp", token="000123")


if __name__ == "__main__":
    unittest.main()
