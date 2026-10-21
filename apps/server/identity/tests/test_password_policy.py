import unittest

from pydantic import ValidationError

from identity.api.auth.schemas import PasswordChangeRequest, PasswordResetRequest, RegisterRequest


class PasswordPolicyChecks(unittest.TestCase):
    @staticmethod
    def requests(password):
        return (
            (RegisterRequest, {"email": "user@example.com", "username": "user", "password": password}, "password"),
            (PasswordChangeRequest, {"new_password": password}, "new_password"),
            (PasswordResetRequest, {"token": "synthetic-reset-token", "new_password": password}, "new_password"),
        )

    def test_accepts_eight_or_more_characters_without_composition_rules(self):
        for password in ("password", "12345678", "UPPERCASE", "        ", "with spaces", "😀" * 8, "x" * 200):
            for model, payload, field in self.requests(password):
                with self.subTest(model=model.__name__, length=len(password)):
                    request = model(**payload)
                    self.assertEqual(getattr(request, field).get_secret_value(), password)

    def test_rejects_passwords_shorter_than_eight_characters(self):
        for password in ("", "short", "1234567", "😀" * 7):
            for model, payload, _ in self.requests(password):
                with self.subTest(model=model.__name__, length=len(password)), self.assertRaises(ValidationError):
                    model(**payload)

    def test_preserves_whitespace_without_trimming_or_normalization(self):
        for whitespace in (" ", "\t", "\n", "\r", "\v", "\f", "\u00a0", "\u2003", "\u2028"):
            for password in (whitespace + "password", "pass" + whitespace + "word", "password" + whitespace):
                for model, payload, field in self.requests(password):
                    with self.subTest(model=model.__name__, password=password):
                        self.assertEqual(getattr(model(**payload), field).get_secret_value(), password)


if __name__ == "__main__":
    unittest.main()
