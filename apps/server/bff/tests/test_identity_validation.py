import unittest

import httpx

from bff.core.identity import IdentityClient
from bff.exceptions import BffError


class IdentityValidationChecks(unittest.TestCase):
    def test_validation_feedback_uses_safe_labels_and_never_reflects_input(self):
        private = "synthetic-private-password"
        response = httpx.Response(422, json={"detail": [
            {"type": "too_short", "loc": ["body", "password"], "input": private, "msg": private},
            {"type": "value_error", "loc": ["body", "email"], "input": private, "ctx": {"error": private}},
            {"type": "extra_forbidden", "loc": ["body", private], "input": private},
        ]})
        with self.assertRaises(BffError) as caught:
            IdentityClient.require_success(response)
        self.assertEqual(caught.exception.status_code, 422)
        self.assertIn("Password must contain at least 8 characters.", caught.exception.detail)
        self.assertIn("Email address is invalid.", caught.exception.detail)
        self.assertNotIn(private, caught.exception.detail)

    def test_unknown_validation_shapes_use_generic_feedback(self):
        for error in (None, {"loc": ["body", 5]}, {"loc": None}, {"type": [], "loc": ["body", "username"]}):
            with self.subTest(error=error), self.assertRaises(BffError) as caught:
                IdentityClient.require_success(httpx.Response(422, json={"detail": [error]}))
            self.assertEqual(caught.exception.status_code, 422)
