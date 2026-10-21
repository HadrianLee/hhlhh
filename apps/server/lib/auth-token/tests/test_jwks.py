"""Verify real JWT signatures against a disposable HTTP JWKS server."""
from datetime import UTC, datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import ssl
import sys
from threading import Thread
from typing import Annotated, Any
import unittest
from unittest.mock import patch
from uuid import uuid4

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / 'src'))
os.environ.update(
    JWT_ISSUER='https://identity.test', JWT_AUDIENCE='apps',
    JWKS_URL='https://identity.test/.well-known/jwks.json', JWT_CLOCK_SKEW_SECONDS='5',
)

from cryptography.hazmat.primitives.asymmetric import rsa
from fastapi import APIRouter, Depends, FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from fastapi.testclient import TestClient
import jwt

from auth_token import dependencies
from auth_token.exceptions import AuthError, InvalidTokenError, TokenExpiredError


class JwksChecks(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.private_keys = [rsa.generate_private_key(public_exponent=65537, key_size=2048) for _ in range(2)]
        cls.public_keys = [{**jwt.algorithms.RSAAlgorithm.to_jwk(key.public_key(), as_dict=True),
                            'kid': f'key-{index}', 'alg': 'RS256', 'use': 'sig'}
                           for index, key in enumerate(cls.private_keys)]

        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                cls.requests.append(self.path)
                self.send_response(cls.status)
                self.send_header('Content-Type', 'application/jwk-set+json')
                self.end_headers()
                self.wfile.write(cls.body)

            def log_message(self, *_):
                pass

        cls.server = ThreadingHTTPServer(('127.0.0.1', 0), Handler)
        cls.server_thread = Thread(target=cls.server.serve_forever, daemon=True)
        cls.server_thread.start()

    @classmethod
    def tearDownClass(cls):
        cls.server.shutdown()
        cls.server.server_close()
        cls.server_thread.join()

    def setUp(self):
        type(self).requests = []
        type(self).status = 200
        self.publish([self.public_keys[0]])
        self.client = jwt.PyJWKClient(f'http://127.0.0.1:{self.server.server_port}/jwks', timeout=2,
            ssl_context=ssl.create_default_context())
        client_patch = patch.object(dependencies, 'jwks_client', self.client)
        client_patch.start()
        self.addCleanup(client_patch.stop)

    def publish(self, keys):
        type(self).body = json.dumps({'keys': keys}).encode()

    def token(self, changes=None, *, headers=None, key_index=0, omit=()):
        now = int(datetime.now(UTC).timestamp())
        payload = {
            'iss': 'https://identity.test', 'aud': 'apps', 'sub': str(uuid4()),
            'iat': now, 'nbf': now, 'exp': now + 600, 'jti': uuid4().hex,
            **(changes or {}),
        }
        for claim in omit:
            payload.pop(claim)
        header = {'kid': f'key-{key_index}', 'typ': 'JWT', **(headers or {})}
        if header.get('kid') is None:
            header.pop('kid')
        return jwt.encode(payload, self.private_keys[key_index], algorithm='RS256',
            headers=header)

    def test_valid_identity_token_needs_no_roles_or_permissions(self):
        token = self.token()
        claims = dependencies.decode_jwt(token)
        self.assertNotIn('permissions', claims)
        self.assertNotIn('roles', claims)
        self.assertNotIn('sid', claims)
        self.assertEqual(claims, dependencies.decode_jwt(token))
        self.assertEqual(self.requests, ['/jwks'])

    def test_new_kid_refreshes_cached_jwks(self):
        dependencies.decode_jwt(self.token())
        self.publish(self.public_keys)
        dependencies.decode_jwt(self.token(key_index=1))
        self.assertEqual(self.requests, ['/jwks', '/jwks'])

    def test_removed_key_is_rejected_after_jwks_refresh(self):
        token = self.token()
        dependencies.decode_jwt(token)
        self.publish([self.public_keys[1]])
        self.client.get_jwk_set(refresh=True)
        with self.assertRaises(InvalidTokenError):
            dependencies.decode_jwt(token)

    def test_wrong_signature_and_unknown_kid_are_rejected(self):
        for token in (self.token(key_index=1, headers={'kid': 'key-0'}), self.token(headers={'kid': 'unknown'})):
            with self.subTest(token=jwt.get_unverified_header(token)):
                with self.assertRaises(InvalidTokenError):
                    dependencies.decode_jwt(token)

    def test_missing_required_claims_are_rejected(self):
        for claim in ('iss', 'aud', 'sub', 'iat', 'nbf', 'exp', 'jti'):
            with self.subTest(claim=claim), self.assertRaises(InvalidTokenError):
                dependencies.decode_jwt(self.token(omit=(claim,)))

    def test_wrong_issuer_audience_or_claim_types_are_rejected(self):
        for changes in ({'iss': 'other'}, {'aud': 'other'}, {'sub': 123}, {'jti': 123}, {'sub': ''},
                        {'jti': ''}, {'iat': {}}, {'nbf': []}, {'exp': {}}, {'exp': float('inf')}):
            with self.subTest(changes=changes), self.assertRaises(InvalidTokenError):
                dependencies.decode_jwt(self.token(changes))

    def test_expiry_and_clock_allowance(self):
        now = int(datetime.now(UTC).timestamp())
        with self.assertRaises(TokenExpiredError):
            dependencies.decode_jwt(self.token({'exp': now - 60}))
        dependencies.decode_jwt(self.token({'iat': now + 2, 'nbf': now + 2}))
        with self.assertRaises(InvalidTokenError):
            dependencies.decode_jwt(self.token({'iat': now + 60, 'nbf': now + 60}))

    def test_untrusted_algorithms_and_headers_are_rejected_before_fetch(self):
        for algorithm in ('none', 'HS256'):
            token = jwt.encode({'sub': 'user'}, '' if algorithm == 'none' else 'test-only-secret-at-least-32-bytes',
                algorithm=algorithm, headers={'kid': 'key-0', 'typ': 'JWT'})
            with self.subTest(algorithm=algorithm), self.assertRaises(InvalidTokenError):
                dependencies.decode_jwt(token)
        for header in ({'kid': None}, {'kid': ''}, {'typ': 'other'}, {'crit': ['custom']}):
            with self.subTest(header=header), self.assertRaises(InvalidTokenError):
                dependencies.decode_jwt(self.token(headers=header))
        self.assertEqual(self.requests, [])

    def test_token_key_urls_do_not_override_configured_jwks(self):
        claims = dependencies.decode_jwt(self.token(headers={
            'jku': 'https://untrusted.invalid/keys', 'jwk': self.public_keys[1],
        }))
        self.assertIn('sub', claims)
        self.assertEqual(self.requests, ['/jwks'])

    def test_jwks_outage_and_invalid_json_return_503(self):
        for status, body in ((503, b'unavailable'), (200, b'invalid json'), (200, b'{"keys": []}')):
            type(self).status, type(self).body = status, body
            with self.subTest(status=status, body=body), self.assertRaises(HTTPException) as error:
                dependencies.decode_jwt(self.token())
            self.assertEqual(error.exception.status_code, 503)

    def test_endpoint_and_router_protection(self):
        app = FastAPI()

        @app.exception_handler(AuthError)
        async def handle_auth_error(request: Request, exc: AuthError):
            return JSONResponse(status_code=exc.status_code, content=exc.to_dict(),
                headers={'WWW-Authenticate': 'Bearer'} if exc.status_code == 401 else {})

        @app.get('/me')
        def me(payload: Annotated[dict[str, Any], Depends(dependencies.verify_jwt)]):
            return {'user_id': payload['sub']}

        private = APIRouter(prefix='/private', dependencies=[Depends(dependencies.verify_jwt)])

        @private.get('/data')
        def data():
            return {'ok': True}

        app.include_router(private)
        with TestClient(app) as client:
            for path in ('/me', '/private/data'):
                self.assertEqual(client.get(path).status_code, 401)
                self.assertEqual(client.get(path, headers={'Authorization': 'Bearer invalid'}).status_code, 401)
                response = client.get(path, headers={'Authorization': f'Bearer {self.token()}'})
                self.assertEqual(response.status_code, 200, response.text)


if __name__ == '__main__':
    unittest.main(verbosity=2)
