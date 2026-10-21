"""API checks using real AsyncSession transactions and a local SQLite test driver."""
import asyncio
import importlib
import hashlib
from io import BytesIO
import json
import os
import secrets
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from uuid import UUID, uuid4
from datetime import UTC, datetime, timedelta

ROOT = Path(__file__).resolve().parents[2]
sys.path[:0] = [str(ROOT / 'identity/src'), str(ROOT / 'lib/auth-token/src'), str(ROOT / 'lib/authz-helper/src')]
os.environ.update(
    JWT_ACCESS_TOKEN_TTL_SECONDS='600', JWT_KEY_ROTATION_INTERVAL_SECONDS='3600',
    JWT_ISSUER='https://identity.test', JWT_AUDIENCE='apps',
    JWKS_URL='https://identity.test/.well-known/jwks.json',
    JWT_CLOCK_SKEW_SECONDS='5',
    IDENTITY_TOKEN_HMAC_KEY='test-only-key-not-for-production-0123456789',
    SMTP_HOST='mailpit.test', SMTP_PORT='2525', IDENTITY_EMAIL_FROM='identity@example.com',
    BFF_PUBLIC_ORIGIN='https://frontend.example.com',
)

import httpx
import jwt
import cbor2
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy import create_engine, event, select, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session

from identity.core.security import _hash_password
from identity.db.models.identity import AuthToken, Permission, Role, RolePermission, User, UserRole, UserSession
from identity.db.services.base import Database
from identity.db.services.identity import IdentityDbService
from auth_token import dependencies as auth_dependencies
from identity.db.models.challenge import AuthChallenge, ChallengePurpose, Passkey, PasskeyLoginChallenge
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url

main = importlib.import_module('identity.main')
PASSWORD = 'a sufficiently long password'
NEW_PASSWORD = 'DifferentSecurePassword456!'
ADMIN_ACTIONS = (
    'identity.users.read', 'identity.users.manage', 'identity.roles.read', 'identity.roles.manage',
    'identity.permissions.read', 'identity.permissions.manage', 'identity.audit.read',
)


class ApiChecks(unittest.IsolatedAsyncioTestCase):
    @classmethod
    def setUpClass(cls):
        cls.password_hash = _hash_password(PASSWORD, b'0123456789abcdef')

    async def asyncSetUp(self):
        test_url = os.environ.get('IDENTITY_TEST_DATABASE_URL')
        self.async_engine = None
        if test_url:
            url = make_url(test_url)
            if url.database != 'identity_api_test' or url.host not in {'127.0.0.1', 'localhost'}:
                raise ValueError('PostgreSQL tests require a disposable local identity_api_test database')
            self.async_engine = create_async_engine(url)
            async with self.async_engine.begin() as connection:
                await connection.execute(text('CREATE SCHEMA IF NOT EXISTS identity'))
                await connection.execute(text('CREATE SCHEMA IF NOT EXISTS key_manager'))
                await connection.run_sync(User.metadata.drop_all)
                await connection.run_sync(User.metadata.create_all)
            factory = async_sessionmaker(self.async_engine, expire_on_commit=False)
        else:
            self.engine = create_engine('sqlite://', execution_options={
                'schema_translate_map': {'identity': None, 'key_manager': None},
            })

            @event.listens_for(self.engine, 'connect')
            def foreign_keys(connection, _):
                connection.execute('PRAGMA foreign_keys=ON')

            User.metadata.create_all(self.engine)
            engine = self.engine

            class SqliteSession(Session):
                def __init__(self, **kwargs):
                    kwargs['bind'] = engine
                    super().__init__(**kwargs)

            factory = async_sessionmaker(class_=AsyncSession, sync_session_class=SqliteSession, expire_on_commit=False)
        self.database = Database(factory)
        self.db = IdentityDbService(self.database)
        self.user = await self.db.create_user(email='user@example.com', username='user', password_hash=self.password_hash)
        self.admin = await self.db.create_user(email='admin@example.com', username='admin', password_hash=self.password_hash)
        async with self.database.transaction() as session:
            role = Role(name='identity-admin', is_system=True)
            permissions = [Permission(action=action) for action in ADMIN_ACTIONS]
            session.add_all([role, *permissions])
            await session.flush()
            self.admin_role_id = str(role.role_id)
            session.add_all([RolePermission(role_id=role.role_id, permission_id=row.permission_id) for row in permissions])
            session.add(UserRole(user_id=self.admin.user_id, role_id=role.role_id, assigned_by_user_id=self.admin.user_id))
        self.messages = []

        async def deliver(**message):
            self.messages.append(message)

        self.database_patch = patch.object(main, 'Database', return_value=self.database)
        self.database_patch.start()
        self.lifespan = main.app.router.lifespan_context(main.app)
        await self.lifespan.__aenter__()
        main.app.state.identity_email_delivery = deliver
        self.jwks_payload = await main.app.state.key_manager.jwks()
        client_patch = patch.object(auth_dependencies, 'jwks_client', jwt.PyJWKClient(auth_dependencies.JWKS_URL,
            timeout=5, ssl_context=auth_dependencies.jwks_client.ssl_context))
        client_patch.start()
        self.addCleanup(client_patch.stop)
        transport_patch = patch('jwt.jwks_client.urllib.request.urlopen', side_effect=lambda *args, **kwargs:
            BytesIO(json.dumps(self.jwks_payload).encode()))
        self.jwks_http = transport_patch.start()
        self.addCleanup(transport_patch.stop)
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=main.app), base_url='https://identity.test')

    async def asyncTearDown(self):
        await self.client.aclose()
        await self.lifespan.__aexit__(None, None, None)
        self.database_patch.stop()
        if self.async_engine is not None:
            await self.async_engine.dispose()
        else:
            self.engine.dispose()

    async def login(self, *, admin=False, password=PASSWORD, email=None):
        response = await self.client.post('/api/auth/login', json={
            'email': email or ('admin@example.com' if admin else 'user@example.com'), 'password': password,
        })
        self.assertEqual(response.status_code, 200, response.text)
        return response.json()

    @staticmethod
    def headers(tokens):
        return {'Authorization': f"Bearer {tokens['access_token']}"}

    async def test_registration_validation_and_no_secret_exposure(self):
        response = await self.client.post('/api/auth/register', json={
            'email': 'new@example.com', 'username': 'new-user', 'password': NEW_PASSWORD,
        })
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.json()['email'], 'new@example.com')
        self.assertIsNone(response.json()['verified_at'])
        self.assertNotIn('password', response.text)
        self.assertNotIn('token_version', response.json())
        self.assertEqual(len(self.messages), 1)
        duplicate = await self.client.post('/api/auth/register', json={
            'email': 'new@example.com', 'username': 'another', 'password': NEW_PASSWORD,
        })
        self.assertEqual(duplicate.status_code, 409)
        for extra in ({'password': 's3cr!'}, {'is_banned': True}, {'roles': ['admin']}):
            invalid = await self.client.post('/api/auth/register', json={
                'email': 'other@example.com', 'username': 'other', 'password': NEW_PASSWORD, **extra,
            })
            self.assertEqual(invalid.status_code, 422, invalid.text)
            self.assertNotIn('s3cr!', invalid.text)

    async def test_registration_rejects_short_passwords_without_creating_users_or_sending_email(self):
        for password in ('', 'bad123', '1234567', '😀' * 7):
            with self.subTest(password=password):
                response = await self.client.post('/api/auth/register', json={
                    'email': 'weak-password@example.com', 'username': 'weak-password', 'password': password,
                })
                self.assertEqual(response.status_code, 422, response.text)
                if password:
                    self.assertNotIn(password, response.text)
                self.assertIsNone(await self.db.get_user_by_email('weak-password@example.com'))
        self.assertEqual(self.messages, [])

    async def test_registration_accepts_simple_and_long_passwords_and_can_login(self):
        for index, password in enumerate(('password', 'with spaces', 'x' * 200)):
            email = f'password-policy-{index}@example.com'
            response = await self.client.post('/api/auth/register', json={
                'email': email, 'username': f'password-policy-{index}', 'password': password,
            })
            self.assertEqual(response.status_code, 201, response.text)
            self.assertNotIn('password_hash', response.text)
            await self.login(email=email, password=password)

    async def test_login_jwks_and_identity_only_claims(self):
        tokens = await self.login()
        public = (await self.client.get('/.well-known/jwks.json')).json()['keys'][0]
        claims = jwt.decode(tokens['access_token'], jwt.PyJWK.from_dict(public).key,
                            algorithms=['RS256'], audience='apps', issuer='https://identity.test')
        self.assertEqual(claims['sub'], str(self.user.user_id))
        self.assertEqual(claims['sid'], tokens['session_id'])
        self.assertNotIn('permissions', claims)
        self.assertNotIn('roles', claims)
        session = await self.db.get_session(UUID(tokens['session_id']))
        self.assertEqual(len(session.refresh_token_digest), 64)
        self.assertNotEqual(session.refresh_token_digest, tokens['refresh_token'])
        profile = await self.client.get('/api/users/me', headers=self.headers(tokens))
        self.assertEqual(profile.status_code, 200, profile.text)
        self.assertEqual(profile.json()['user_id'], str(self.user.user_id))
        self.assertNotIn('password_hash', profile.json())

    async def test_protected_routes_refresh_jwks_after_key_rotation(self):
        first = await self.login()
        self.assertEqual((await self.client.get('/api/users/me', headers=self.headers(first))).status_code, 200)
        self.assertEqual(self.jwks_http.call_count, 1)
        await main.app.state.key_manager.rotate()
        self.jwks_payload = await main.app.state.key_manager.jwks()
        second = await self.login()
        self.assertEqual((await self.client.get('/api/users/me', headers=self.headers(second))).status_code, 200)
        self.assertEqual(self.jwks_http.call_count, 2)
        self.assertEqual((await self.client.get('/api/users/me', headers=self.headers(first))).status_code, 200)

    async def test_jwks_outage_returns_unavailable_for_protected_routes(self):
        from urllib.error import URLError

        tokens = await self.login()
        self.jwks_http.side_effect = URLError('test outage')
        response = await self.client.get('/api/users/me', headers=self.headers(tokens))
        self.assertEqual(response.status_code, 503, response.text)
        self.assertNotIn('test outage', response.text)

    async def test_token_permission_claims_cannot_grant_identity_access(self):
        tokens = await self.login()
        claims = jwt.decode(tokens['access_token'], options={'verify_signature': False})
        key = main.app.state.key_manager._active
        token = jwt.encode({**claims, 'permissions': list(ADMIN_ACTIONS), 'roles': ['identity-admin']},
            key.raw_value, algorithm='RS256', headers={'kid': key.kid, 'typ': 'JWT'})
        headers = {'Authorization': f'Bearer {token}'}
        self.assertEqual((await self.client.get('/api/users/me', headers=headers)).status_code, 200)
        self.assertEqual((await self.client.get('/api/users', headers=headers)).status_code, 403)
        self.assertEqual((await self.client.get('/api/users/me/permissions', headers=headers)).json(), [])

    async def test_invalid_credentials_are_uniform(self):
        wrong = await self.client.post('/api/auth/login', json={'email': 'user@example.com', 'password': 'wrong'})
        missing = await self.client.post('/api/auth/login', json={'email': 'missing@example.com', 'password': 'wrong'})
        self.assertEqual(wrong.status_code, 401)
        self.assertEqual(wrong.json(), missing.json())
        self.assertEqual(wrong.headers['www-authenticate'], 'Bearer')

    async def test_protected_routes_require_valid_user_and_owned_session(self):
        self.assertEqual((await self.client.get('/api/users/me')).status_code, 401)
        self.assertEqual((await self.client.get('/api/users/me', headers={'Authorization': 'Bearer invalid'})).status_code, 401)
        tokens = await self.login()
        forged = main.app.state.key_manager.sign({'sub': str(self.admin.user_id), 'sid': tokens['session_id']})
        response = await self.client.get('/api/users/me', headers={'Authorization': f'Bearer {forged}'})
        self.assertEqual(response.status_code, 401)

    async def test_profile_update_conflicts_and_validation(self):
        headers = self.headers(await self.login())
        response = await self.client.patch('/api/users/me', headers=headers, json={'username': 'updated'})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['username'], 'updated')
        self.assertEqual((await self.client.patch('/api/users/me', headers=headers, json={'username': 'admin'})).status_code, 409)
        self.assertEqual((await self.client.patch('/api/users/me', headers=headers, json={'username': ' '})).status_code, 422)
        self.assertEqual((await self.client.patch('/api/users/me', headers=headers, json={'email': 'other@example.com'})).status_code, 422)

    async def test_refresh_rotation_and_replay_revoke_the_session(self):
        tokens = await self.login()
        response = await self.client.post('/api/auth/refresh', json={'refresh_token': tokens['refresh_token']})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        fresh = response.json()
        self.assertNotEqual(fresh['refresh_token'], tokens['refresh_token'])
        self.assertEqual(fresh['session_id'], tokens['session_id'])
        replay = await self.client.post('/api/auth/refresh', json={'refresh_token': tokens['refresh_token']})
        self.assertEqual(replay.status_code, 401)
        self.assertEqual((await self.client.post('/api/auth/refresh', json={'refresh_token': fresh['refresh_token']})).status_code, 401)
        self.assertEqual((await self.client.get('/api/users/me', headers=self.headers(fresh))).status_code, 401)

    async def test_tampered_refresh_cannot_revoke_a_valid_session(self):
        tokens = await self.login()
        token = tokens['refresh_token']
        changed = token[:-1] + ('0' if token[-1] != '0' else '1')
        self.assertEqual((await self.client.post('/api/auth/refresh', json={'refresh_token': changed})).status_code, 401)
        self.assertEqual((await self.client.post('/api/auth/refresh', json={'refresh_token': token})).status_code, 200)

    async def test_logout_and_session_ownership(self):
        tokens = await self.login()
        other = await self.login(admin=True)
        headers = self.headers(tokens)
        sessions = await self.client.get('/api/auth/sessions', headers=headers)
        self.assertEqual(sessions.status_code, 200)
        self.assertNotIn('refresh_token_digest', sessions.text)
        denied = await self.client.delete(f"/api/auth/sessions/{other['session_id']}", headers=headers)
        self.assertEqual(denied.status_code, 404)
        self.assertEqual((await self.client.post('/api/auth/logout', headers=headers)).status_code, 204)
        self.assertEqual((await self.client.get('/api/users/me', headers=headers)).status_code, 401)
        self.assertEqual((await self.client.post('/api/auth/refresh', json={'refresh_token': tokens['refresh_token']})).status_code, 401)
        self.assertEqual((await self.client.get('/api/users/me', headers=self.headers(other))).status_code, 200)

    async def test_logout_all_revokes_only_owned_sessions(self):
        first, second, other = await self.login(), await self.login(), await self.login(admin=True)
        self.assertEqual((await self.client.post('/api/auth/logout-all', headers=self.headers(first))).status_code, 204)
        self.assertEqual((await self.client.get('/api/users/me', headers=self.headers(second))).status_code, 401)
        self.assertEqual((await self.client.get('/api/users/me', headers=self.headers(other))).status_code, 200)

    async def test_password_change_revokes_sessions(self):
        tokens = await self.login()
        wrong = await self.client.post('/api/auth/password/change', headers=self.headers(tokens), json={
            'current_password': PASSWORD, 'new_password': NEW_PASSWORD,
        })
        self.assertEqual(wrong.status_code, 403)
        await self.complete_mfa(self.headers(tokens))
        weak = await self.client.post('/api/auth/password/change', headers=self.headers(tokens), json={
            'new_password': 'bad123',
        })
        self.assertEqual(weak.status_code, 422, weak.text)
        self.assertNotIn('bad123', weak.text)
        self.assertEqual((await self.db.get_user(self.user.user_id)).password_hash, self.password_hash)
        response = await self.client.post('/api/auth/password/change', headers=self.headers(tokens), json={
            'new_password': NEW_PASSWORD,
        })
        self.assertEqual(response.status_code, 204, response.text)
        self.assertEqual((await self.client.get('/api/users/me', headers=self.headers(tokens))).status_code, 401)
        old = await self.client.post('/api/auth/login', json={'email': 'user@example.com', 'password': PASSWORD})
        self.assertEqual(old.status_code, 401)
        await self.login(password=NEW_PASSWORD)

    async def test_sensitive_settings_reject_pending_other_session_expired_and_cancelled_proofs(self):
        first = await self.login()
        first_headers = self.headers(first)
        await self.complete_mfa(first_headers)
        added = await self.client.post('/api/users/me/emails', headers=first_headers, json={'email': 'pending@example.com'})
        self.assertEqual(added.status_code, 201, added.text)
        email_id = added.json()['secondary_email_id']
        second_headers = self.headers(await self.login())
        requests = (
            ('post', '/api/auth/password/change', {'current_password': PASSWORD, 'new_password': NEW_PASSWORD}),
            ('post', '/api/users/me/emails', {'email': 'unapproved@example.com'}),
            ('delete', f'/api/users/me/emails/{email_id}', None),
            ('post', f'/api/users/me/emails/{email_id}/primary', None),
            ('post', '/api/challenges/passkey-registration', {'current_password': PASSWORD}),
        )

        async def assert_denied():
            for method, path, body in requests:
                with self.subTest(method=method, path=path):
                    response = await self.client.request(method, path, headers=second_headers, json=body)
                    self.assertEqual(response.status_code, 403, response.text)
                    self.assertEqual(response.headers['content-type'], 'application/problem+json')
                    self.assertEqual(response.headers['cache-control'], 'no-store')

        await assert_denied()  # The first session's proof cannot authorize the second.
        async with self.database.transaction() as session:
            await session.execute(update(AuthChallenge).values(created_at=datetime.now(UTC) - timedelta(seconds=61)))
        challenge, code = await self.email_challenge(second_headers)
        await assert_denied()  # Merely issuing a challenge does not prove possession.
        verified = await self.client.post(challenge.headers['location'] + '/verify', headers=second_headers,
            json={'method': 'email_otp', 'code': code})
        self.assertEqual(verified.status_code, 200, verified.text)
        proof_id = UUID(verified.json()['challenge_id'])
        async with self.database.transaction() as session:
            await session.execute(update(AuthChallenge).where(AuthChallenge.challenge_id == proof_id)
                .values(verified_at=datetime.now(UTC) - timedelta(seconds=301)))
        await assert_denied()
        async with self.database.transaction() as session:
            await session.execute(update(AuthChallenge).where(AuthChallenge.challenge_id == proof_id)
                .values(verified_at=datetime.now(UTC), cancelled_at=datetime.now(UTC)))
        await assert_denied()
        self.assertEqual((await self.db.get_user(self.user.user_id)).password_hash, self.password_hash)
        self.assertEqual(len(await self.db.list_secondary_emails(self.user.user_id)), 1)
        self.assertEqual((await self.client.get('/api/users/me', headers=second_headers)).status_code, 200)

    async def test_password_change_rechecks_challenge_after_hashing(self):
        tokens = await self.login()
        headers = self.headers(tokens)
        await self.complete_mfa(headers)
        security = main.app.state.identity_security
        hash_password = security.hash_password

        async def expire_while_hashing(password):
            result = await hash_password(password)
            async with self.database.transaction() as session:
                await session.execute(update(AuthChallenge).values(verified_at=datetime.now(UTC) - timedelta(seconds=301)))
            return result

        with patch.object(security, 'hash_password', side_effect=expire_while_hashing):
            response = await self.client.post('/api/auth/password/change', headers=headers,
                json={'new_password': NEW_PASSWORD})
        self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual((await self.db.get_user(self.user.user_id)).password_hash, self.password_hash)
        self.assertIsNone((await self.db.get_session(UUID(tokens['session_id']))).revoked_at)

    async def test_login_rejects_credentials_changed_after_password_verification(self):
        security = main.app.state.identity_security
        verify_password = security.verify_password
        new_hash = await security.hash_password(NEW_PASSWORD)

        async def change_after_verification(password, password_hash):
            valid = await verify_password(password, password_hash)
            if valid:
                async with self.database.transaction() as session:
                    await session.execute(update(User).where(User.user_id == self.user.user_id).values(
                        password_hash=new_hash, token_version=User.token_version + 1,
                    ))
            return valid

        with patch.object(security, 'verify_password', side_effect=change_after_verification):
            response = await self.client.post('/api/auth/login', json={
                'email': 'user@example.com', 'password': PASSWORD,
            })
        self.assertEqual(response.status_code, 401, response.text)
        self.assertEqual(await self.db.list_sessions(self.user.user_id), [])
        await self.login(password=NEW_PASSWORD)

    async def test_password_recovery_is_private_single_use_and_revokes_sessions(self):
        tokens = await self.login()
        known = await self.client.post('/api/auth/password/forgot', json={'email': 'user@example.com'})
        unknown = await self.client.post('/api/auth/password/forgot', json={'email': 'unknown@example.com'})
        self.assertEqual(known.status_code, 202)
        self.assertEqual(known.json(), unknown.json())
        self.assertEqual(len(self.messages), 1)
        message = self.messages[0]
        self.assertEqual(message['purpose'], 'password_reset')
        self.assertNotIn(message['token'], known.text)
        response = await self.client.post('/api/auth/password/reset', json={'token': message['token'], 'new_password': NEW_PASSWORD})
        self.assertEqual(response.status_code, 204, response.text)
        replay = await self.client.post('/api/auth/password/reset', json={'token': message['token'], 'new_password': NEW_PASSWORD})
        self.assertEqual(replay.status_code, 401)
        self.assertEqual((await self.client.get('/api/users/me', headers=self.headers(tokens))).status_code, 401)
        await self.login(password=NEW_PASSWORD)

    async def test_weak_reset_password_does_not_consume_the_reset_token(self):
        response = await self.client.post('/api/auth/password/forgot', json={'email': 'user@example.com'})
        self.assertEqual(response.status_code, 202, response.text)
        token = self.messages[-1]['token']
        response = await self.client.post('/api/auth/password/reset', json={'token': token, 'new_password': 'bad123'})
        self.assertEqual(response.status_code, 422, response.text)
        self.assertNotIn('bad123', response.text)
        self.assertNotIn(token, response.text)
        self.assertEqual((await self.db.get_user(self.user.user_id)).password_hash, self.password_hash)
        response = await self.client.post('/api/auth/password/reset', json={'token': token, 'new_password': NEW_PASSWORD})
        self.assertEqual(response.status_code, 204, response.text)
        await self.login(password=NEW_PASSWORD)

    async def test_expired_recovery_token_is_rejected(self):
        await self.client.post('/api/auth/password/forgot', json={'email': 'user@example.com'})
        async with self.database.transaction() as session:
            await session.execute(update(AuthToken).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
        response = await self.client.post('/api/auth/password/reset', json={'token': self.messages[0]['token'], 'new_password': NEW_PASSWORD})
        self.assertEqual(response.status_code, 401)
        await self.login()

    async def test_password_recovery_delivery_failure_remains_private(self):
        delivered = []

        async def broken(**message):
            delivered.append(message['token'])
            raise RuntimeError('private provider diagnostic')

        main.app.state.identity_email_delivery = broken
        with self.assertLogs('identity.services.identity', level='ERROR') as logs:
            known = await self.client.post('/api/auth/password/forgot', json={'email': 'user@example.com'})
        unknown = await self.client.post('/api/auth/password/forgot', json={'email': 'unknown@example.com'})
        self.assertEqual(known.status_code, 202)
        self.assertEqual(unknown.status_code, 202)
        self.assertEqual(known.json(), unknown.json())
        self.assertEqual(len(delivered), 1)
        for output in (known.text, unknown.text, '\n'.join(logs.output)):
            self.assertNotIn(delivered[0], output)
            self.assertNotIn('private provider diagnostic', output)
        self.assertEqual(self.messages, [])

    async def test_primary_verification_and_request_throttle(self):
        response = await self.client.post('/api/auth/email/verification/request', json={'email': 'user@example.com'})
        self.assertEqual(response.status_code, 202)
        await self.client.post('/api/auth/email/verification/request', json={'email': 'user@example.com'})
        self.assertEqual(len(self.messages), 1)
        token = self.messages[0]['token']
        self.assertEqual((await self.client.post('/api/auth/email/verification/confirm', json={'token': token})).status_code, 204)
        self.assertIsNotNone((await self.db.get_user(self.user.user_id)).verified_at)
        self.assertEqual((await self.client.post('/api/auth/email/verification/confirm', json={'token': token})).status_code, 401)

    async def test_secondary_email_verification_ownership_and_delete(self):
        headers = self.headers(await self.login())
        await self.complete_mfa(headers)
        added = await self.client.post('/api/users/me/emails', headers=headers, json={'email': 'secondary@example.com'})
        self.assertEqual(added.status_code, 201, added.text)
        email_id = added.json()['secondary_email_id']
        other_headers = self.headers(await self.login(admin=True))
        await self.complete_mfa(other_headers)
        self.assertEqual((await self.client.delete(f'/api/users/me/emails/{email_id}', headers=other_headers)).status_code, 404)
        response = await self.client.post(f'/api/users/me/emails/{email_id}/verification', headers=headers)
        self.assertEqual(response.status_code, 202, response.text)
        token = self.messages[-1]['token']
        tampered = f'{uuid4()}.{token.split(".", 1)[1]}'
        self.assertEqual((await self.client.post('/api/auth/email/verification/confirm', json={'token': tampered})).status_code, 401)
        self.assertEqual((await self.client.post('/api/auth/email/verification/confirm', json={'token': token})).status_code, 204)
        emails = (await self.client.get('/api/users/me/emails', headers=headers)).json()
        self.assertTrue(emails[0]['is_verified'])
        self.assertEqual((await self.client.delete(f'/api/users/me/emails/{email_id}', headers=headers)).status_code, 204)
        self.assertEqual((await self.client.delete(f'/api/users/me/emails/{email_id}', headers=headers)).status_code, 404)

    async def test_verified_secondary_can_become_primary_after_challenge(self):
        headers = self.headers(await self.login())
        await self.complete_mfa(headers)
        added = await self.client.post('/api/users/me/emails', headers=headers, json={'email': 'new-primary@example.com'})
        email_id = added.json()['secondary_email_id']
        url = f'/api/users/me/emails/{email_id}/primary'
        self.assertEqual((await self.client.post(url, headers=headers)).status_code, 403)
        await self.client.post(f'/api/users/me/emails/{email_id}/verification', headers=headers)
        await self.client.post('/api/auth/email/verification/confirm', json={'token': self.messages[-1]['token']})
        response = await self.client.post(url, headers=headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json()['email'], 'new-primary@example.com')
        self.assertEqual((await self.client.get('/api/users/me', headers=headers)).status_code, 401)
        await self.login(email='new-primary@example.com')

    async def test_admin_routes_deny_unprivileged_users(self):
        headers = self.headers(await self.login())
        await self.complete_mfa(headers)
        for path in ('/api/users', '/api/roles', '/api/permissions', '/api/audit/role-assignments'):
            response = await self.client.get(path, headers=headers)
            self.assertEqual(response.status_code, 403, (path, response.text))
        response = await self.client.post('/api/roles', headers=headers, json={'name': 'bad'})
        self.assertEqual(response.status_code, 403)
        self.assertEqual(response.json()['detail'], 'identity permission required')

    async def test_admin_writes_require_recent_challenge_for_the_acting_session(self):
        first_headers = self.headers(await self.login(admin=True))
        role_id, permission_id = uuid4(), uuid4()
        requests = (
            ('patch', f'/api/users/{self.user.user_id}/ban', {'is_banned': True}),
            ('delete', f'/api/users/{self.user.user_id}/sessions', None),
            ('put', f'/api/users/{self.user.user_id}/roles/{role_id}', None),
            ('delete', f'/api/users/{self.user.user_id}/roles/{role_id}', None),
            ('post', '/api/roles', {'name': 'unapproved'}),
            ('patch', f'/api/roles/{role_id}', {'name': 'unapproved'}),
            ('delete', f'/api/roles/{role_id}', None),
            ('put', f'/api/roles/{role_id}/permissions/{permission_id}', None),
            ('delete', f'/api/roles/{role_id}/permissions/{permission_id}', None),
            ('post', '/api/permissions', {'action': 'identity.unapproved'}),
            ('patch', f'/api/permissions/{permission_id}', {'description': 'unapproved'}),
            ('delete', f'/api/permissions/{permission_id}', None),
        )

        async def assert_denied(headers):
            for method, path, body in requests:
                with self.subTest(method=method, path=path):
                    response = await self.client.request(method, path, headers=headers, json=body)
                    self.assertEqual(response.status_code, 403, response.text)
                    self.assertEqual(response.headers['content-type'], 'application/problem+json')
                    self.assertEqual(response.headers['cache-control'], 'no-store')

        await assert_denied(first_headers)
        self.assertEqual((await self.client.get('/api/users', headers=first_headers)).status_code, 200)
        await self.complete_mfa(first_headers)
        second_headers = self.headers(await self.login(admin=True))
        await assert_denied(second_headers)
        async with self.database.transaction() as session:
            await session.execute(update(AuthChallenge).values(verified_at=datetime.now(UTC) - timedelta(seconds=301)))
        await assert_denied(first_headers)
        self.assertFalse((await self.db.get_user(self.user.user_id)).is_banned)

    async def test_admin_ban_and_session_management(self):
        user_tokens, admin_tokens = await self.login(), await self.login(admin=True)
        headers = self.headers(admin_tokens)
        await self.complete_mfa(headers)
        url = f'/api/users/{self.user.user_id}/ban'
        response = await self.client.patch(url, headers=headers, json={'is_banned': True})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertTrue(response.json()['is_banned'])
        self.assertEqual((await self.client.get('/api/users/me', headers=self.headers(user_tokens))).status_code, 401)
        banned_login = await self.client.post('/api/auth/login', json={'email': 'user@example.com', 'password': PASSWORD})
        self.assertEqual(banned_login.status_code, 401)
        self.assertEqual((await self.client.patch(url, headers=headers, json={'is_banned': False})).status_code, 200)
        tokens = await self.login()
        self.assertEqual((await self.client.get(f'/api/users/{self.user.user_id}/sessions', headers=headers)).status_code, 200)
        self.assertEqual((await self.client.delete(f'/api/users/{self.user.user_id}/sessions', headers=headers)).status_code, 204)
        self.assertEqual((await self.client.get('/api/users/me', headers=self.headers(tokens))).status_code, 401)
        self.assertEqual((await self.client.patch(f'/api/users/{self.admin.user_id}/ban', headers=headers, json={'is_banned': True})).status_code, 403)

    async def test_admin_change_rechecks_challenge_before_writing(self):
        from identity.db.services.admin import IdentityAdminDbService

        headers = self.headers(await self.login(admin=True))
        await self.complete_mfa(headers)
        create_role = IdentityAdminDbService.create_role

        async def delayed_create(service, **kwargs):
            async with self.database.transaction() as session:
                await session.execute(update(AuthChallenge).values(verified_at=datetime.now(UTC) - timedelta(seconds=301)))
            return await create_role(service, **kwargs)

        with patch.object(IdentityAdminDbService, 'create_role', new=delayed_create):
            response = await self.client.post('/api/roles', headers=headers, json={'name': 'expired-proof'})
        self.assertEqual(response.status_code, 403, response.text)
        roles = (await self.client.get('/api/roles', headers=headers)).json()
        self.assertNotIn('expired-proof', [row['name'] for row in roles])

    async def test_role_and_permission_crud_and_audits(self):
        headers = self.headers(await self.login(admin=True))
        await self.complete_mfa(headers)
        role = await self.client.post('/api/roles', headers=headers, json={'name': 'support', 'description': 'support role'})
        self.assertEqual(role.status_code, 201, role.text)
        role_id = role.json()['role_id']
        permission = await self.client.post('/api/permissions', headers=headers, json={'action': 'identity.support.read'})
        self.assertEqual(permission.status_code, 201, permission.text)
        permission_id = permission.json()['permission_id']
        link = f'/api/roles/{role_id}/permissions/{permission_id}'
        self.assertEqual((await self.client.put(link, headers=headers)).json(), {'changed': True})
        self.assertEqual((await self.client.put(link, headers=headers)).json(), {'changed': False})
        self.assertEqual((await self.client.get(f'/api/roles/{role_id}/permissions', headers=headers)).json()[0]['action'], 'identity.support.read')
        assignment = f'/api/users/{self.user.user_id}/roles/{role_id}'
        self.assertEqual((await self.client.put(assignment, headers=headers)).json(), {'changed': True})
        self.assertEqual((await self.client.put(assignment, headers=headers)).json(), {'changed': False})
        self.assertEqual((await self.client.get(f'/api/users/{self.user.user_id}/permissions', headers=headers)).json(), ['identity.support.read'])
        self.assertEqual((await self.client.patch(f'/api/roles/{role_id}', headers=headers, json={'name': 'support-renamed'})).status_code, 200)
        self.assertEqual((await self.client.patch(f'/api/permissions/{permission_id}', headers=headers, json={'description': 'updated'})).status_code, 200)
        self.assertEqual((await self.client.get(f'/api/permissions/{permission_id}', headers=headers)).status_code, 200)
        self.assertEqual((await self.client.get(f'/api/roles/{role_id}', headers=headers)).status_code, 200)
        self.assertEqual((await self.client.delete(assignment, headers=headers)).json(), {'changed': True})
        self.assertEqual((await self.client.delete(link, headers=headers)).json(), {'changed': True})
        self.assertEqual((await self.client.delete(f'/api/permissions/{permission_id}', headers=headers)).status_code, 204)
        self.assertEqual((await self.client.delete(f'/api/roles/{role_id}', headers=headers)).status_code, 204)
        for path in ('role-assignments', 'role-definitions', 'role-permissions'):
            audit = await self.client.get(f'/api/audit/{path}', headers=headers)
            self.assertEqual(audit.status_code, 200, audit.text)
            self.assertTrue(audit.json())
            self.assertEqual(audit.json()[0]['actor_user_id'], str(self.admin.user_id))

    async def test_identity_permissions_are_checked_fresh_without_token_claims(self):
        admin_headers = self.headers(await self.login(admin=True))
        await self.complete_mfa(admin_headers)
        user_headers = self.headers(await self.login())
        url = '/api/users/me/permissions'
        self.assertEqual((await self.client.get(url)).status_code, 401)
        response = await self.client.get(url, headers=user_headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), [])
        self.assertEqual(response.headers['cache-control'], 'no-store')
        response = await self.client.get(url, headers=admin_headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), sorted(ADMIN_ACTIONS))
        role = (await self.client.post('/api/roles', headers=admin_headers, json={'name': 'reader'})).json()
        permissions = (await self.client.get('/api/permissions', headers=admin_headers)).json()
        permission = next(row for row in permissions if row['action'] == 'identity.users.read')
        await self.client.put(f"/api/roles/{role['role_id']}/permissions/{permission['permission_id']}", headers=admin_headers)
        link = f"/api/users/{self.user.user_id}/roles/{role['role_id']}"
        await self.client.put(link, headers=admin_headers)
        response = await self.client.get(url, headers=user_headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), ['identity.users.read'])
        self.assertEqual((await self.client.get('/api/users', headers=user_headers)).status_code, 200)
        await self.client.delete(link, headers=admin_headers)
        response = await self.client.get(url, headers=user_headers)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.json(), [])
        self.assertEqual((await self.client.get('/api/users', headers=user_headers)).status_code, 403)

    async def test_system_roles_and_input_bounds(self):
        headers = self.headers(await self.login(admin=True))
        await self.complete_mfa(headers)
        self.assertEqual((await self.client.delete(f'/api/roles/{self.admin_role_id}', headers=headers)).status_code, 403)
        self.assertEqual((await self.client.patch(f'/api/roles/{self.admin_role_id}', headers=headers, json={'name': 'other'})).status_code, 403)
        self.assertEqual((await self.client.get('/api/users?limit=101', headers=headers)).status_code, 422)
        self.assertEqual((await self.client.get('/api/roles?offset=-1', headers=headers)).status_code, 422)
        self.assertEqual((await self.client.patch(f'/api/roles/{self.admin_role_id}', headers=headers, json={})).status_code, 422)
        self.assertEqual((await self.client.post('/api/roles', headers=headers, json={'name': 'bad', 'is_system': True})).status_code, 422)
        self.assertEqual((await self.client.get(f'/api/users/{uuid4()}', headers=headers)).status_code, 404)

    async def test_authentication_rate_limit_is_bounded(self):
        for _ in range(30):
            response = await self.client.post('/api/auth/email/verification/request', json={'email': 'unknown@example.com'})
            self.assertEqual(response.status_code, 202)
        response = await self.client.post('/api/auth/email/verification/request', json={'email': 'unknown@example.com'})
        self.assertEqual(response.status_code, 429)
        self.assertEqual(response.headers['retry-after'], '60')

    async def test_expired_wrong_audience_and_missing_claims_are_rejected(self):
        tokens = await self.login()
        claims = jwt.decode(tokens['access_token'], options={'verify_signature': False})
        key = main.app.state.key_manager._active
        for changes in ({'iss': 'other'}, {'aud': 'other'}, {'exp': 1}, {'nbf': 9999999999}, {'sub': 'not-a-uuid'}):
            with self.subTest(changes=changes):
                token = jwt.encode({**claims, **changes}, key.raw_value, algorithm='RS256', headers={'kid': key.kid, 'typ': 'JWT'})
                response = await self.client.get('/api/users/me', headers={'Authorization': f'Bearer {token}'})
                self.assertEqual(response.status_code, 401, response.text)
        missing = dict(claims)
        del missing['sid']
        token = jwt.encode(missing, key.raw_value, algorithm='RS256', headers={'kid': key.kid})
        self.assertEqual((await self.client.get('/api/users/me', headers={'Authorization': f'Bearer {token}'})).status_code, 401)

    async def test_system_permission_identifiers_are_protected(self):
        headers = self.headers(await self.login(admin=True))
        await self.complete_mfa(headers)
        permissions = (await self.client.get('/api/permissions', headers=headers)).json()
        permission_id = permissions[0]['permission_id']
        url = f'/api/permissions/{permission_id}'
        self.assertEqual((await self.client.get(url, headers=headers)).status_code, 200)
        self.assertEqual((await self.client.delete(url, headers=headers)).status_code, 403)
        self.assertEqual((await self.client.patch(url, headers=headers, json={'action': 'renamed'})).status_code, 403)

    async def test_bootstrap_is_idempotent_and_grants_only_explicit_user(self):
        from identity.bootstrap_admin import grant_admin

        headers = self.headers(await self.login())
        self.assertEqual((await self.client.get('/api/users', headers=headers)).status_code, 403)
        await grant_admin(self.user.user_id, self.database)
        await grant_admin(self.user.user_id, self.database)
        self.assertEqual((await self.client.get('/api/users', headers=headers)).status_code, 200)
        self.assertEqual(await self.db.list_user_permissions(self.user.user_id), set(ADMIN_ACTIONS))
        with self.assertRaises(ValueError):
            await grant_admin(uuid4(), self.database)

    async def test_deleting_attached_permission_preserves_audit_snapshot(self):
        headers = self.headers(await self.login(admin=True))
        await self.complete_mfa(headers)
        role = (await self.client.post('/api/roles', headers=headers, json={'name': 'temporary'})).json()
        permission = (await self.client.post('/api/permissions', headers=headers, json={'action': 'identity.temporary'})).json()
        await self.client.put(f"/api/roles/{role['role_id']}/permissions/{permission['permission_id']}", headers=headers)
        response = await self.client.delete(f"/api/permissions/{permission['permission_id']}", headers=headers)
        self.assertEqual(response.status_code, 204, response.text)
        self.assertEqual((await self.client.get(f"/api/roles/{role['role_id']}/permissions", headers=headers)).json(), [])
        logs = (await self.client.get('/api/audit/role-permissions', headers=headers)).json()
        deleted = next(row for row in logs if row['changes'].get('permission_deleted'))
        self.assertIsNone(deleted['permission_id'])
        self.assertEqual(deleted['permission_action_snapshot'], 'identity.temporary')

    async def test_concurrent_refresh_has_one_winner_and_revokes_replayed_session(self):
        if self.async_engine is None:
            self.skipTest('requires PostgreSQL row locking')
        tokens = await self.login()
        responses = await asyncio.gather(*[
            self.client.post('/api/auth/refresh', json={'refresh_token': tokens['refresh_token']}) for _ in range(2)
        ])
        self.assertEqual(sorted(row.status_code for row in responses), [200, 401])
        self.assertIsNotNone((await self.db.get_session(UUID(tokens['session_id']))).revoked_at)

    async def test_concurrent_password_reset_consumes_token_once(self):
        if self.async_engine is None:
            self.skipTest('requires PostgreSQL row locking')
        await self.client.post('/api/auth/password/forgot', json={'email': 'user@example.com'})
        token = self.messages[0]['token']
        responses = await asyncio.gather(*[
            self.client.post('/api/auth/password/reset', json={'token': token, 'new_password': NEW_PASSWORD}) for _ in range(2)
        ])
        self.assertEqual(sorted(row.status_code for row in responses), [204, 401])
        await self.login(password=NEW_PASSWORD)

    async def test_unavailable_signer_does_not_create_a_session(self):
        with patch.object(main.app.state.key_manager, 'sign', side_effect=RuntimeError('overdue')):
            response = await self.client.post('/api/auth/login', json={'email': 'user@example.com', 'password': PASSWORD})
        self.assertEqual(response.status_code, 503, response.text)
        self.assertEqual(await self.db.list_sessions(self.user.user_id), [])

    async def test_small_clock_adjustment_is_allowed_and_larger_one_is_rejected(self):
        tokens = await self.login()
        claims = jwt.decode(tokens['access_token'], options={'verify_signature': False})
        key = main.app.state.key_manager._active
        for seconds, expected in ((2, 200), (60, 401)):
            now = int(datetime.now(UTC).timestamp())
            adjusted = {**claims, 'iat': now + seconds, 'nbf': now + seconds}
            token = jwt.encode(adjusted, key.raw_value, algorithm='RS256', headers={'kid': key.kid, 'typ': 'JWT'})
            response = await self.client.get('/api/users/me', headers={'Authorization': f'Bearer {token}'})
            self.assertEqual(response.status_code, expected, response.text)

    async def test_database_text_and_secret_validation_does_not_echo_input(self):
        response = await self.client.post('/api/auth/register', json={
            'email': 'new@example.com', 'username': 'bad\x00name', 'password': NEW_PASSWORD,
        })
        self.assertEqual(response.status_code, 422)
        secret = 'z' * 513
        response = await self.client.post('/api/auth/refresh', json={'refresh_token': secret})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(secret, response.text)

    async def email_challenge(self, headers):
        profile = await self.client.get('/api/users/me', headers=headers)
        self.assertEqual(profile.status_code, 200, profile.text)
        user_id = UUID(profile.json()['user_id'])
        async with self.database.transaction() as session:
            await session.execute(update(User).where(User.user_id == user_id).values(verified_at=datetime.now(UTC)))
        response = await self.client.post('/api/challenges/email-otp', headers=headers)
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(self.messages[-1]['purpose'], 'mfa_email_otp')
        return response, self.messages[-1]['token']

    async def complete_mfa(self, headers):
        status = await self.client.get('/api/challenges/mfa', headers=headers)
        self.assertEqual(status.status_code, 200, status.text)
        if status.json()['verified_at'] is not None:
            return status.json()
        response, code = await self.email_challenge(headers)
        verified = await self.client.post(response.headers['location'] + '/verify', headers=headers,
            json={'method': 'email_otp', 'code': code})
        self.assertEqual(verified.status_code, 200, verified.text)
        return verified.json()

    async def registration_challenge(self, headers):
        with patch.dict(os.environ, WEBAUTHN_RP_ID='identity.test', WEBAUTHN_RP_NAME='Identity', WEBAUTHN_ORIGIN='https://identity.test'):
            response = await self.client.post('/api/challenges/passkey-registration', headers=headers)
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    async def authentication_challenge(self, headers):
        with patch.dict(os.environ, WEBAUTHN_RP_ID='identity.test', WEBAUTHN_RP_NAME='Identity', WEBAUTHN_ORIGIN='https://identity.test'):
            response = await self.client.post('/api/challenges/passkey-authentication', headers=headers)
        self.assertEqual(response.status_code, 201, response.text)
        return response.json()

    @staticmethod
    def registration_credential(options, private_key, credential_id, *, origin='https://identity.test', flags=0x45, challenge=None, cross_origin=False):
        public = private_key.public_key().public_numbers()
        cose = cbor2.dumps({1: 2, 3: -7, -1: 1, -2: public.x.to_bytes(32, 'big'), -3: public.y.to_bytes(32, 'big')})
        authenticator_data = (hashlib.sha256(options['rp']['id'].encode()).digest() + bytes([flags])
            + (0).to_bytes(4, 'big') + bytes(16) + len(credential_id).to_bytes(2, 'big') + credential_id + cose)
        client_data = json.dumps({'type': 'webauthn.create', 'challenge': challenge or options['challenge'],
                                 'origin': origin, 'crossOrigin': cross_origin}).encode()
        encoded_id = bytes_to_base64url(credential_id)
        return {'id': encoded_id, 'rawId': encoded_id, 'type': 'public-key', 'response': {
            'clientDataJSON': bytes_to_base64url(client_data),
            'attestationObject': bytes_to_base64url(cbor2.dumps({'fmt': 'none', 'attStmt': {}, 'authData': authenticator_data})),
        }}

    @staticmethod
    def assertion_credential(options, private_key, credential_id, user_id, *, counter=1, flags=0x05, origin='https://identity.test'):
        authenticator_data = hashlib.sha256(options['rpId'].encode()).digest() + bytes([flags]) + counter.to_bytes(4, 'big')
        client_data = json.dumps({'type': 'webauthn.get', 'challenge': options['challenge'], 'origin': origin}).encode()
        signature = private_key.sign(authenticator_data + hashlib.sha256(client_data).digest(), ec.ECDSA(hashes.SHA256()))
        encoded_id = bytes_to_base64url(credential_id)
        return {'id': encoded_id, 'rawId': encoded_id, 'type': 'public-key', 'response': {
            'clientDataJSON': bytes_to_base64url(client_data), 'authenticatorData': bytes_to_base64url(authenticator_data),
            'signature': bytes_to_base64url(signature), 'userHandle': bytes_to_base64url(user_id.bytes),
        }}

    async def enroll_test_passkey(self, headers):
        await self.complete_mfa(headers)
        challenge = await self.registration_challenge(headers)
        private_key, credential_id = ec.generate_private_key(ec.SECP256R1()), secrets.token_bytes(32)
        credential = self.registration_credential(challenge['public_key'], private_key, credential_id)
        response = await self.client.post(f"/api/challenges/{challenge['challenge_id']}/verify", headers=headers,
            json={'method': 'passkey_registration', 'credential': credential})
        self.assertEqual(response.status_code, 200, response.text)
        return private_key, credential_id

    async def login_passkey_options(self, binding='a' * 64):
        with patch.dict(os.environ, WEBAUTHN_RP_ID='identity.test', WEBAUTHN_RP_NAME='Identity', WEBAUTHN_ORIGIN='https://identity.test'):
            response = await self.client.post('/api/auth/passkey/options', json={'browser_binding': binding})
        self.assertEqual(response.status_code, 201, response.text)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        self.assertEqual(response.json()['public_key']['allowCredentials'], [])
        self.assertEqual(response.json()['public_key']['userVerification'], 'required')
        self.assertNotIn(binding, response.text)
        return response.json()

    async def test_passkey_sign_in_creates_session_and_recent_mfa_once(self):
        headers = self.headers(await self.login())
        key, credential_id = await self.enroll_test_passkey(headers)
        await self.db.revoke_all_user_sessions(self.user.user_id)
        challenge = await self.login_passkey_options()
        credential = self.assertion_credential(challenge['public_key'], key, credential_id, self.user.user_id)
        payload = {'challenge_id': challenge['challenge_id'], 'browser_binding': 'a' * 64, 'credential': credential}
        response = await self.client.post('/api/auth/passkey/login', json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        headers = self.headers(response.json())
        self.assertEqual((await self.client.get('/api/users/me', headers=headers)).json()['user_id'], str(self.user.user_id))
        status = await self.client.get('/api/challenges/mfa', headers=headers)
        self.assertEqual(status.json()['method'], 'passkey_authentication')
        self.assertEqual((await self.client.post('/api/auth/passkey/login', json=payload)).status_code, 401)
        async with self.database.session() as session:
            row = await session.get(PasskeyLoginChallenge, UUID(challenge['challenge_id']))
            self.assertIsNotNone(row.consumed_at)
            self.assertEqual((await session.get(Passkey, credential_id)).sign_count, 1)

    async def test_passkey_sign_in_binding_expiry_and_validation(self):
        key, credential_id = await self.enroll_test_passkey(self.headers(await self.login()))
        challenge = await self.login_passkey_options()
        credential = self.assertion_credential(challenge['public_key'], key, credential_id, self.user.user_id)
        payload = {'challenge_id': challenge['challenge_id'], 'browser_binding': 'b' * 64, 'credential': credential}
        self.assertEqual((await self.client.post('/api/auth/passkey/login', json=payload)).status_code, 401)
        async with self.database.session() as session:
            self.assertEqual((await session.get(PasskeyLoginChallenge, UUID(challenge['challenge_id']))).attempts_remaining, 5)
        payload['browser_binding'] = 'a' * 64
        self.assertEqual((await self.client.post('/api/auth/passkey/login', json=payload)).status_code, 200)
        challenge = await self.login_passkey_options()
        payload['challenge_id'] = challenge['challenge_id']
        payload['credential'] = self.assertion_credential(challenge['public_key'], key, credential_id, self.user.user_id, counter=2)
        async with self.database.transaction() as session:
            await session.execute(update(PasskeyLoginChallenge).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
        self.assertEqual((await self.client.post('/api/auth/passkey/login', json=payload)).status_code, 401)
        invalid = 'Ω' * 64
        response = await self.client.post('/api/auth/passkey/options', json={'browser_binding': invalid})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(invalid, response.text)

    async def test_passkey_sign_in_rejects_invalid_assertions_and_exhausts_attempts(self):
        key, credential_id = await self.enroll_test_passkey(self.headers(await self.login()))
        challenge = await self.login_passkey_options()
        for changes in ({'origin': 'https://evil.test'}, {'user_id': uuid4()}, {'flags': 0x01}, {'private_key': ec.generate_private_key(ec.SECP256R1())}, {'credential_id': secrets.token_bytes(32)}):
            kwargs = {'options': challenge['public_key'], 'private_key': key, 'credential_id': credential_id, 'user_id': self.user.user_id, **changes}
            response = await self.client.post('/api/auth/passkey/login', json={
                'challenge_id': challenge['challenge_id'], 'browser_binding': 'a' * 64,
                'credential': self.assertion_credential(**kwargs),
            })
            self.assertEqual(response.status_code, 401, response.text)
        async with self.database.session() as session:
            self.assertEqual((await session.get(PasskeyLoginChallenge, UUID(challenge['challenge_id']))).attempts_remaining, 0)
            self.assertEqual((await session.get(Passkey, credential_id)).sign_count, 0)
        credential = self.assertion_credential(challenge['public_key'], key, credential_id, self.user.user_id)
        response = await self.client.post('/api/auth/passkey/login', json={'challenge_id': challenge['challenge_id'], 'browser_binding': 'a' * 64, 'credential': credential})
        self.assertEqual(response.status_code, 401)

    async def test_passkey_sign_in_rejects_missing_handle_cross_origin_bans_and_stale_counter(self):
        key, credential_id = await self.enroll_test_passkey(self.headers(await self.login()))
        for mode in ('missing_handle', 'cross_origin', 'banned', 'stale_counter'):
            with self.subTest(mode=mode):
                challenge = await self.login_passkey_options()
                credential = self.assertion_credential(challenge['public_key'], key, credential_id, self.user.user_id)
                if mode == 'missing_handle':
                    credential['response'].pop('userHandle')
                elif mode == 'cross_origin':
                    data = json.loads(base64url_to_bytes(credential['response']['clientDataJSON']))
                    data['crossOrigin'] = True
                    data = json.dumps(data).encode()
                    credential['response']['clientDataJSON'] = bytes_to_base64url(data)
                    credential['response']['signature'] = bytes_to_base64url(key.sign(base64url_to_bytes(credential['response']['authenticatorData']) + hashlib.sha256(data).digest(), ec.ECDSA(hashes.SHA256())))
                elif mode == 'banned':
                    async with self.database.transaction() as session:
                        await session.execute(update(User).where(User.user_id == self.user.user_id).values(is_banned=True))
                else:
                    async with self.database.transaction() as session:
                        await session.execute(update(User).where(User.user_id == self.user.user_id).values(is_banned=False))
                        await session.execute(update(Passkey).values(sign_count=1))
                response = await self.client.post('/api/auth/passkey/login', json={
                    'challenge_id': challenge['challenge_id'], 'browser_binding': 'a' * 64, 'credential': credential,
                })
                self.assertEqual(response.status_code, 401, response.text)

    async def test_passkey_sign_in_signer_failure_rolls_back_consumption(self):
        key, credential_id = await self.enroll_test_passkey(self.headers(await self.login()))
        challenge = await self.login_passkey_options()
        payload = {'challenge_id': challenge['challenge_id'], 'browser_binding': 'a' * 64,
                   'credential': self.assertion_credential(challenge['public_key'], key, credential_id, self.user.user_id)}
        with patch('identity.services.identity.sign_access_token', side_effect=RuntimeError('synthetic unavailable')):
            response = await self.client.post('/api/auth/passkey/login', json=payload)
        self.assertEqual(response.status_code, 503)
        async with self.database.session() as session:
            row = await session.get(PasskeyLoginChallenge, UUID(challenge['challenge_id']))
            self.assertIsNone(row.consumed_at)
            self.assertEqual(row.attempts_remaining, 5)
            self.assertEqual((await session.get(Passkey, credential_id)).sign_count, 0)
        self.assertEqual((await self.client.post('/api/auth/passkey/login', json=payload)).status_code, 200)

    async def test_passkey_sign_in_concurrent_completion_has_one_winner(self):
        if self.async_engine is None:
            self.skipTest('requires PostgreSQL row locking')
        key, credential_id = await self.enroll_test_passkey(self.headers(await self.login()))
        challenge = await self.login_passkey_options()
        payload = {'challenge_id': challenge['challenge_id'], 'browser_binding': 'a' * 64,
                   'credential': self.assertion_credential(challenge['public_key'], key, credential_id, self.user.user_id)}
        results = await asyncio.gather(*(self.client.post('/api/auth/passkey/login', json=payload) for _ in range(2)))
        self.assertEqual(sorted(response.status_code for response in results), [200, 401])

    async def test_challenge_email_otp_is_secret_single_use_and_session_bound(self):
        tokens = await self.login()
        headers = self.headers(tokens)
        response, code = await self.email_challenge(headers)
        self.assertRegex(code, r'^[0-9]{6}$')
        self.assertNotIn(code, response.text)
        self.assertEqual(response.headers['cache-control'], 'no-store')
        challenge = response.json()
        async with self.database.session() as session:
            row = await session.get(AuthChallenge, UUID(challenge['challenge_id']))
            self.assertEqual(len(row.otp_digest), 64)
            self.assertNotEqual(row.otp_digest, hashlib.sha256(code.encode()).hexdigest())
            self.assertIsNone(row.challenge)
        second_headers = self.headers(await self.login())
        url = response.headers['location']
        self.assertEqual(url, f"/api/challenges/{challenge['challenge_id']}")
        self.assertEqual((await self.client.get(url, headers=second_headers)).status_code, 404)
        self.assertEqual((await self.client.post(url + '/verify', headers=second_headers,
            json={'method': 'email_otp', 'code': code})).status_code, 404)
        verified = await self.client.post(url + '/verify', headers=headers, json={'method': 'email_otp', 'code': code})
        self.assertEqual(verified.status_code, 200, verified.text)
        self.assertEqual(verified.json()['status'], 'verified')
        self.assertIsNotNone(verified.json()['mfa_expires_at'])
        self.assertEqual((await self.client.post(url + '/verify', headers=headers,
            json={'method': 'email_otp', 'code': code})).status_code, 409)
        self.assertEqual((await self.client.get('/api/challenges/mfa', headers=headers)).json()['method'], 'email_otp')
        self.assertIsNone((await self.client.get('/api/challenges/mfa', headers=second_headers)).json()['method'])

    async def test_challenge_email_otp_attempts_persist_and_exhaust(self):
        headers = self.headers(await self.login())
        response, code = await self.email_challenge(headers)
        url = response.headers['location']
        wrong = '000000' if code != '000000' else '111111'
        for attempt in range(5):
            rejected = await self.client.post(url + '/verify', headers=headers, json={'method': 'email_otp', 'code': wrong})
            self.assertEqual(rejected.status_code, 429 if attempt == 4 else 400, rejected.text)
        self.assertEqual(rejected.headers['retry-after'], '60')
        self.assertEqual((await self.client.post(url + '/verify', headers=headers,
            json={'method': 'email_otp', 'code': code})).status_code, 429)
        state = (await self.client.get(url, headers=headers)).json()
        self.assertEqual((state['status'], state['attempts_remaining']), ('exhausted', 0))

    async def test_challenge_email_otp_requires_verified_email(self):
        headers = self.headers(await self.login())
        self.assertEqual((await self.client.post('/api/challenges/email-otp', headers=headers)).status_code, 403)
        self.assertEqual(self.messages, [])

    async def test_challenge_email_delivery_failure_cancels_without_exposing_code(self):
        headers = self.headers(await self.login())
        async with self.database.transaction() as session:
            await session.execute(update(User).where(User.user_id == self.user.user_id).values(verified_at=datetime.now(UTC)))
        delivered = []

        async def broken(**message):
            delivered.append(message['token'])
            raise RuntimeError('private provider diagnostic')

        main.app.state.identity_email_delivery = broken
        response = await self.client.post('/api/challenges/email-otp', headers=headers)
        self.assertEqual(response.status_code, 503, response.text)
        self.assertNotIn(delivered[0], response.text)
        self.assertNotIn('private provider diagnostic', response.text)
        async with self.database.session() as session:
            row = await session.scalar(select(AuthChallenge))
            self.assertIsNotNone(row.cancelled_at)

    async def test_challenge_otp_resend_limit_applies_across_sessions(self):
        headers = self.headers(await self.login())
        await self.email_challenge(headers)
        second = self.headers(await self.login())
        response = await self.client.post('/api/challenges/email-otp', headers=second)
        self.assertEqual(response.status_code, 429, response.text)
        self.assertGreater(int(response.headers['retry-after']), 0)
        self.assertEqual(len(self.messages), 1)

    async def test_challenge_expiry_and_revoked_sessions(self):
        tokens = await self.login()
        headers = self.headers(tokens)
        response, code = await self.email_challenge(headers)
        async with self.database.transaction() as session:
            await session.execute(update(AuthChallenge).values(expires_at=datetime.now(UTC) - timedelta(seconds=1)))
        response = await self.client.post(response.headers['location'] + '/verify', headers=headers,
            json={'method': 'email_otp', 'code': code})
        self.assertEqual(response.status_code, 410, response.text)
        await self.db.revoke_session(UUID(tokens['session_id']))
        self.assertEqual((await self.client.get('/api/challenges/mfa', headers=headers)).status_code, 401)

    async def test_challenge_passkey_enrollment_and_real_assertion(self):
        headers = self.headers(await self.login())
        private_key, credential_id = await self.enroll_test_passkey(headers)
        async with self.database.transaction() as session:
            await session.execute(update(AuthChallenge).where(AuthChallenge.purpose == ChallengePurpose.EMAIL_OTP)
                .values(verified_at=datetime.now(UTC) - timedelta(seconds=301)))
        self.assertIsNone((await self.client.get('/api/challenges/mfa', headers=headers)).json()['method'])
        with patch.dict(os.environ, WEBAUTHN_RP_ID='identity.test', WEBAUTHN_RP_NAME='Identity', WEBAUTHN_ORIGIN='https://identity.test'):
            denied = await self.client.post('/api/challenges/passkey-registration', headers=headers,
                json={'current_password': PASSWORD})
        self.assertEqual(denied.status_code, 403, denied.text)
        challenge = await self.authentication_challenge(headers)
        options = challenge['public_key']
        self.assertEqual(options['userVerification'], 'required')
        self.assertEqual(options['allowCredentials'][0]['id'], bytes_to_base64url(credential_id))
        credential = self.assertion_credential(options, private_key, credential_id, self.user.user_id)
        response = await self.client.post(f"/api/challenges/{challenge['challenge_id']}/verify", headers=headers,
            json={'method': 'passkey_authentication', 'credential': credential})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertIsNotNone(response.json()['mfa_expires_at'])
        async with self.database.session() as session:
            key = await session.get(Passkey, credential_id)
            self.assertEqual(key.sign_count, 1)
            self.assertIsNotNone(key.last_used_at)
        status = (await self.client.get('/api/challenges/mfa', headers=headers)).json()
        self.assertEqual(status['method'], 'passkey_authentication')
        next_registration = await self.registration_challenge(headers)
        self.assertEqual(next_registration['public_key']['excludeCredentials'][0]['id'], bytes_to_base64url(credential_id))
        self.assertEqual(next_registration['public_key']['excludeCredentials'][0]['transports'], [])
        changed = await self.client.post('/api/auth/password/change', headers=headers, json={'new_password': NEW_PASSWORD})
        self.assertEqual(changed.status_code, 204, changed.text)
        self.assertEqual((await self.client.get('/api/users/me', headers=headers)).status_code, 401)

    async def test_challenge_passkey_options_require_completed_challenge(self):
        headers = self.headers(await self.login())
        with patch.dict(os.environ, WEBAUTHN_RP_ID='identity.test', WEBAUTHN_RP_NAME='Identity', WEBAUTHN_ORIGIN='https://identity.test'):
            wrong = await self.client.post('/api/challenges/passkey-registration', headers=headers,
                json={'current_password': 'wrong'})
        self.assertEqual(wrong.status_code, 403)
        await self.complete_mfa(headers)
        challenge = await self.registration_challenge(headers)
        options = challenge['public_key']
        self.assertEqual(base64url_to_bytes(options['user']['id']), self.user.user_id.bytes)
        self.assertEqual(len(base64url_to_bytes(options['challenge'])), 64)
        self.assertEqual(options['authenticatorSelection']['userVerification'], 'required')
        self.assertEqual(options['authenticatorSelection']['residentKey'], 'required')
        second = await self.registration_challenge(headers)
        self.assertNotEqual(options['challenge'], second['public_key']['challenge'])
        first_status = (await self.client.get(f"/api/challenges/{challenge['challenge_id']}", headers=headers)).json()
        self.assertEqual(first_status['status'], 'cancelled')

    async def test_challenge_enrollment_rechecks_mfa_before_completion(self):
        first_headers = self.headers(await self.login())
        second_headers = self.headers(await self.login())
        proof = await self.complete_mfa(second_headers)
        pending = await self.registration_challenge(second_headers)
        async with self.database.transaction() as session:
            await session.execute(update(AuthChallenge).where(AuthChallenge.purpose == ChallengePurpose.EMAIL_OTP)
                .values(created_at=datetime.now(UTC) - timedelta(seconds=61)))
        await self.enroll_test_passkey(first_headers)
        async with self.database.transaction() as session:
            await session.execute(update(AuthChallenge).where(AuthChallenge.challenge_id == UUID(proof['challenge_id']))
                .values(verified_at=datetime.now(UTC) - timedelta(seconds=301)))
        credential = self.registration_credential(pending['public_key'], ec.generate_private_key(ec.SECP256R1()), secrets.token_bytes(32))
        response = await self.client.post(f"/api/challenges/{pending['challenge_id']}/verify", headers=second_headers,
            json={'method': 'passkey_registration', 'credential': credential})
        self.assertEqual(response.status_code, 403, response.text)

    async def test_challenge_passkey_registration_checks_origin_challenge_and_verification(self):
        headers = self.headers(await self.login())
        await self.complete_mfa(headers)
        challenge = await self.registration_challenge(headers)
        key, credential_id = ec.generate_private_key(ec.SECP256R1()), secrets.token_bytes(32)
        url = f"/api/challenges/{challenge['challenge_id']}/verify"
        for changes in ({'origin': 'https://other.test'}, {'challenge': bytes_to_base64url(b'unexpected')},
                        {'flags': 0x41}, {'cross_origin': True}):
            credential = self.registration_credential(challenge['public_key'], key, credential_id, **changes)
            response = await self.client.post(url, headers=headers, json={'method': 'passkey_registration', 'credential': credential})
            self.assertEqual(response.status_code, 400, response.text)
        credential = self.registration_credential(challenge['public_key'], key, credential_id)
        response = await self.client.post(url, headers=headers, json={'method': 'passkey_registration', 'credential': credential})
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual((await self.client.post(url, headers=headers,
            json={'method': 'passkey_registration', 'credential': credential})).status_code, 409)

    async def test_challenge_passkey_assertion_rejects_bad_signature_and_counter_reuse(self):
        headers = self.headers(await self.login())
        key, credential_id = await self.enroll_test_passkey(headers)
        first = await self.authentication_challenge(headers)
        credential = self.assertion_credential(first['public_key'], key, credential_id, self.user.user_id)
        url = f"/api/challenges/{first['challenge_id']}/verify"
        bad = self.assertion_credential(first['public_key'], ec.generate_private_key(ec.SECP256R1()), credential_id, self.user.user_id)
        self.assertEqual((await self.client.post(url, headers=headers,
            json={'method': 'passkey_authentication', 'credential': bad})).status_code, 400)
        self.assertEqual((await self.client.post(url, headers=headers,
            json={'method': 'passkey_authentication', 'credential': credential})).status_code, 200)
        second = await self.authentication_challenge(headers)
        stale = self.assertion_credential(second['public_key'], key, credential_id, self.user.user_id, counter=1)
        response = await self.client.post(f"/api/challenges/{second['challenge_id']}/verify", headers=headers,
            json={'method': 'passkey_authentication', 'credential': stale})
        self.assertEqual(response.status_code, 400, response.text)

    async def test_challenge_passkey_configuration_and_missing_credentials(self):
        headers = self.headers(await self.login())
        for rp, origin in (('', ''), ('identity.test', 'https://other.test'), ('identity.test', 'http://identity.test'),
                           ('https://identity.test', 'https://identity.test'), ('127.0.0.1', 'https://127.0.0.1')):
            with patch.dict(os.environ, WEBAUTHN_RP_ID=rp, WEBAUTHN_ORIGIN=origin):
                response = await self.client.post('/api/challenges/passkey-authentication', headers=headers)
            self.assertEqual(response.status_code, 503, response.text)
        with patch.dict(os.environ, WEBAUTHN_RP_ID='identity.test', WEBAUTHN_ORIGIN='https://identity.test'):
            response = await self.client.post('/api/challenges/passkey-authentication', headers=headers)
        self.assertEqual(response.status_code, 409, response.text)

    async def test_challenge_problem_details_http_semantics_and_validation_redaction(self):
        response = await self.client.post('/api/challenges/email-otp')
        self.assertEqual(response.status_code, 401)
        self.assertEqual(response.headers['www-authenticate'], 'Bearer')
        self.assertEqual(response.headers['content-type'], 'application/problem+json')
        self.assertEqual(response.json()['type'], 'about:blank')
        self.assertEqual(response.json()['status'], 401)
        self.assertTrue(response.json()['instance'].startswith('urn:uuid:'))
        headers = self.headers(await self.login())
        response = await self.client.post(f'/api/challenges/{uuid4()}/verify', headers=headers,
            json={'method': 'email_otp', 'code': 'secret-value'})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn('secret-value', response.text)
        self.assertIn('errors', response.json())
        for body in ({'method': 'secret-value'}, {'method': 'email_otp', 'code': '123456', 'secret-value': True}):
            response = await self.client.post(f'/api/challenges/{uuid4()}/verify', headers=headers, json=body)
            self.assertEqual(response.status_code, 422, response.text)
            self.assertNotIn('secret-value', response.text)
        for method, path, expected in (('get', '/api/challenges/no/such/route', 404),
                                        ('post', '/api/challenges/mfa', 405)):
            response = await getattr(self.client, method)(path, headers=headers)
            self.assertEqual(response.status_code, expected)
            self.assertEqual(response.json()['status'], expected)
            self.assertEqual(response.headers['content-type'], 'application/problem+json')
        self.assertIn('GET', response.headers['allow'])
        response = await self.client.post('/api/challenges/email-otp', headers={**headers, 'Content-Type': 'text/plain'}, content='x')
        self.assertEqual(response.status_code, 415)

    async def test_challenge_openapi_has_typed_requests_problems_and_headers(self):
        main.app.openapi_schema = None
        schema = main.app.openapi()
        create = schema['paths']['/api/challenges/passkey-registration']['post']
        self.assertIn('Location', create['responses']['201']['headers'])
        self.assertEqual(create['security'], [{'HTTPBearer': []}])
        self.assertEqual(list(create['responses']['422']['content']), ['application/problem+json'])
        self.assertIn('WWW-Authenticate', create['responses']['401']['headers'])
        self.assertIn('Retry-After', create['responses']['429']['headers'])
        verify = schema['paths']['/api/challenges/{challenge_id}/verify']['post']
        body = verify['requestBody']['content']['application/json']['schema']
        self.assertEqual(body['discriminator']['propertyName'], 'method')
        self.assertEqual(len(body['oneOf']), 3)

    async def test_sensitive_endpoint_contracts_use_challenges_instead_of_password_confirmation(self):
        main.app.openapi_schema = None
        schema = main.app.openapi()
        password = schema['components']['schemas']['PasswordChangeRequest']
        self.assertEqual(password['required'], ['new_password'])
        self.assertEqual(list(password['properties']), ['new_password'])
        for path in ('/api/challenges/passkey-registration', '/api/users/me/emails/{email_id}/primary'):
            self.assertNotIn('requestBody', schema['paths'][path]['post'])
        for path, operations in schema['paths'].items():
            for method, operation in operations.items():
                sensitive = (path == '/api/auth/password/change'
                    or path.startswith('/api/users/me/emails') and method in {'post', 'delete'} and not path.endswith('/verification')
                    or path.startswith(('/api/roles', '/api/permissions')) and method in {'post', 'patch', 'put', 'delete'}
                    or path.startswith('/api/users/{user_id}') and method in {'patch', 'put', 'delete'})
                if sensitive:
                    with self.subTest(method=method, path=path):
                        self.assertIn('application/problem+json', operation['responses']['403']['content'])

    async def test_challenge_recent_mfa_guard_and_expiry(self):
        from identity.api.challenges.dependencies import RecentMfaDep

        async def protected(principal: RecentMfaDep):
            return {'user_id': str(principal.user.user_id)}

        main.app.add_api_route('/api/test-recent-mfa', protected, methods=['GET'])
        route = main.app.routes[-1]
        try:
            headers = self.headers(await self.login())
            self.assertEqual((await self.client.get('/api/test-recent-mfa', headers=headers)).status_code, 403)
            response, code = await self.email_challenge(headers)
            self.assertEqual((await self.client.post(response.headers['location'] + '/verify', headers=headers,
                json={'method': 'email_otp', 'code': code})).status_code, 200)
            self.assertEqual((await self.client.get('/api/test-recent-mfa', headers=headers)).status_code, 200)
            async with self.database.transaction() as session:
                await session.execute(update(AuthChallenge).values(verified_at=datetime.now(UTC) - timedelta(seconds=301)))
            self.assertEqual((await self.client.get('/api/test-recent-mfa', headers=headers)).status_code, 403)
        finally:
            main.app.routes.remove(route)

    async def test_challenge_concurrent_otp_verification_has_one_winner(self):
        if self.async_engine is None:
            self.skipTest('requires PostgreSQL row locking')
        headers = self.headers(await self.login())
        response, code = await self.email_challenge(headers)
        responses = await asyncio.gather(*[self.client.post(response.headers['location'] + '/verify', headers=headers,
            json={'method': 'email_otp', 'code': code}) for _ in range(2)])
        self.assertEqual(sorted(row.status_code for row in responses), [200, 409])


if __name__ == '__main__':
    unittest.main(verbosity=2)
