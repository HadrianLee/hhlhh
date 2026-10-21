"""Cookie/session checks. Set BFF_TEST_DATABASE_URL for real PostgreSQL locks."""
import asyncio
from dataclasses import replace
from datetime import UTC, datetime, timedelta
import json
import os
from pathlib import Path
import sys
import unittest
from unittest.mock import patch
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "bff/src"))

from cryptography.fernet import Fernet
import httpx
from sqlalchemy import create_engine, event, select, text, update
from sqlalchemy.engine import make_url
from sqlalchemy.ext.asyncio import AsyncSession, async_sessionmaker, create_async_engine
from sqlalchemy.orm import Session

from bff.core.security import BffSettings, CSRF_COOKIE, SESSION_COOKIE
from bff.db.models import Base, BrowserSession, SessionEvent
from bff.db.services.base import Database
from bff.db.services.session import utcnow
from bff.main import create_app


class FakeIdentity:
    def __init__(self):
        self.users = {"user@example.com": uuid4(), "other@example.com": uuid4()}
        self.sessions = {}
        self.access = {}
        self.refresh_count = 0
        self.requests = []
        self.offline = False
        self.lose_refresh_response = False
        self.large_response = False
        self.redirect = False
        self.passkey_challenges = {}

    def issue(self, session_id):
        row = self.sessions[session_id]
        access = f"access-{session_id}-{uuid4()}"
        refresh = f"refresh-{session_id}-{uuid4()}"
        self.access[access] = session_id
        row["refresh"] = refresh
        return {"access_token": access, "refresh_token": refresh, "token_type": "bearer",
                "expires_in": 600, "session_id": session_id,
                "refresh_expires_at": (utcnow() + timedelta(days=30)).isoformat()}

    async def __call__(self, request):
        self.requests.append(request)
        if self.offline and request.url.host == "identity.test":
            raise httpx.ConnectError("synthetic offline", request=request)
        path = request.url.path
        if self.redirect:
            return httpx.Response(307, headers={"Location": "https://evil.test/collect"})
        body = json.loads(request.content) if request.content else {}
        if path == "/api/auth/passkey/options":
            challenge_id = str(uuid4())
            self.passkey_challenges[challenge_id] = body['browser_binding']
            return httpx.Response(201, json={'challenge_id': challenge_id, 'public_key': {
                'challenge': 'synthetic-challenge', 'rpId': 'bff.test', 'timeout': 300000,
                'allowCredentials': [], 'userVerification': 'required',
            }})
        if path == "/api/auth/passkey/login":
            challenge_id = body['challenge_id']
            if self.passkey_challenges.get(challenge_id) != body['browser_binding']:
                return httpx.Response(401, json={'detail': 'Passkey sign-in could not be verified'})
            self.passkey_challenges.pop(challenge_id)
            session_id = str(uuid4())
            self.sessions[session_id] = {'user_id': self.users['user@example.com'], 'revoked': False, 'mfa': True}
            return httpx.Response(200, json=self.issue(session_id))
        if path == "/api/auth/login":
            email = body.get("email")
            if email not in self.users or body.get("password") != "a sufficiently long password":
                return httpx.Response(401, json={"detail": "invalid email or password"})
            session_id = str(uuid4())
            self.sessions[session_id] = {"user_id": self.users[email], "revoked": False, "mfa": False}
            return httpx.Response(200, json=self.issue(session_id))
        if path == "/api/auth/refresh":
            self.refresh_count += 1
            await asyncio.sleep(0.03)
            match = next(((sid, row) for sid, row in self.sessions.items() if row["refresh"] == body.get("refresh_token")), None)
            if match is None or match[1]["revoked"]:
                return httpx.Response(401, json={"detail": "refresh reuse"})
            tokens = self.issue(match[0])
            if self.lose_refresh_response:
                raise httpx.ReadTimeout("synthetic response lost", request=request)
            return httpx.Response(200, json=tokens)
        token = request.headers.get("authorization", "").removeprefix("Bearer ")
        session_id = self.access.get(token)
        row = self.sessions.get(session_id)
        if row is None or row["revoked"]:
            return httpx.Response(401, json={"detail": "session is no longer active"})
        if request.url.host == "app.test":
            return httpx.Response(200, json={"headers": dict(request.headers), "body": body,
                                           "path": path, "query": str(request.url.query, "ascii")})
        if path == "/api/users/me":
            if self.large_response:
                return httpx.Response(200, json={"value": "x" * 5000})
            return httpx.Response(200, json={"user_id": str(row["user_id"]), "username": "from-identity"})
        if path == "/api/users/me/permissions":
            return httpx.Response(200, json=["identity.users.read"])
        if path == "/api/auth/logout":
            row["revoked"] = True
            return httpx.Response(204)
        if path == "/api/auth/logout-all":
            for other in self.sessions.values():
                if other["user_id"] == row["user_id"]:
                    other["revoked"] = True
            return httpx.Response(204)
        if path == "/api/roles":
            return httpx.Response(403, json={"detail": "identity permission required"})
        if path == "/api/challenges/email-otp":
            challenge_id = str(uuid4())
            return httpx.Response(201, json={"challenge_id": challenge_id},
                                  headers={"Location": "/api/challenges/" + challenge_id, "Set-Cookie": "upstream=never-forward"})
        if path.endswith("/verify") and path.startswith("/api/challenges/"):
            row["mfa"] = True
            return httpx.Response(200, json={"verified": True})
        if path == "/api/auth/password/change":
            if not row["mfa"]:
                return httpx.Response(403, json={"detail": "Complete a recent MFA challenge for this session"})
            for other in self.sessions.values():
                if other["user_id"] == row["user_id"]:
                    other["revoked"] = True
            return httpx.Response(204)
        return httpx.Response(404, json={"detail": "not found"})


class BffApiChecks(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.postgres = os.environ.get("BFF_TEST_DATABASE_URL")
        self.async_engine = None
        if self.postgres:
            url = make_url(self.postgres)
            if url.database != "bff_api_test" or url.host not in {"127.0.0.1", "localhost"}:
                raise ValueError("Tests require a disposable local bff_api_test database")
            self.async_engine = create_async_engine(url, hide_parameters=True)
            async with self.async_engine.begin() as connection:
                await connection.execute(text("CREATE SCHEMA IF NOT EXISTS bff"))
                await connection.run_sync(Base.metadata.drop_all)
                await connection.run_sync(Base.metadata.create_all)
            factory = async_sessionmaker(self.async_engine, expire_on_commit=False)
        else:
            self.engine = create_engine("sqlite://", execution_options={"schema_translate_map": {"bff": None}})

            @event.listens_for(self.engine, "connect")
            def foreign_keys(connection, _):
                connection.execute("PRAGMA foreign_keys=ON")

            Base.metadata.create_all(self.engine)
            engine = self.engine

            class SqliteSession(Session):
                def __init__(self, **kwargs):
                    kwargs["bind"] = engine
                    super().__init__(**kwargs)

            factory = async_sessionmaker(class_=AsyncSession, sync_session_class=SqliteSession, expire_on_commit=False)
        self.database = Database(factory)
        self.identity = FakeIdentity()
        self.settings = BffSettings(database_url=self.postgres or "postgresql+asyncpg://test:test@localhost/bff_api_test",
            public_origin="https://bff.test", identity_base_url="https://identity.test",
            session_hmac_key=b"test-only-bff-key-not-for-production-12345",
            token_encryption_keys=(Fernet.generate_key(),), upstreams={"app": "https://app.test"})
        self.upstream = httpx.AsyncClient(transport=httpx.MockTransport(self.identity))
        self.app = create_app(settings=self.settings, database=self.database, http_client=self.upstream)
        self.lifespan = self.app.router.lifespan_context(self.app)
        await self.lifespan.__aenter__()
        self.client = httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url="https://bff.test")

    async def asyncTearDown(self):
        await self.client.aclose()
        await self.lifespan.__aexit__(None, None, None)
        await self.upstream.aclose()
        if self.async_engine is not None:
            await self.async_engine.dispose()
        else:
            self.engine.dispose()

    async def csrf(self):
        response = await self.client.get("/api/auth/csrf")
        self.assertEqual(response.status_code, 200)
        return {"Origin": "https://bff.test", "X-CSRF-Token": response.json()["csrf_token"]}

    async def login(self, email="user@example.com"):
        headers = await self.csrf()
        response = await self.client.post("/api/auth/login", headers=headers,
            json={"email": email, "password": "a sufficiently long password"})
        self.assertEqual(response.status_code, 200, response.text)
        return response, {"Origin": "https://bff.test", "X-CSRF-Token": response.json()["csrf_token"]}

    async def expire_access(self):
        async with self.database.transaction() as session:
            await session.execute(update(BrowserSession).values(access_expires_at=utcnow() - timedelta(seconds=1)))

    @staticmethod
    def passkey_credential():
        return {'id': 'YQ', 'rawId': 'YQ', 'type': 'public-key', 'response': {
            'clientDataJSON': 'YQ', 'authenticatorData': 'YQ', 'signature': 'YQ', 'userHandle': 'YQ',
        }}

    async def test_passkey_login_sets_session_and_rotates_csrf_without_exposing_tokens(self):
        headers = await self.csrf()
        options = await self.client.post('/api/auth/passkey/options', headers=headers)
        self.assertEqual(options.status_code, 201, options.text)
        self.assertNotIn('browser_binding', options.text)
        payload = {'challenge_id': options.json()['challenge_id'], 'credential': self.passkey_credential()}
        response = await self.client.post('/api/auth/passkey/login', headers=headers, json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(set(response.json()), {'csrf_token'})
        self.assertNotEqual(response.json()['csrf_token'], headers['X-CSRF-Token'])
        self.assertIsNotNone(self.client.cookies.get(SESSION_COOKIE))
        self.assertIsNone(self.client.cookies.get(CSRF_COOKIE))
        self.assertEqual((await self.client.get('/api/auth/session')).status_code, 200)
        protected = await self.client.post('/api/identity/challenges/email-otp', headers={
            'Origin': 'https://bff.test', 'X-CSRF-Token': response.json()['csrf_token'],
        })
        self.assertEqual(protected.status_code, 201)

    async def test_passkey_login_is_bound_to_the_requesting_browser_and_requires_csrf(self):
        headers = await self.csrf()
        self.assertEqual((await self.client.post('/api/auth/passkey/options')).status_code, 403)
        options = await self.client.post('/api/auth/passkey/options', headers=headers)
        payload = {'challenge_id': options.json()['challenge_id'], 'credential': self.passkey_credential()}
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=self.app), base_url='https://bff.test') as other:
            csrf = (await other.get('/api/auth/csrf')).json()['csrf_token']
            rejected = await other.post('/api/auth/passkey/login', json=payload, headers={
                'Origin': 'https://bff.test', 'X-CSRF-Token': csrf,
            })
            self.assertEqual(rejected.status_code, 401, rejected.text)
            self.assertIsNone(other.cookies.get(SESSION_COOKIE))
        self.assertEqual((await self.client.post('/api/auth/passkey/login', headers=headers, json=payload)).status_code, 200)

    async def test_passkey_login_replaces_existing_session_and_blocks_binding_injection(self):
        _, headers = await self.login()
        old = (await self.client.get('/api/auth/session')).json()['session_id']
        options = await self.client.post('/api/auth/passkey/options', headers=headers)
        payload = {'challenge_id': options.json()['challenge_id'], 'credential': self.passkey_credential()}
        invalid = await self.client.post('/api/auth/passkey/login', headers=headers, json={**payload, 'browser_binding': 'attacker'})
        self.assertEqual(invalid.status_code, 422)
        response = await self.client.post('/api/auth/passkey/login', headers=headers, json=payload)
        self.assertEqual(response.status_code, 200, response.text)
        current = (await self.client.get('/api/auth/session')).json()['session_id']
        self.assertNotEqual(current, old)
        rows = (await self.client.get('/api/auth/sessions')).json()
        self.assertIsNotNone(next(row for row in rows if row['session_id'] == old)['revoked_at'])

    async def test_authentication_does_not_move_last_used_backward(self):
        await self.login()
        current = (await self.client.get('/api/auth/session')).json()
        last_used = datetime.fromisoformat(current['last_used_at']).replace(tzinfo=UTC)
        with patch('bff.services.session.utcnow', return_value=last_used - timedelta(seconds=1)):
            response = await self.client.get('/api/auth/session')
        self.assertEqual(response.status_code, 200, response.text)
        self.assertGreaterEqual(datetime.fromisoformat(response.json()['last_used_at']).replace(tzinfo=UTC), last_used)

    async def test_login_cookie_encryption_and_no_user_table(self):
        response, _ = await self.login()
        self.assertEqual(set(response.json()), {"csrf_token"})
        session_response = await self.client.get("/api/auth/session")
        self.assertEqual(session_response.status_code, 200)
        self.assertTrue(session_response.json()["is_current"])
        cookie = next(value for value in response.headers.get_list("set-cookie") if value.startswith(SESSION_COOKIE + "="))
        for flag in ("Secure", "HttpOnly", "SameSite=lax", "Path=/"):
            self.assertIn(flag, cookie)
        self.assertNotIn("Domain=", cookie)
        self.assertNotIn("access_token", response.text)
        self.assertNotIn("refresh_token", response.text)
        self.assertNotIn("identity_session_id", response.text)
        async with self.database.session() as session:
            row = await session.scalar(select(BrowserSession))
            self.assertNotEqual(row.cookie_digest, self.client.cookies.get(SESSION_COOKIE))
            self.assertNotIn(b"access-", row.access_token_encrypted)
            self.assertNotIn(b"refresh-", row.refresh_token_encrypted)
            events = list(await session.scalars(select(SessionEvent.event_type)))
            self.assertEqual(events, ["created"])
        self.assertEqual(set(Base.metadata.tables), {"bff.browser_sessions", "bff.session_events"})

    async def test_login_requires_origin_and_csrf_before_forwarding(self):
        body = {"email": "user@example.com", "password": "a sufficiently long password"}
        self.assertEqual((await self.client.post("/api/auth/login", json=body)).status_code, 403)
        headers = await self.csrf()
        headers["Origin"] = "https://evil.test"
        self.assertEqual((await self.client.post("/api/auth/login", json=body, headers=headers)).status_code, 403)
        self.assertFalse(self.identity.requests)

    async def test_csrf_binds_to_session_and_changes_after_login(self):
        old = await self.csrf()
        _, headers = await self.login()
        self.assertNotEqual(old["X-CSRF-Token"], headers["X-CSRF-Token"])
        self.assertEqual((await self.client.post("/api/auth/logout", headers=old)).status_code, 403)
        cookie = self.client.cookies.get(SESSION_COOKIE)
        for _ in range(2):
            response = await self.client.get("/api/auth/csrf")
            self.assertEqual(response.json()["csrf_token"], headers["X-CSRF-Token"])
            self.assertNotIn("set-cookie", response.headers)
            self.assertNotIn(CSRF_COOKIE, self.client.cookies)
            written = await self.client.post("/api/apps/app/api/items", json={"value": 1}, headers=headers)
            self.assertEqual(written.status_code, 200, written.text)
            self.assertEqual(self.client.cookies.get(SESSION_COOKIE), cookie)

    async def test_anonymous_csrf_is_stateless_and_uses_an_http_only_cookie(self):
        response = await self.client.get("/api/auth/csrf")
        self.assertEqual(response.status_code, 200)
        cookies = response.headers.get_list("set-cookie")
        self.assertEqual(len(cookies), 1)
        self.assertTrue(cookies[0].startswith(CSRF_COOKIE + "="))
        for flag in ("Secure", "HttpOnly", "SameSite=lax", "Path=/"):
            self.assertIn(flag, cookies[0])
        expected = self.app.state.security.csrf_token(self.client.cookies.get(CSRF_COOKIE), authenticated=False)
        self.assertEqual(response.json(), {"csrf_token": expected})
        self.assertEqual((await self.client.get("/api/auth/csrf")).json()["csrf_token"], expected)
        self.assertFalse(self.identity.requests)
        async with self.database.session() as session:
            self.assertIsNone(await session.scalar(select(BrowserSession)))
            self.assertIsNone(await session.scalar(select(SessionEvent)))

    async def test_csrf_survives_access_token_refresh_without_setting_cookies(self):
        _, headers = await self.login()
        cookie = self.client.cookies.get(SESSION_COOKIE)
        await self.expire_access()
        response = await self.client.get("/api/auth/csrf")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["csrf_token"], headers["X-CSRF-Token"])
        self.assertEqual(self.identity.refresh_count, 1)
        self.assertEqual(self.client.cookies.get(SESSION_COOKIE), cookie)
        self.assertNotIn("set-cookie", response.headers)
        self.assertNotIn(CSRF_COOKIE, self.client.cookies)

    async def test_relogin_rejects_the_previous_sessions_csrf_token(self):
        _, previous = await self.login()
        _, current = await self.login()
        self.assertNotEqual(previous["X-CSRF-Token"], current["X-CSRF-Token"])
        response = await self.client.post("/api/apps/app/api/items", json={}, headers=previous)
        self.assertEqual(response.status_code, 403)
        response = await self.client.post("/api/apps/app/api/items", json={}, headers=current)
        self.assertEqual(response.status_code, 200)

    async def test_csrf_rejects_a_valid_looking_unknown_session(self):
        forged = self.app.state.security.new_secret()
        self.client.cookies.set(SESSION_COOKIE, forged, domain="bff.test", path="/")
        response = await self.client.get("/api/auth/csrf")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(SESSION_COOKIE, self.client.cookies)
        self.assertIn(CSRF_COOKIE, self.client.cookies)
        self.assertNotEqual(response.json()["csrf_token"], self.app.state.security.csrf_token(forged, authenticated=True))
        # The stale session cookie must not prevent anonymous CSRF validation on login.
        logged_in = await self.client.post("/api/auth/login", json={"email": "user@example.com", "password": "a sufficiently long password"},
            headers={"Origin": "https://bff.test", "X-CSRF-Token": response.json()["csrf_token"]})
        self.assertEqual(logged_in.status_code, 200, logged_in.text)

    async def test_csrf_falls_back_for_revoked_sessions(self):
        _, headers = await self.login()
        cookie = self.client.cookies.get(SESSION_COOKIE)
        self.assertEqual((await self.client.post("/api/auth/logout", headers=headers)).status_code, 204)
        self.client.cookies.set(SESSION_COOKIE, cookie, domain="bff.test", path="/")
        response = await self.client.get("/api/auth/csrf")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(SESSION_COOKIE, self.client.cookies)
        self.assertIn(CSRF_COOKIE, self.client.cookies)
        self.assertNotEqual(response.json()["csrf_token"], headers["X-CSRF-Token"])

    async def test_csrf_falls_back_for_expired_sessions(self):
        _, headers = await self.login()
        async with self.database.transaction() as session:
            await session.execute(update(BrowserSession).values(created_at=utcnow() - timedelta(days=2), expires_at=utcnow() - timedelta(seconds=1)))
        response = await self.client.get("/api/auth/csrf")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(SESSION_COOKIE, self.client.cookies)
        self.assertIn(CSRF_COOKIE, self.client.cookies)
        self.assertNotEqual(response.json()["csrf_token"], headers["X-CSRF-Token"])

    async def test_csrf_falls_back_when_identity_rejects_refresh(self):
        _, headers = await self.login()
        for row in self.identity.sessions.values():
            row["revoked"] = True
        before = len(self.identity.requests)
        response = await self.client.get("/api/auth/csrf")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["csrf_token"], headers["X-CSRF-Token"])
        self.assertNotIn("set-cookie", response.headers)
        self.assertEqual(len(self.identity.requests), before)
        await self.expire_access()
        response = await self.client.get("/api/auth/csrf")
        self.assertEqual(response.status_code, 200)
        self.assertNotIn(SESSION_COOKIE, self.client.cookies)
        self.assertIn(CSRF_COOKIE, self.client.cookies)
        self.assertNotEqual(response.json()["csrf_token"], headers["X-CSRF-Token"])

    async def test_csrf_uses_the_local_session_during_an_identity_outage(self):
        _, headers = await self.login()
        before = len(self.identity.requests)
        self.identity.offline = True
        response = await self.client.get("/api/auth/csrf")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json()["csrf_token"], headers["X-CSRF-Token"])
        self.assertNotIn("set-cookie", response.headers)
        self.assertIn(SESSION_COOKIE, self.client.cookies)
        self.assertNotIn(CSRF_COOKIE, self.client.cookies)
        self.assertEqual(len(self.identity.requests), before)

    async def test_csrf_dependency_protects_writes_across_all_api_routers(self):
        await self.login()
        before = len(self.identity.requests)
        for method, path, body in (
            ("POST", "/api/auth/login", {"email": "user@example.com", "password": "a sufficiently long password"}),
            ("POST", "/api/auth/register", {}),
            ("POST", "/api/identity/challenges/email-otp", {}),
            ("POST", "/api/apps/app/api/items", {}),
            ("PUT", "/api/apps/app/api/items", {}),
            ("PATCH", "/api/identity/users/me", {"username": "changed"}),
            ("DELETE", f"/api/auth/sessions/{uuid4()}", None),
            ("POST", "/api/auth/logout", None),
        ):
            with self.subTest(method=method, path=path):
                response = await self.client.request(method, path, json=body, headers={"Origin": "https://bff.test"})
                self.assertEqual(response.status_code, 403, response.text)
        self.assertEqual(len(self.identity.requests), before)

    async def test_apps_router_enforces_csrf_when_mounted_without_the_parent_router(self):
        from fastapi import FastAPI
        from bff.api.apps.router import router
        from bff.exception_handlers import register_exception_handlers

        _, headers = await self.login()
        standalone = FastAPI()
        standalone.state.security = self.app.state.security
        standalone.state.session_service = self.app.state.session_service
        register_exception_handlers(standalone)
        standalone.include_router(router, prefix="/api/apps")
        async with httpx.AsyncClient(transport=httpx.ASGITransport(app=standalone), base_url="https://bff.test") as client:
            client.cookies.update(self.client.cookies)
            before = len(self.identity.requests)
            for method in ("POST", "PUT", "PATCH", "DELETE"):
                with self.subTest(method=method):
                    missing = await client.request(method, "/api/apps/app/api/items", json={}, headers={"Origin": "https://bff.test"})
                    self.assertEqual(missing.status_code, 403, missing.text)
                    wrong = await client.request(method, "/api/apps/app/api/items", json={}, headers={**headers, "X-CSRF-Token": "0" * 64})
                    self.assertEqual(wrong.status_code, 403, wrong.text)
            self.assertEqual(len(self.identity.requests), before)
            for method in ("POST", "PUT", "PATCH", "DELETE"):
                with self.subTest(method=method):
                    valid = await client.request(method, "/api/apps/app/api/items", json={}, headers=headers)
                    self.assertEqual(valid.status_code, 200, valid.text)
            read = await client.get("/api/apps/app/api/items")
            self.assertEqual(read.status_code, 200, read.text)

    async def test_proxy_identity_permissions_and_blocks_token_routes(self):
        await self.login()
        response = await self.client.get("/api/identity/users/me/permissions")
        self.assertEqual(response.json(), ["identity.users.read"])
        self.assertEqual(response.headers["cache-control"], "no-store")
        for path in ("auth/login", "auth/refresh", "auth/sessions", "auth/logout"):
            self.assertEqual((await self.client.get("/api/identity/" + path)).status_code, 404)
        self.assertEqual((await self.client.get("/api/identity/roles")).status_code, 403)

    async def test_proxy_strips_browser_credentials_and_preserves_query(self):
        _, headers = await self.login()
        response = await self.client.post("/api/apps/app/api/items?tag=a&tag=b", headers={**headers,
            "Authorization": "Bearer attacker-input", "X-User-ID": "attacker", "X-Forwarded-For": "attacker"}, json={"value": 1})
        self.assertEqual(response.status_code, 200, response.text)
        upstream = response.json()
        self.assertTrue(upstream["headers"]["authorization"].startswith("Bearer access-"))
        for header in ("cookie", "x-user-id", "x-forwarded-for", "x-csrf-token"):
            self.assertNotIn(header, upstream["headers"])
        self.assertEqual(upstream["query"], "tag=a&tag=b")
        self.assertEqual(upstream["body"], {"value": 1})
        self.assertEqual((await self.client.get("/api/apps/unknown/api/items")).status_code, 404)

    async def test_challenge_location_and_mfa_remain_owned_by_identity(self):
        _, headers = await self.login()
        response = await self.client.post("/api/identity/auth/password/change", json={"new_password": "long new password"}, headers=headers)
        self.assertEqual(response.status_code, 403)
        challenge = await self.client.post("/api/identity/challenges/email-otp", json={}, headers=headers)
        self.assertEqual(challenge.status_code, 201)
        self.assertEqual(challenge.headers["location"], "/api/identity/challenges/" + challenge.json()["challenge_id"])
        self.assertNotIn("set-cookie", challenge.headers)
        await self.client.post(challenge.headers["location"] + "/verify", json={"code": "123456"}, headers=headers)
        changed = await self.client.post("/api/identity/auth/password/change", json={"new_password": "long new password"}, headers=headers)
        self.assertEqual(changed.status_code, 204)
        self.assertEqual((await self.client.get("/api/auth/session")).status_code, 401)

    async def test_identity_revocation_is_applied_when_refresh_is_rejected(self):
        await self.login()
        for row in self.identity.sessions.values():
            row["revoked"] = True
        before = len(self.identity.requests)
        response = await self.client.get("/api/auth/session")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(self.identity.requests), before)
        await self.expire_access()
        response = await self.client.get("/api/auth/session")
        self.assertEqual(response.status_code, 401)
        self.assertEqual([request.url.path for request in self.identity.requests[before:]], ["/api/auth/refresh"])
        self.assertNotIn(SESSION_COOKIE, self.client.cookies)
        async with self.database.session() as session:
            row = await session.scalar(select(BrowserSession))
            self.assertIsNotNone(row.revoked_at)
            self.assertIsNone(row.refresh_token_encrypted)

    async def test_idle_expiry_is_committed(self):
        await self.login()
        async with self.database.transaction() as session:
            await session.execute(update(BrowserSession).values(created_at=utcnow() - timedelta(days=3), last_used_at=utcnow() - timedelta(days=2)))
        self.assertEqual((await self.client.get("/api/auth/session")).status_code, 401)
        async with self.database.session() as session:
            row = await session.scalar(select(BrowserSession))
            self.assertEqual(row.revoke_reason, "expired")

    async def test_refresh_rotation_is_automatic(self):
        await self.login()
        # Refresh before expiry, using expires_in-derived scheduling metadata.
        async with self.database.transaction() as session:
            await session.execute(update(BrowserSession).values(
                access_expires_at=utcnow() + timedelta(seconds=self.settings.refresh_margin_seconds / 2)))
        before = len(self.identity.requests)
        self.assertEqual((await self.client.get("/api/auth/session")).status_code, 200)
        self.assertEqual(self.identity.refresh_count, 1)
        self.assertEqual([(request.method, request.url.path) for request in self.identity.requests[before:]],
                         [("POST", "/api/auth/refresh")])
        async with self.database.session() as session:
            events = list(await session.scalars(select(SessionEvent.event_type)))
            self.assertIn("refreshed", events)

    async def test_valid_local_session_does_not_call_identity(self):
        await self.login()
        before = len(self.identity.requests)
        self.identity.offline = True
        for path in ("/api/auth/session", "/api/auth/sessions", "/api/auth/csrf"):
            response = await self.client.get(path)
            self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual(len(self.identity.requests), before)

    async def test_application_action_only_calls_the_downstream_service(self):
        _, headers = await self.login()
        before = len(self.identity.requests)
        self.identity.offline = True
        response = await self.client.post("/api/apps/app/api/items", headers=headers, json={"value": 1})
        self.assertEqual(response.status_code, 200, response.text)
        requests = self.identity.requests[before:]
        self.assertEqual([(request.method, request.url.host, request.url.path) for request in requests],
                         [("POST", "app.test", "/api/items")])
        self.assertTrue(response.json()["headers"]["authorization"].startswith("Bearer access-"))

    async def test_identity_gateway_only_calls_the_requested_endpoint(self):
        await self.login()
        before = len(self.identity.requests)
        response = await self.client.get("/api/identity/users/me/permissions")
        self.assertEqual(response.status_code, 200, response.text)
        self.assertEqual([request.url.path for request in self.identity.requests[before:]], ["/api/users/me/permissions"])

    async def test_parallel_refresh_uses_one_postgresql_lock(self):
        if not self.postgres:
            self.skipTest("Run with BFF_TEST_DATABASE_URL to verify PostgreSQL row locking")
        await self.login()
        await self.expire_access()
        responses = await asyncio.gather(*(self.client.get("/api/auth/session") for _ in range(6)))
        self.assertEqual([response.status_code for response in responses], [200] * 6)
        self.assertEqual(self.identity.refresh_count, 1)

    async def test_lost_refresh_response_revokes_local_session(self):
        await self.login()
        await self.expire_access()
        self.identity.lose_refresh_response = True
        self.assertEqual((await self.client.get("/api/auth/session")).status_code, 504)
        self.assertNotIn(SESSION_COOKIE, self.client.cookies)
        async with self.database.session() as session:
            row = await session.scalar(select(BrowserSession))
            self.assertIsNotNone(row.revoked_at)
            self.assertTrue(row.revocation_pending)
        self.assertEqual((await self.client.get("/api/auth/session")).status_code, 401)

    async def test_logout_queues_revocation_during_identity_outage(self):
        _, headers = await self.login()
        self.identity.offline = True
        self.assertEqual((await self.client.post("/api/auth/logout", headers=headers)).status_code, 204)
        self.assertNotIn(SESSION_COOKIE, self.client.cookies)
        async with self.database.session() as session:
            row = await session.scalar(select(BrowserSession))
            self.assertIsNotNone(row.revoked_at)
            self.assertTrue(row.revocation_pending)
        self.identity.offline = False
        await self.app.state.session_service.cleanup()
        self.assertTrue(all(row["revoked"] for row in self.identity.sessions.values()))
        async with self.database.session() as session:
            row = await session.scalar(select(BrowserSession))
            self.assertFalse(row.revocation_pending)
            self.assertIsNone(row.refresh_token_encrypted)

    async def test_logout_all_revokes_all_devices(self):
        first, _ = await self.login()
        first_cookie = self.client.cookies.get(SESSION_COOKIE)
        self.client.cookies.clear()
        _, headers = await self.login()
        self.assertEqual((await self.client.post("/api/auth/logout-all", headers=headers)).status_code, 204)
        self.assertTrue(all(row["revoked"] for row in self.identity.sessions.values()))
        self.client.cookies.set(SESSION_COOKIE, first_cookie, domain="bff.test", path="/")
        self.assertEqual((await self.client.get("/api/auth/session")).status_code, 401)

    async def test_session_tracking_and_ownership(self):
        await self.login()
        first_id = (await self.client.get("/api/auth/session")).json()["session_id"]
        self.client.cookies.clear()
        _, headers = await self.login("other@example.com")
        second_id = (await self.client.get("/api/auth/session")).json()["session_id"]
        sessions = await self.client.get("/api/auth/sessions")
        self.assertEqual([row["session_id"] for row in sessions.json()], [second_id])
        self.assertEqual((await self.client.get(f"/api/auth/sessions/{first_id}/events")).status_code, 404)
        self.assertEqual((await self.client.delete(f"/api/auth/sessions/{first_id}", headers=headers)).status_code, 404)
        events = await self.client.get(f"/api/auth/sessions/{second_id}/events")
        self.assertEqual(events.json()[0]["event_type"], "created")
        self.assertEqual((await self.client.delete(f"/api/auth/sessions/{second_id}", headers=headers)).status_code, 204)
        self.assertNotIn(SESSION_COOKIE, self.client.cookies)

    async def test_relogin_rotates_cookie_and_replaces_previous_session(self):
        await self.login()
        first_cookie = self.client.cookies.get(SESSION_COOKIE)
        await self.login()
        self.assertNotEqual(first_cookie, self.client.cookies.get(SESSION_COOKIE))
        async with self.database.session() as session:
            rows = list(await session.scalars(select(BrowserSession)))
            self.assertEqual(len(rows), 2)
            self.assertEqual(sum(row.revoked_at is not None for row in rows), 1)
        await self.app.state.session_service.cleanup()
        self.assertEqual(sum(row["revoked"] for row in self.identity.sessions.values()), 1)

    async def test_duplicate_cookie_and_wrong_methods_are_rejected(self):
        await self.login()
        value = self.client.cookies.get(SESSION_COOKIE)
        response = await self.client.get("/api/auth/session", headers={"Cookie": f"{SESSION_COOKIE}={value}; {SESSION_COOKIE}=other"})
        self.assertEqual(response.status_code, 400)
        response = await self.client.get("/api/identity/auth/password/change")
        self.assertEqual(response.status_code, 405)
        self.assertEqual(response.headers["allow"], "POST")

    async def test_validation_never_echoes_password(self):
        headers = await self.csrf()
        password = "sensitive-test-password" * 10
        response = await self.client.post("/api/auth/login", json={"email": "invalid", "password": password}, headers=headers)
        self.assertEqual(response.status_code, 422)
        self.assertNotIn(password, response.text)
        self.assertEqual(response.headers["content-type"], "application/problem+json")

    async def test_cross_site_csrf_fetch_is_rejected(self):
        response = await self.client.get("/api/auth/csrf", headers={"Sec-Fetch-Site": "cross-site"})
        self.assertEqual(response.status_code, 403)

    async def test_request_and_response_size_limits(self):
        _, headers = await self.login()
        security = self.app.state.security
        security.settings = replace(self.settings, max_request_bytes=100, max_response_bytes=1000)
        self.app.state.session_service.identity.settings = security.settings
        response = await self.client.post("/api/identity/challenges/email-otp", content=b"x" * 101,
            headers={**headers, "Content-Type": "application/json"})
        self.assertEqual(response.status_code, 413)
        self.identity.large_response = True
        response = await self.client.get("/api/identity/users/me")
        self.assertEqual(response.status_code, 502)

    async def test_ciphertext_cannot_be_moved_between_sessions(self):
        await self.login()
        async with self.database.transaction() as session:
            row = await session.scalar(select(BrowserSession))
            row.identity_session_id = uuid4()
        self.assertEqual((await self.client.get("/api/auth/session")).status_code, 401)

    async def test_readiness_and_openapi_have_cookie_auth(self):
        self.assertEqual((await self.client.get("/health")).status_code, 200)
        self.assertEqual((await self.client.get("/ready")).status_code, 200)
        schema = (await self.client.get("/openapi.json")).json()
        self.assertEqual(schema["components"]["securitySchemes"]["APIKeyCookie"]["in"], "cookie")
        self.assertNotIn("HTTPBearer", schema["components"]["securitySchemes"])
        operations = [operation for path in schema["paths"].values() for operation in path.values()]
        ids = [operation["operationId"] for operation in operations]
        self.assertEqual(len(ids), len(set(ids)))
        login = schema["paths"]["/api/auth/login"]["post"]
        self.assertTrue(any(p["name"] == "X-CSRF-Token" and p["required"] for p in login["parameters"]))
        self.assertEqual(set(schema["components"]["schemas"]["LoginResponse"]["properties"]), {"csrf_token"})

    async def test_redirects_are_not_followed_or_exposed(self):
        await self.login()
        before = len(self.identity.requests)
        self.identity.redirect = True
        response = await self.client.get("/api/identity/users/me")
        self.assertEqual(response.status_code, 502)
        self.assertNotIn("location", response.headers)
        self.assertEqual(len(self.identity.requests), before + 1)

    async def test_identity_cannot_be_registered_as_an_application_upstream(self):
        with self.assertRaises(ValueError):
            replace(self.settings, upstreams={"identity": "https://identity.test"})

    async def test_public_session_uuid_is_not_a_cookie_credential(self):
        await self.login()
        session_id = (await self.client.get("/api/auth/session")).json()["session_id"]
        self.client.cookies.clear()
        self.client.cookies.set(SESSION_COOKIE, session_id, domain="bff.test", path="/")
        self.assertEqual((await self.client.get("/api/auth/session")).status_code, 401)


if __name__ == "__main__":
    unittest.main()
