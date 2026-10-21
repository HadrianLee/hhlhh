import asyncio
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
import hmac
import json
from uuid import UUID

from sqlalchemy import delete, select
from webauthn import generate_authentication_options, options_to_json, verify_authentication_response
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import UserVerificationRequirement

from auth_token.exceptions import AuthenticationError
from identity.core.challenges import CHALLENGE_TTL_SECONDS, PasskeySettings
from identity.db.models.challenge import AuthChallenge, ChallengePurpose, Passkey, PasskeyLoginChallenge
from identity.db.models.identity import User, UserSession
from .base import Database
from .identity import _as_utc


class PasskeyLoginDbService:
    def __init__(self, database: Database):
        self.db = database

    async def options(self, browser_binding: str):
        settings = PasskeySettings.from_env()
        options = generate_authentication_options(
            rp_id=settings.rp_id, timeout=CHALLENGE_TTL_SECONDS * 1000,
            user_verification=UserVerificationRequirement.REQUIRED,
        )
        now = datetime.now(UTC)
        async with self.db.transaction() as session:
            await session.execute(delete(PasskeyLoginChallenge).where(PasskeyLoginChallenge.expires_at <= now))
            row = PasskeyLoginChallenge(challenge=options.challenge, browser_binding=browser_binding,
                rp_id=settings.rp_id, origin=settings.origin, expires_at=now + timedelta(seconds=CHALLENGE_TTL_SECONDS))
            session.add(row)
            await session.flush()
            return {"challenge_id": row.challenge_id, "public_key": json.loads(options_to_json(options))}

    async def authenticate(self, challenge_id: UUID, browser_binding: str, credential: dict,
                           make_session: Callable[[User], UserSession]) -> None:
        failure = None
        async with self.db.transaction() as session:
            row = await session.get(PasskeyLoginChallenge, challenge_id, with_for_update=True)
            now = datetime.now(UTC)
            if (row is None or row.consumed_at is not None or _as_utc(row.expires_at) <= now
                    or row.attempts_remaining == 0 or not hmac.compare_digest(row.browser_binding, browser_binding)):
                raise AuthenticationError("Passkey sign-in could not be verified")
            row.attempts_remaining -= 1
            try:
                if credential["id"] != credential["rawId"]:
                    raise ValueError("credential IDs differ")
                credential_id = base64url_to_bytes(credential["rawId"])
                user_id = await session.scalar(select(Passkey.user_id).where(Passkey.credential_id == credential_id))
                user = await session.get(User, user_id, with_for_update=True) if user_id else None
                key = await session.get(Passkey, credential_id, with_for_update=True)
                if (user is None or user.is_banned or key is None
                        or key.user_id != user.user_id or key.rp_id != row.rp_id):
                    raise ValueError("credential is unavailable")
                handle = credential["response"].get("userHandle")
                if handle is None or not hmac.compare_digest(base64url_to_bytes(handle), user.user_id.bytes):
                    raise ValueError("unexpected user handle")
                client_data = json.loads(base64url_to_bytes(credential["response"]["clientDataJSON"]))
                if (not isinstance(client_data, dict) or client_data.get("crossOrigin", False) is not False
                        or "topOrigin" in client_data):
                    raise ValueError("cross-origin ceremony is not permitted")
                verified = await asyncio.to_thread(verify_authentication_response,
                    credential=credential, expected_challenge=row.challenge, expected_rp_id=row.rp_id,
                    expected_origin=row.origin, credential_public_key=key.public_key,
                    credential_current_sign_count=key.sign_count, require_user_verification=True)
                if verified.credential_device_type.value != key.device_type:
                    raise ValueError("credential backup eligibility changed")
            except (WebAuthnException, ValueError, TypeError, KeyError):
                failure = AuthenticationError("Passkey sign-in could not be verified")
            if failure is None:
                # Signing and session creation share this transaction with consuming
                # the challenge and advancing the credential's signature counter.
                login = make_session(user)
                session.add(login)
                await session.flush()
                key.sign_count = verified.new_sign_count
                key.backed_up = verified.credential_backed_up
                key.last_used_at = now
                row.consumed_at = now
                session.add(AuthChallenge(user_id=user.user_id, session_id=login.session_id,
                    purpose=ChallengePurpose.PASSKEY_AUTHENTICATION, challenge=row.challenge,
                    rp_id=row.rp_id, origin=row.origin, expires_at=row.expires_at,
                    verified_at=now, attempts_remaining=4))
            await session.flush()
        if failure is not None:
            raise failure
