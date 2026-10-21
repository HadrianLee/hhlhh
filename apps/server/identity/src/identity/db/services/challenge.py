import asyncio
from datetime import UTC, datetime, timedelta
import hashlib
import hmac
import json
import math
import secrets
from typing import Any
from uuid import UUID, uuid4

from sqlalchemy import select, update
from webauthn import (
    generate_authentication_options, generate_registration_options, options_to_json,
    verify_authentication_response, verify_registration_response,
)
from webauthn.helpers import base64url_to_bytes
from webauthn.helpers.exceptions import WebAuthnException
from webauthn.helpers.structs import (
    AuthenticatorSelectionCriteria, PublicKeyCredentialDescriptor, ResidentKeyRequirement,
    UserVerificationRequirement,
)

from identity.core.challenges import CHALLENGE_TTL_SECONDS, MFA_TTL_SECONDS, ChallengeError, PasskeySettings
from identity.core.email_delivery import IdentityEmailDelivery
from identity.core.security import IdentitySecurity
from identity.db.models.challenge import AuthChallenge, ChallengePurpose, Passkey
from identity.db.models.identity import User, UserSession
from .base import Database
from .identity import _as_utc
from .security import require_recent_mfa


def challenge_response(row: AuthChallenge) -> dict[str, Any]:
    if row.cancelled_at is not None:
        status = "cancelled"
    elif row.verified_at is not None:
        status = "verified"
    elif _as_utc(row.expires_at) <= datetime.now(UTC):
        status = "expired"
    elif row.attempts_remaining == 0:
        status = "exhausted"
    else:
        status = "pending"
    return {
        "challenge_id": row.challenge_id, "purpose": row.purpose, "status": status,
        "expires_at": _as_utc(row.expires_at),
        "verified_at": _as_utc(row.verified_at) if row.verified_at else None,
        "attempts_remaining": row.attempts_remaining,
    }


class ChallengeDbService:
    def __init__(self, database: Database, security: IdentitySecurity, delivery: IdentityEmailDelivery):
        self.db = database
        self.security = security
        self.delivery = delivery

    async def _active(self, session, user_id: UUID, session_id: UUID) -> User:
        user = await session.get(User, user_id, with_for_update=True)
        login = await session.get(UserSession, session_id, with_for_update=True)
        if (user is None or user.is_banned or login is None or login.user_id != user_id
                or login.revoked_at is not None or _as_utc(login.expires_at) <= datetime.now(UTC)):
            raise ChallengeError(401, "The current session is no longer active")
        return user

    async def _insert(self, session, *, user_id, session_id, purpose, challenge=None, settings=None, otp_digest=None, challenge_id=None):
        await session.execute(update(AuthChallenge).where(
            AuthChallenge.user_id == user_id, AuthChallenge.session_id == session_id,
            AuthChallenge.purpose == purpose, AuthChallenge.verified_at.is_(None),
            AuthChallenge.cancelled_at.is_(None),
        ).values(cancelled_at=datetime.now(UTC)))
        row = AuthChallenge(
            challenge_id=challenge_id or uuid4(), user_id=user_id, session_id=session_id, purpose=purpose,
            challenge=challenge, otp_digest=otp_digest, rp_id=settings.rp_id if settings else None,
            origin=settings.origin if settings else None,
            expires_at=datetime.now(UTC) + timedelta(seconds=CHALLENGE_TTL_SECONDS),
        )
        session.add(row)
        await session.flush()
        return row

    async def _require_enrollment_mfa(self, session, user_id: UUID, session_id: UUID):
        return await require_recent_mfa(session, user_id, session_id)

    async def create_registration(self, user: User, session_id: UUID):
        settings = PasskeySettings.from_env()
        async with self.db.transaction() as session:
            user = await self._require_enrollment_mfa(session, user.user_id, session_id)
            credentials = list(await session.scalars(select(Passkey).where(
                Passkey.user_id == user.user_id, Passkey.rp_id == settings.rp_id,
            )))
            options = generate_registration_options(
                rp_id=settings.rp_id, rp_name=settings.rp_name, user_id=user.user_id.bytes,
                user_name=user.email, user_display_name=user.username, timeout=CHALLENGE_TTL_SECONDS * 1000,
                authenticator_selection=AuthenticatorSelectionCriteria(
                    resident_key=ResidentKeyRequirement.REQUIRED, user_verification=UserVerificationRequirement.REQUIRED,
                ),
                exclude_credentials=[PublicKeyCredentialDescriptor(id=row.credential_id) for row in credentials],
            )
            row = await self._insert(session, user_id=user.user_id, session_id=session_id,
                purpose=ChallengePurpose.PASSKEY_REGISTRATION, challenge=options.challenge, settings=settings)
            return {**challenge_response(row), "public_key": json.loads(options_to_json(options))}

    async def create_authentication(self, user_id: UUID, session_id: UUID):
        settings = PasskeySettings.from_env()
        async with self.db.transaction() as session:
            await self._active(session, user_id, session_id)
            credentials = list(await session.scalars(select(Passkey).where(
                Passkey.user_id == user_id, Passkey.rp_id == settings.rp_id,
            )))
            if not credentials:
                raise ChallengeError(409, "Enroll a passkey before requesting a passkey check")
            options = generate_authentication_options(
                rp_id=settings.rp_id, timeout=CHALLENGE_TTL_SECONDS * 1000,
                allow_credentials=[PublicKeyCredentialDescriptor(id=row.credential_id) for row in credentials],
                user_verification=UserVerificationRequirement.REQUIRED,
            )
            row = await self._insert(session, user_id=user_id, session_id=session_id,
                purpose=ChallengePurpose.PASSKEY_AUTHENTICATION, challenge=options.challenge, settings=settings)
            return {**challenge_response(row), "public_key": json.loads(options_to_json(options))}

    def _otp_digest(self, challenge_id: UUID, user: User, session_id: UUID, code: str) -> str:
        message = b"email-otp:v1:" + challenge_id.bytes + user.user_id.bytes + session_id.bytes + user.email.encode() + b"\x00" + code.encode()
        return hmac.new(self.security.settings.token_hmac_key, message, hashlib.sha256).hexdigest()

    async def create_email_otp(self, user_id: UUID, session_id: UUID):
        code = f"{secrets.randbelow(1_000_000):06d}"
        challenge_id = uuid4()
        async with self.db.transaction() as session:
            user = await self._active(session, user_id, session_id)
            if user.verified_at is None:
                raise ChallengeError(403, "Verify the primary email address before requesting an email OTP")
            latest = await session.scalar(select(AuthChallenge).where(
                AuthChallenge.user_id == user_id, AuthChallenge.purpose == ChallengePurpose.EMAIL_OTP,
            ).order_by(AuthChallenge.created_at.desc()).limit(1))
            if latest is not None:
                remaining = 60 - (datetime.now(UTC) - _as_utc(latest.created_at)).total_seconds()
                if remaining > 0:
                    raise ChallengeError(429, "An email OTP was recently requested", retry_after=math.ceil(remaining))
            row = await self._insert(session, user_id=user_id, session_id=session_id,
                purpose=ChallengePurpose.EMAIL_OTP, challenge_id=challenge_id,
                otp_digest=self._otp_digest(challenge_id, user, session_id, code))
            result = challenge_response(row)
            email = user.email
        try:
            await self.delivery(email=email, purpose="mfa_email_otp", token=code)
        except Exception as exc:
            async with self.db.transaction() as session:
                await session.execute(update(AuthChallenge).where(AuthChallenge.challenge_id == challenge_id)
                    .values(cancelled_at=datetime.now(UTC)))
            raise ChallengeError(503, "MFA email delivery is temporarily unavailable") from exc
        return result

    async def get(self, user_id: UUID, session_id: UUID, challenge_id: UUID):
        async with self.db.session() as session:
            row = await session.scalar(select(AuthChallenge).where(
                AuthChallenge.challenge_id == challenge_id, AuthChallenge.user_id == user_id,
                AuthChallenge.session_id == session_id,
            ))
            if row is None:
                raise ChallengeError(404, "Challenge not found")
            return challenge_response(row)

    async def _recent_mfa(self, session, user_id: UUID, session_id: UUID):
        return await session.scalar(select(AuthChallenge).where(
            AuthChallenge.user_id == user_id, AuthChallenge.session_id == session_id,
            AuthChallenge.purpose.in_([ChallengePurpose.EMAIL_OTP, ChallengePurpose.PASSKEY_AUTHENTICATION]),
            AuthChallenge.cancelled_at.is_(None),
            AuthChallenge.verified_at > datetime.now(UTC) - timedelta(seconds=MFA_TTL_SECONDS),
        ).order_by(AuthChallenge.verified_at.desc()).limit(1))

    async def mfa_status(self, user_id: UUID, session_id: UUID):
        async with self.db.session() as session:
            row = await self._recent_mfa(session, user_id, session_id)
            if row is None:
                return {"verified_at": None, "expires_at": None, "method": None}
            verified_at = _as_utc(row.verified_at)
            return {"verified_at": verified_at, "expires_at": verified_at + timedelta(seconds=MFA_TTL_SECONDS), "method": row.purpose}

    async def _verify_passkey(self, session, user: User, row: AuthChallenge, credential: dict[str, Any]):
        client_data = json.loads(base64url_to_bytes(credential["response"]["clientDataJSON"]))
        if not isinstance(client_data, dict) or client_data.get("crossOrigin", False) is not False or "topOrigin" in client_data:
            raise ValueError("cross-origin ceremony is not permitted")
        if row.purpose == ChallengePurpose.PASSKEY_REGISTRATION:
            verified = await asyncio.to_thread(verify_registration_response,
                credential=credential, expected_challenge=row.challenge, expected_rp_id=row.rp_id,
                expected_origin=row.origin, require_user_presence=True, require_user_verification=True)
            if await session.get(Passkey, verified.credential_id) is not None:
                raise ValueError("credential already enrolled")
            session.add(Passkey(
                credential_id=verified.credential_id, user_id=user.user_id, public_key=verified.credential_public_key,
                rp_id=row.rp_id, sign_count=verified.sign_count,
                device_type=verified.credential_device_type.value, backed_up=verified.credential_backed_up,
            ))
        else:
            key = await session.get(Passkey, base64url_to_bytes(credential["rawId"]), with_for_update=True)
            if key is None or key.user_id != user.user_id or key.rp_id != row.rp_id:
                raise ValueError("credential is not owned by this user")
            handle = credential["response"].get("userHandle")
            if handle is not None and base64url_to_bytes(handle) != user.user_id.bytes:
                raise ValueError("unexpected user handle")
            verified = await asyncio.to_thread(verify_authentication_response,
                credential=credential, expected_challenge=row.challenge, expected_rp_id=row.rp_id,
                expected_origin=row.origin, credential_public_key=key.public_key,
                credential_current_sign_count=key.sign_count, require_user_verification=True)
            if verified.credential_device_type.value != key.device_type:
                raise ValueError("credential backup eligibility changed")
            key.sign_count = verified.new_sign_count
            key.backed_up = verified.credential_backed_up
            key.last_used_at = datetime.now(UTC)

    async def verify(self, user_id: UUID, session_id: UUID, challenge_id: UUID, *, method: str, code: str | None = None, credential: dict[str, Any] | None = None):
        failure = None
        async with self.db.transaction() as session:
            user = await self._active(session, user_id, session_id)
            row = await session.scalar(select(AuthChallenge).where(
                AuthChallenge.challenge_id == challenge_id, AuthChallenge.user_id == user_id,
                AuthChallenge.session_id == session_id,
            ).with_for_update())
            if row is None:
                raise ChallengeError(404, "Challenge not found")
            if row.cancelled_at is not None or row.verified_at is not None:
                raise ChallengeError(409, "Challenge has already been completed or replaced")
            if _as_utc(row.expires_at) <= datetime.now(UTC):
                raise ChallengeError(410, "Challenge has expired")
            if row.attempts_remaining == 0:
                raise ChallengeError(429, "Challenge attempt limit reached; request a new challenge", retry_after=60)
            if method != row.purpose:
                raise ChallengeError(400, "Verification method does not match the challenge")
            if row.purpose == ChallengePurpose.PASSKEY_REGISTRATION:
                await self._require_enrollment_mfa(session, user_id, session_id)
            row.attempts_remaining -= 1
            try:
                if row.purpose == ChallengePurpose.EMAIL_OTP:
                    if user.verified_at is None or code is None or not hmac.compare_digest(
                        row.otp_digest, self._otp_digest(challenge_id, user, session_id, code),
                    ):
                        raise ValueError("incorrect OTP")
                else:
                    await self._verify_passkey(session, user, row, credential)
            except (WebAuthnException, ValueError, TypeError, KeyError):
                failure = ChallengeError(400, "Challenge response could not be verified")
                if row.attempts_remaining == 0:
                    failure = ChallengeError(429, "Challenge attempt limit reached; request a new challenge", retry_after=60)
            if failure is None:
                row.verified_at = datetime.now(UTC)
            await session.flush()
            result = challenge_response(row)
            result["mfa_expires_at"] = (
                _as_utc(row.verified_at) + timedelta(seconds=MFA_TTL_SECONDS)
                if row.verified_at and row.purpose != ChallengePurpose.PASSKEY_REGISTRATION else None
            )
        if failure is not None:
            raise failure
        return result
