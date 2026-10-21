from datetime import datetime
from typing import Annotated, Any, Literal
from uuid import UUID

from pydantic import BaseModel, Field, SecretStr, field_validator
from webauthn.helpers import base64url_to_bytes, bytes_to_base64url
from webauthn.helpers.structs import AuthenticatorTransport

from identity.api.auth.schemas import InputModel
from identity.db.models.challenge import ChallengePurpose

Base64Url = Annotated[str, Field(min_length=1, pattern=r"^[A-Za-z0-9_-]+$")]
Transport = AuthenticatorTransport


class ProblemDetails(BaseModel):
    type: str = Field(default="about:blank", json_schema_extra={"format": "uri-reference"})
    title: str
    status: int = Field(ge=400, le=599)
    detail: str
    instance: str = Field(json_schema_extra={"format": "uri-reference"})
    errors: list[dict[str, Any]] | None = None


class CredentialDescriptor(BaseModel):
    type: Literal["public-key"]
    id: Base64Url
    transports: list[Transport] = Field(default_factory=list)


class RelyingParty(BaseModel):
    id: str
    name: str


class PasskeyUser(BaseModel):
    id: Base64Url
    name: str
    displayName: str


class CredentialParameter(BaseModel):
    type: Literal["public-key"]
    alg: int


class AuthenticatorSelection(BaseModel):
    residentKey: Literal["required"]
    requireResidentKey: Literal[True]
    userVerification: Literal["required"]


class RegistrationOptions(BaseModel):
    rp: RelyingParty
    user: PasskeyUser
    challenge: Base64Url
    pubKeyCredParams: list[CredentialParameter]
    timeout: int
    excludeCredentials: list[CredentialDescriptor]
    authenticatorSelection: AuthenticatorSelection
    attestation: Literal["none"]


class AuthenticationOptions(BaseModel):
    challenge: Base64Url
    timeout: int
    rpId: str
    allowCredentials: list[CredentialDescriptor]
    userVerification: Literal["required"]


class ChallengeResponse(BaseModel):
    challenge_id: UUID
    purpose: ChallengePurpose
    status: Literal["pending", "verified", "expired", "exhausted", "cancelled"]
    expires_at: datetime
    verified_at: datetime | None
    attempts_remaining: int


class RegistrationChallengeResponse(ChallengeResponse):
    purpose: Literal[ChallengePurpose.PASSKEY_REGISTRATION]
    public_key: RegistrationOptions


class AuthenticationChallengeResponse(ChallengeResponse):
    purpose: Literal[ChallengePurpose.PASSKEY_AUTHENTICATION]
    public_key: AuthenticationOptions


class EmailOtpChallengeResponse(ChallengeResponse):
    purpose: Literal[ChallengePurpose.EMAIL_OTP]


class VerificationResponse(ChallengeResponse):
    mfa_expires_at: datetime | None


class MfaStatus(BaseModel):
    verified_at: datetime | None
    expires_at: datetime | None
    method: Literal["passkey_authentication", "email_otp"] | None


class CredentialInput(InputModel):
    id: Base64Url = Field(max_length=1364)
    rawId: Base64Url = Field(max_length=1364)
    type: Literal["public-key"]
    authenticatorAttachment: Literal["platform", "cross-platform"] | None = None
    clientExtensionResults: dict[str, Any] = Field(default_factory=dict)

    @field_validator("id", "rawId")
    @classmethod
    def canonical_id(cls, value):
        try:
            raw = base64url_to_bytes(value)
            if not raw or len(raw) > 1023 or bytes_to_base64url(raw) != value:
                raise ValueError("invalid credential ID")
        except ValueError as exc:
            raise ValueError("invalid credential ID") from exc
        return value


class AttestationResponse(InputModel):
    clientDataJSON: Base64Url = Field(max_length=8192)
    attestationObject: Base64Url = Field(max_length=65536)
    transports: list[Transport] | None = None
    authenticatorData: Base64Url | None = Field(default=None, max_length=65536)
    publicKey: Base64Url | None = Field(default=None, max_length=8192)
    publicKeyAlgorithm: int | None = None


class AssertionResponse(InputModel):
    clientDataJSON: Base64Url = Field(max_length=8192)
    authenticatorData: Base64Url = Field(max_length=65536)
    signature: Base64Url = Field(max_length=8192)
    userHandle: Base64Url | None = Field(default=None, max_length=86)


class RegistrationCredential(CredentialInput):
    response: AttestationResponse


class AuthenticationCredential(CredentialInput):
    response: AssertionResponse


class RegistrationVerification(InputModel):
    method: Literal["passkey_registration"]
    credential: RegistrationCredential


class AuthenticationVerification(InputModel):
    method: Literal["passkey_authentication"]
    credential: AuthenticationCredential


class EmailOtpVerification(InputModel):
    method: Literal["email_otp"]
    code: SecretStr = Field(min_length=6, max_length=6, json_schema_extra={"pattern": "^[0-9]{6}$"})

    @field_validator("code")
    @classmethod
    def six_digits(cls, value):
        if not all("0" <= char <= "9" for char in value.get_secret_value()):
            raise ValueError("a six-digit code is required")
        return value


VerificationRequest = Annotated[
    RegistrationVerification | AuthenticationVerification | EmailOtpVerification,
    Field(discriminator="method"),
]
