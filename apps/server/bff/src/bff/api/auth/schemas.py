from datetime import datetime
from uuid import UUID
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr

from bff.db.models.session import BrowserSession


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class LoginRequest(InputModel):
    email: EmailStr
    password: SecretStr = Field(min_length=1)


class PasskeyAssertion(InputModel):
    clientDataJSON: str = Field(min_length=1, max_length=8192, pattern=r"^[A-Za-z0-9_-]+$")
    authenticatorData: str = Field(min_length=1, max_length=65536, pattern=r"^[A-Za-z0-9_-]+$")
    signature: str = Field(min_length=1, max_length=8192, pattern=r"^[A-Za-z0-9_-]+$")
    userHandle: str = Field(min_length=1, max_length=86, pattern=r"^[A-Za-z0-9_-]+$")


class PasskeyCredential(InputModel):
    id: str = Field(min_length=1, max_length=1364, pattern=r"^[A-Za-z0-9_-]+$")
    rawId: str = Field(min_length=1, max_length=1364, pattern=r"^[A-Za-z0-9_-]+$")
    type: Literal["public-key"]
    response: PasskeyAssertion
    authenticatorAttachment: Literal["platform", "cross-platform"] | None = None
    clientExtensionResults: dict[str, Any] = Field(default_factory=dict)


class PasskeyLoginRequest(InputModel):
    challenge_id: UUID
    credential: PasskeyCredential


class CsrfResponse(BaseModel):
    csrf_token: str


class SessionResponse(BaseModel):
    session_id: UUID
    created_at: datetime
    last_used_at: datetime
    expires_at: datetime
    revoked_at: datetime | None
    revoke_reason: str | None
    ip_address: str | None
    user_agent: str | None
    is_current: bool

    @classmethod
    def from_session(cls, row: BrowserSession, current_id: UUID) -> "SessionResponse":
        return cls(**{name: getattr(row, name) for name in cls.model_fields if name != "is_current"},
                   is_current=row.session_id == current_id)


class LoginResponse(CsrfResponse):
    pass


class EventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    event_id: UUID
    event_type: str
    reason: str | None
    created_at: datetime


class ProblemDetails(BaseModel):
    type: str = "about:blank"
    title: str
    status: int
    detail: str
    instance: str
