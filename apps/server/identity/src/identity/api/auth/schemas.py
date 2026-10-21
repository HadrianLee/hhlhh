from datetime import datetime
from typing import Annotated, Literal
from uuid import UUID

from pydantic import BaseModel, ConfigDict, EmailStr, Field, SecretStr, field_validator


NewPassword = Annotated[
    SecretStr,
    Field(min_length=8, description="At least eight characters. No character-composition requirements."),
]


class InputModel(BaseModel):
    model_config = ConfigDict(extra="forbid", str_strip_whitespace=False)

    @field_validator("*")
    @classmethod
    def validate_text(cls, value):
        text = value.get_secret_value() if isinstance(value, SecretStr) else value
        if isinstance(text, str):
            try:
                text.encode("utf-8")
            except UnicodeEncodeError as exc:
                raise ValueError("valid Unicode text is required") from exc
            if not isinstance(value, SecretStr) and "\x00" in text:
                raise ValueError("null characters are not allowed")
        return value


class LoginRequest(InputModel):
    email: EmailStr
    password: SecretStr = Field(min_length=1)


class LoginResponse(BaseModel):
    access_token: str
    refresh_token: str
    token_type: Literal["bearer"] = "bearer"
    expires_in: int
    session_id: UUID
    refresh_expires_at: datetime


class RegisterRequest(InputModel):
    email: EmailStr
    username: str = Field(min_length=1, max_length=120, pattern=r"^\S(?:.*\S)?$")
    password: NewPassword


class RefreshRequest(InputModel):
    refresh_token: SecretStr = Field(min_length=1, max_length=512)


class EmailRequest(InputModel):
    email: EmailStr


class TokenRequest(InputModel):
    token: SecretStr = Field(min_length=1, max_length=512)


class PasswordResetRequest(TokenRequest):
    new_password: NewPassword


class PasswordChangeRequest(InputModel):
    new_password: NewPassword


class MessageResponse(BaseModel):
    message: str


class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    user_id: UUID
    email: EmailStr
    username: str
    verified_at: datetime | None
    created_at: datetime
    updated_at: datetime


class UserUpdateRequest(InputModel):
    username: str = Field(min_length=1, max_length=120, pattern=r"^\S(?:.*\S)?$")


class SessionResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    session_id: UUID
    created_at: datetime
    expires_at: datetime
    last_used_at: datetime | None
    revoked_at: datetime | None


class SecondaryEmailResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)
    secondary_email_id: UUID
    email: EmailStr
    is_verified: bool
    verified_at: datetime | None
    created_at: datetime
