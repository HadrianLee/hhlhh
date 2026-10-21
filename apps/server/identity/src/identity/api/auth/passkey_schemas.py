from typing import Annotated
from uuid import UUID
import re

from pydantic import Field, SecretStr, field_validator

from identity.api.auth.schemas import InputModel
from identity.api.challenges.schemas import AuthenticationCredential, AuthenticationOptions


class PasskeyOptionsRequest(InputModel):
    browser_binding: Annotated[SecretStr, Field(min_length=64, max_length=64)]

    @field_validator("browser_binding")
    @classmethod
    def hex_binding(cls, value):
        if re.fullmatch(r"[0-9a-f]{64}", value.get_secret_value()) is None:
            raise ValueError("browser binding must be 64 lowercase hexadecimal characters")
        return value


class PasskeyOptionsResponse(InputModel):
    challenge_id: UUID
    public_key: AuthenticationOptions


class PasskeyLoginRequest(PasskeyOptionsRequest):
    challenge_id: UUID
    credential: AuthenticationCredential
