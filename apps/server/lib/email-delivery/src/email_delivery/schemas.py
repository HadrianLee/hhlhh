from pydantic import BaseModel, EmailStr, field_validator

class EmailRequest(BaseModel):
    fr: EmailStr
    to: EmailStr
    subject: str
    body: str
    is_html: bool = False

    @field_validator("subject")
    @classmethod
    def validate_subject(cls, value: str) -> str:
        if any(character in value for character in ("\r", "\n", "\x00")):
            raise ValueError("Email subject must not contain line breaks or null characters")
        return value
