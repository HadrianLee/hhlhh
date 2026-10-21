from uuid import UUID

from identity.core.key_manager import KeyManager


def sign_access_token(
    key_manager: KeyManager,
    *,
    user_id: UUID,
    session_id: UUID | None = None,
) -> str:
    """Issue an identity token for a user already authenticated by the caller."""
    if not isinstance(user_id, UUID):
        raise ValueError("user_id must be a UUID")
    payload = {"sub": str(user_id)}
    if session_id is not None:
        if not isinstance(session_id, UUID):
            raise ValueError("session_id must be a UUID")
        payload["sid"] = str(session_id)
    return key_manager.sign(payload)
