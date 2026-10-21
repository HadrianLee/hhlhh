class BffError(Exception):
    def __init__(self, status_code: int, detail: str, *, clear_session: bool = False, headers: dict[str, str] | None = None):
        self.status_code = status_code
        self.detail = detail
        self.clear_session = clear_session
        self.headers = headers or {}
        super().__init__(detail)


class SessionInvalidError(BffError):
    def __init__(self, detail: str = "Sign in again"):
        super().__init__(401, detail, clear_session=True)
