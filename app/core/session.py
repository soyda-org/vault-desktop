from dataclasses import dataclass


@dataclass(frozen=True)
class DesktopSession:
    identifier: str
    user_id: str
    device_id: str
    session_id: str
    access_token: str
    refresh_token: str
    token_type: str


class SessionStore:
    def __init__(self) -> None:
        self._current: DesktopSession | None = None

    @property
    def current(self) -> DesktopSession | None:
        return self._current

    def is_authenticated(self) -> bool:
        return self._current is not None

    def set_session(self, session: DesktopSession) -> None:
        self._current = session

    def clear(self) -> None:
        self._current = None
