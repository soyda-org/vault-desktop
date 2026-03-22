from __future__ import annotations

from dataclasses import dataclass, replace


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
        self.current: DesktopSession | None = None

    def set_session(self, session: DesktopSession) -> None:
        self.current = session

    def clear(self) -> None:
        self.current = None

    def is_authenticated(self) -> bool:
        return self.current is not None and bool(self.current.access_token)

    def rotate_tokens(
        self,
        *,
        access_token: str,
        refresh_token: str,
        token_type: str,
        session_id: str | None = None,
        user_id: str | None = None,
        device_id: str | None = None,
    ) -> DesktopSession | None:
        if self.current is None:
            return None

        self.current = replace(
            self.current,
            access_token=access_token,
            refresh_token=refresh_token,
            token_type=token_type,
            session_id=session_id or self.current.session_id,
            user_id=user_id or self.current.user_id,
            device_id=device_id or self.current.device_id,
        )
        return self.current
