from app.core.session import DesktopSession, SessionStore


def test_session_store_starts_empty() -> None:
    store = SessionStore()

    assert store.current is None
    assert store.is_authenticated() is False


def test_session_store_set_and_clear() -> None:
    store = SessionStore()

    session = DesktopSession(
        identifier="alice",
        user_id="user_001",
        device_id="device_001",
        session_id="session_001",
        access_token="access",
        refresh_token="refresh",
        token_type="bearer",
    )

    store.set_session(session)

    assert store.is_authenticated() is True
    assert store.current == session

    store.clear()

    assert store.current is None
    assert store.is_authenticated() is False
