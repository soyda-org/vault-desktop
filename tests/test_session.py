from app.core.session import DesktopSession, SessionStore


VALID_MASTER_KEY_B64 = "S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s="


def test_session_store_starts_empty() -> None:
    store = SessionStore()

    assert store.current is None
    assert store.is_authenticated() is False
    assert store.has_vault_master_key() is False


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
    assert store.has_vault_master_key() is False

    store.clear()

    assert store.current is None
    assert store.is_authenticated() is False
    assert store.has_vault_master_key() is False


def test_session_store_can_set_and_clear_vault_master_key() -> None:
    store = SessionStore()
    store.set_session(
        DesktopSession(
            identifier="alice",
            user_id="user_001",
            device_id="device_001",
            session_id="session_001",
            access_token="access",
            refresh_token="refresh",
            token_type="bearer",
        )
    )

    updated = store.set_vault_master_key(VALID_MASTER_KEY_B64)

    assert updated is not None
    assert updated.vault_master_key_b64 == VALID_MASTER_KEY_B64
    assert store.has_vault_master_key() is True

    cleared = store.clear_vault_master_key()

    assert cleared is not None
    assert cleared.vault_master_key_b64 is None
    assert store.has_vault_master_key() is False


def test_rotate_tokens_preserves_vault_master_key() -> None:
    store = SessionStore()
    store.set_session(
        DesktopSession(
            identifier="alice",
            user_id="user_001",
            device_id="device_001",
            session_id="session_001",
            access_token="access-1",
            refresh_token="refresh-1",
            token_type="bearer",
            vault_master_key_b64=VALID_MASTER_KEY_B64,
        )
    )

    updated = store.rotate_tokens(
        access_token="access-2",
        refresh_token="refresh-2",
        token_type="bearer",
    )

    assert updated is not None
    assert updated.access_token == "access-2"
    assert updated.refresh_token == "refresh-2"
    assert updated.vault_master_key_b64 == VALID_MASTER_KEY_B64
