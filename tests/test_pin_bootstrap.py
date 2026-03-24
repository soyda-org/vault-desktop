import json
from pathlib import Path

from app.core.pin_bootstrap import (
    LocalPinBootstrapStore,
    create_local_pin_bootstrap,
    unlock_master_key_b64_with_pin,
)

VALID_MASTER_KEY_B64 = "S0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0tLS0s="


def test_create_local_pin_bootstrap_round_trip() -> None:
    bootstrap = create_local_pin_bootstrap(
        user_id="user_1",
        identifier_hint="alice",
        pin="1234",
        master_key_b64=VALID_MASTER_KEY_B64,
    )

    unlocked = unlock_master_key_b64_with_pin(
        bootstrap=bootstrap,
        pin="1234",
    )

    assert unlocked == VALID_MASTER_KEY_B64
    assert bootstrap.user_id == "user_1"
    assert bootstrap.identifier_hint == "alice"


def test_unlock_master_key_b64_with_pin_rejects_wrong_pin() -> None:
    bootstrap = create_local_pin_bootstrap(
        user_id="user_1",
        identifier_hint="alice",
        pin="1234",
        master_key_b64=VALID_MASTER_KEY_B64,
    )

    try:
        unlock_master_key_b64_with_pin(bootstrap=bootstrap, pin="9999")
        assert False, "Expected ValueError"
    except ValueError as exc:
        assert str(exc) == "PIN unlock failed."


def test_local_pin_bootstrap_store_round_trip_and_clear(tmp_path: Path) -> None:
    store = LocalPinBootstrapStore(config_path=tmp_path / "pin_bootstrap.json")
    bootstrap = create_local_pin_bootstrap(
        user_id="user_1",
        identifier_hint="alice",
        pin="1234",
        master_key_b64=VALID_MASTER_KEY_B64,
    )

    store.save(bootstrap)
    loaded = store.load()

    assert loaded == bootstrap

    raw_data = json.loads((tmp_path / "pin_bootstrap.json").read_text(encoding="utf-8"))
    assert raw_data["user_id"] == "user_1"
    assert VALID_MASTER_KEY_B64 not in json.dumps(raw_data)

    store.clear()
    assert store.load() is None
