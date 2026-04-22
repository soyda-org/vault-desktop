# Install vault-desktop on Linux

## What you need

- a Linux machine with a graphical session
- access to the running `vault-api`
- the packaged archive produced by `scripts/package-linux.sh`

## Package contents

The release process produces:

- `release/vault-desktop-linux.tar.gz`
- `release/vault-desktop-linux.tar.gz.sha256`

## Verify the archive

On the target machine:

```bash
sha256sum -c vault-desktop-linux.tar.gz.sha256
```

## Install

Extract the archive somewhere under your home directory:

```bash
mkdir -p ~/apps
tar -xzf vault-desktop-linux.tar.gz -C ~/apps
```

The app will then live at:

```text
~/apps/vault-desktop/
```

## Run

Start the bundled executable:

```bash
~/apps/vault-desktop/vault-desktop
```

## First launch

Before first real use:

1. make sure `vault-api` is reachable from the target machine
2. open the desktop app
3. if the API is not running on the same machine, replace the default API base URL field value `http://127.0.0.1:8000` with the VM or host address you can actually reach, then click `Probe API`
4. probe the API
5. sign up or log in

## Notes

- this package is Linux-specific
- the bundled app does not require a sibling `vault-crypto` repo on the target machine
- local UI preferences are still stored on the target machine in the user config directory
- the chosen API base URL is persisted in `~/.config/vault-desktop/settings.json`
- if the API runs inside a VM and the desktop runs on another machine, the VM must publish the API beyond `127.0.0.1`; for the compose stack that means setting `VAULT_API_PUBLISH_HOST=0.0.0.0` in `vault-infra/compose/.env` before starting the stack
- file uploads are encrypted locally and streamed chunk by chunk to the API, which avoids buffering the full encrypted payload in desktop memory during large uploads
- large file support also depends on the server schema being migrated; on the compose stack the API now runs `alembic upgrade head` at startup
