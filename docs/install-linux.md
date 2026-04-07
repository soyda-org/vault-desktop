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
3. set the API base URL if needed
4. probe the API
5. sign up or log in

## Notes

- this package is Linux-specific
- the bundled app does not require a sibling `vault-crypto` repo on the target machine
- local UI preferences are still stored on the target machine in the user config directory
