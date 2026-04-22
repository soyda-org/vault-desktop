# Install vault-desktop on Windows

## What you need

- a Windows machine with a graphical session
- access to the running `vault-api`
- the packaged archive produced by `scripts/package-windows.ps1`

## Package contents

The release process produces:

- `release/vault-desktop-windows.zip`
- `release/vault-desktop-windows.zip.sha256`

## Verify the archive

In PowerShell on the target machine:

```powershell
$Expected = (Get-Content .\vault-desktop-windows.zip.sha256).Split(" ")[0].Trim().ToLower()
$Actual = (Get-FileHash -Algorithm SHA256 .\vault-desktop-windows.zip).Hash.ToLower()
if ($Expected -ne $Actual) { throw "SHA-256 mismatch" }
```

## Install

Extract the archive somewhere under your user profile:

```powershell
New-Item -ItemType Directory -Force -Path "$HOME\apps" | Out-Null
Expand-Archive -Path .\vault-desktop-windows.zip -DestinationPath "$HOME\apps\vault-desktop" -Force
```

The app will then live at:

```text
$HOME\apps\vault-desktop\
```

## Run

Start the bundled executable:

```powershell
& "$HOME\apps\vault-desktop\vault-desktop.exe"
```

## First launch

Before first real use:

1. make sure `vault-api` is reachable from the target machine
2. open the desktop app
3. if the API is not running on the same machine, replace the default API base URL field value `http://127.0.0.1:8000` with the VM or host address you can actually reach, then click `Probe API`
4. probe the API
5. sign up or log in

## Notes

- this package is Windows-specific and must be built on Windows
- the bundled app does not require a sibling `vault-crypto` repo on the target machine
- local UI preferences are stored in `%APPDATA%\vault-desktop\settings.json`
- local PIN bootstrap material is stored in `%APPDATA%\vault-desktop\pin_bootstrap.json`
- file uploads are encrypted locally and streamed chunk by chunk to the API, which avoids buffering the full encrypted payload in desktop memory during large uploads
- if the API runs inside a VM and the desktop runs on another machine, the VM must publish the API beyond `127.0.0.1`; for the compose stack that means setting `VAULT_API_PUBLISH_HOST=0.0.0.0` in `vault-infra/compose/.env` before starting the stack
