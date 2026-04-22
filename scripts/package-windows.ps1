Set-StrictMode -Version Latest
$ErrorActionPreference = "Stop"

$RootDir = Split-Path -Parent (Split-Path -Parent $MyInvocation.MyCommand.Path)
$VenvPython = Join-Path $RootDir ".venv\Scripts\python.exe"
$DistDir = Join-Path $RootDir "dist"
$BuildDir = Join-Path $RootDir "build"
$ReleaseDir = Join-Path $RootDir "release"
$AppDir = Join-Path $DistDir "vault-desktop"
$ArchivePath = Join-Path $ReleaseDir "vault-desktop-windows.zip"
$ChecksumPath = Join-Path $ReleaseDir "vault-desktop-windows.zip.sha256"
$VaultCryptoDir = Join-Path (Split-Path -Parent $RootDir) "vault-crypto"

if (-not (Test-Path $VenvPython)) {
    throw "Missing desktop virtualenv at $VenvPython"
}

if (-not (Test-Path $VaultCryptoDir)) {
    throw "Missing sibling vault-crypto repository."
}

& $VenvPython -c "import vault_crypto" *> $null
if ($LASTEXITCODE -ne 0) {
    & $VenvPython -m pip install --no-build-isolation -e $VaultCryptoDir
}

& $VenvPython -c "import PyInstaller" *> $null
if ($LASTEXITCODE -ne 0) {
    & $VenvPython -m pip install pyinstaller
}

if (Test-Path $DistDir) { Remove-Item -Recurse -Force $DistDir }
if (Test-Path $BuildDir) { Remove-Item -Recurse -Force $BuildDir }
if (Test-Path $ReleaseDir) { Remove-Item -Recurse -Force $ReleaseDir }
New-Item -ItemType Directory -Force -Path $ReleaseDir | Out-Null

& $VenvPython -m PyInstaller `
    --noconfirm `
    --clean `
    --windowed `
    --name vault-desktop `
    --collect-submodules vault_crypto `
    --add-data "$RootDir\app\assets;app\assets" `
    "$RootDir\app\main.py"

Copy-Item "$RootDir\docs\install-windows.md" (Join-Path $AppDir "INSTALL.md")
Compress-Archive -Path "$AppDir\*" -DestinationPath $ArchivePath -Force

$Hash = (Get-FileHash -Algorithm SHA256 $ArchivePath).Hash.ToLowerInvariant()
"$Hash *vault-desktop-windows.zip" | Set-Content -Encoding ascii $ChecksumPath

Write-Host ""
Write-Host "Desktop package created in $AppDir"
Write-Host "Release archive: $ArchivePath"
Write-Host "Checksum file: $ChecksumPath"
