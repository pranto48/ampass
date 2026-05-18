# AMPass Desktop — Windows Build Script
# Builds the Tauri desktop app and copies release files to release/dist/

Write-Host "============================================"
Write-Host " AMPass Desktop — Windows Build"
Write-Host "============================================"
Write-Host ""

$tauriDir = Join-Path $PSScriptRoot "..\clients\desktop-tauri"
$distDir = Join-Path $PSScriptRoot "..\release\dist"

# Check Rust is installed
if (-not (Get-Command "cargo" -ErrorAction SilentlyContinue)) {
    Write-Host "ERROR: Rust/Cargo not found. Install from https://rustup.rs/" -ForegroundColor Red
    exit 1
}

# Check Tauri CLI
$tauriCli = cargo install --list 2>$null | Select-String "tauri-cli"
if (-not $tauriCli) {
    Write-Host "Installing Tauri CLI..."
    cargo install tauri-cli --version "^2"
}

# Build
Write-Host "Building AMPass Desktop (release mode)..."
Push-Location $tauriDir
cargo tauri build
$buildResult = $LASTEXITCODE
Pop-Location

if ($buildResult -ne 0) {
    Write-Host "ERROR: Build failed." -ForegroundColor Red
    exit 1
}

# Create dist directory
if (-not (Test-Path $distDir)) {
    New-Item -ItemType Directory -Path $distDir -Force | Out-Null
}

# Find output files
$nsisDir = Join-Path $tauriDir "src-tauri\target\release\bundle\nsis"
$msiDir = Join-Path $tauriDir "src-tauri\target\release\bundle\msi"

$exeFile = Get-ChildItem $nsisDir -Filter "*.exe" -ErrorAction SilentlyContinue | Select-Object -First 1
$msiFile = Get-ChildItem $msiDir -Filter "*.msi" -ErrorAction SilentlyContinue | Select-Object -First 1

# Copy to dist
$checksums = @()

if ($exeFile) {
    Copy-Item $exeFile.FullName -Destination $distDir -Force
    $hash = (Get-FileHash $exeFile.FullName -Algorithm SHA256).Hash
    $checksums += "$hash  $($exeFile.Name)"
    Write-Host "  EXE: $($exeFile.Name) ($([math]::Round($exeFile.Length/1MB, 1)) MB)" -ForegroundColor Green
    Write-Host "  SHA-256: $hash"
}

if ($msiFile) {
    Copy-Item $msiFile.FullName -Destination $distDir -Force
    $hash = (Get-FileHash $msiFile.FullName -Algorithm SHA256).Hash
    $checksums += "$hash  $($msiFile.Name)"
    Write-Host "  MSI: $($msiFile.Name) ($([math]::Round($msiFile.Length/1MB, 1)) MB)" -ForegroundColor Green
    Write-Host "  SHA-256: $hash"
}

# Write checksums file
if ($checksums.Count -gt 0) {
    $checksums | Out-File (Join-Path $distDir "checksums.txt") -Encoding UTF8
    Write-Host ""
    Write-Host "Files copied to: $distDir" -ForegroundColor Cyan
    Write-Host "Checksums saved to: $distDir\checksums.txt"
}

Write-Host ""
Write-Host "============================================"
Write-Host " Next steps:"
Write-Host " 1. Open AMPass web app as admin"
Write-Host " 2. Go to Admin → Release Downloads"
Write-Host " 3. Upload the .exe as 'Windows EXE'"
Write-Host " 4. Upload the .msi as 'Windows MSI'"
Write-Host " 5. Set version and enable the release"
Write-Host "============================================"
