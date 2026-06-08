@echo off
REM AMPass Native Messaging Host - Windows Installation Script
REM Installs to Local AppData so Administrator privileges are NOT required.

echo ============================================
echo  AMPass Native Messaging Host Installer
echo ============================================
echo.

SET INSTALL_DIR=%LOCALAPPDATA%\AMPass
SET MANIFEST_DIR=%INSTALL_DIR%
SET HOST_NAME=com.ampass.desktop

REM Create install directory
if not exist "%INSTALL_DIR%" mkdir "%INSTALL_DIR%"

REM Copy the native host executable (must be built first)
if exist "ampass-desktop.exe" (
    copy /Y "ampass-desktop.exe" "%INSTALL_DIR%\ampass-desktop.exe"
) else if exist "..\desktop-tauri\src-tauri\target\release\ampass-desktop.exe" (
    copy /Y "..\desktop-tauri\src-tauri\target\release\ampass-desktop.exe" "%INSTALL_DIR%\ampass-desktop.exe"
) else (
    echo WARNING: ampass-desktop.exe not found.
    echo Build it first with: npm run build (in clients/desktop-tauri)
    echo or: cargo build --release (in clients/desktop-tauri/src-tauri)
)

REM Copy Chrome manifest and replace placeholder path with dynamic absolute path
powershell -NoProfile -Command "(Get-Content chrome-host-manifest.json) -replace 'C:\\\\Program Files\\\\AMPass\\\\ampass-desktop.exe', ($env:LOCALAPPDATA + '\\AMPass\\ampass-desktop.exe').Replace('\', '\\') | Set-Content '%MANIFEST_DIR%\chrome-host-manifest.json'"

REM Register for Chrome
REG ADD "HKCU\Software\Google\Chrome\NativeMessagingHosts\%HOST_NAME%" /ve /t REG_SZ /d "%MANIFEST_DIR%\chrome-host-manifest.json" /f

REM Register for Edge (uses same registry path pattern as Chrome)
REG ADD "HKCU\Software\Microsoft\Edge\NativeMessagingHosts\%HOST_NAME%" /ve /t REG_SZ /d "%MANIFEST_DIR%\chrome-host-manifest.json" /f

REM Register for Firefox (if manifest exists)
if exist "firefox-host-manifest.json" (
    powershell -NoProfile -Command "(Get-Content firefox-host-manifest.json) -replace 'C:\\\\Program Files\\\\AMPass\\\\ampass-desktop.exe', ($env:LOCALAPPDATA + '\\AMPass\\ampass-desktop.exe').Replace('\', '\\') | Set-Content '%MANIFEST_DIR%\firefox-host-manifest.json'"
    REG ADD "HKCU\Software\Mozilla\NativeMessagingHosts\%HOST_NAME%" /ve /t REG_SZ /d "%MANIFEST_DIR%\firefox-host-manifest.json" /f
)

echo.
echo ============================================
echo  Installation complete!
echo.
echo  IMPORTANT: Edit the manifest file to add your extension ID:
echo  %MANIFEST_DIR%\chrome-host-manifest.json
echo.
echo  Replace REPLACE_WITH_YOUR_EXTENSION_ID with your actual extension ID.
echo  Find it at chrome://extensions/ (Developer mode enabled)
echo ============================================
pause
