@echo off
REM AMPass Native Messaging Host - Windows Uninstall Script
REM Run as Administrator

echo ============================================
echo  AMPass Native Messaging Host Uninstaller
echo ============================================
echo.

SET INSTALL_DIR=%ProgramFiles%\AMPass
SET HOST_NAME=com.ampass.desktop

REM Remove Chrome registry entry
REG DELETE "HKCU\Software\Google\Chrome\NativeMessagingHosts\%HOST_NAME%" /f 2>nul

REM Remove Edge registry entry
REG DELETE "HKCU\Software\Microsoft\Edge\NativeMessagingHosts\%HOST_NAME%" /f 2>nul

REM Remove Firefox registry entry
REG DELETE "HKCU\Software\Mozilla\NativeMessagingHosts\%HOST_NAME%" /f 2>nul

REM Remove installed files
if exist "%INSTALL_DIR%\ampass-desktop.exe" del /F "%INSTALL_DIR%\ampass-desktop.exe"
if exist "%INSTALL_DIR%\chrome-host-manifest.json" del /F "%INSTALL_DIR%\chrome-host-manifest.json"
if exist "%INSTALL_DIR%\firefox-host-manifest.json" del /F "%INSTALL_DIR%\firefox-host-manifest.json"

REM Remove directory if empty
rmdir "%INSTALL_DIR%" 2>nul

echo.
echo  Native messaging host uninstalled.
echo ============================================
pause
