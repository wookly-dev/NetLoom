@echo off
rem NetLoom - .NET 8 SDK resolver / installer
rem This file is called from build_release.bat and run_source.bat.

set "NETLOOM_DOTNET="
set "WOOKLY_DOTNET_DIR=%LOCALAPPDATA%\WooklyDev\dotnet8"

rem 1) Reuse the short per-user WooklyDev SDK cache if present.
call :check_sdk "%WOOKLY_DOTNET_DIR%\dotnet.exe"
if defined NETLOOM_DOTNET goto :ready

rem 2) Reuse a package-local SDK if present.
call :check_sdk "%~dp0.dotnet\dotnet.exe"
if defined NETLOOM_DOTNET goto :ready

rem 3) Reuse a FileRecovery package SDK from Downloads when available.
for /d %%P in ("%USERPROFILE%\Downloads\FileRecovery*") do (
    call :check_sdk "%%~fP\file_recovery_v0_1\.dotnet\dotnet.exe"
    if defined NETLOOM_DOTNET goto :ready
)

rem 4) Use a system-installed .NET 8 SDK if available.
for /f "delims=" %%D in ('where dotnet 2^>nul') do (
    call :check_sdk "%%~fD"
    if defined NETLOOM_DOTNET goto :ready
)

rem 5) No SDK found. Download .NET 8 SDK once into the WooklyDev cache.
echo.
echo .NET 8 SDK was not found.
echo It will be downloaded once into:
echo %WOOKLY_DOTNET_DIR%
echo.

if not exist "%WOOKLY_DOTNET_DIR%" mkdir "%WOOKLY_DOTNET_DIR%" >nul 2>&1

powershell.exe -NoLogo -NoProfile -ExecutionPolicy Bypass -Command ^
  "$ErrorActionPreference='Stop';" ^
  "[Net.ServicePointManager]::SecurityProtocol=[Net.SecurityProtocolType]::Tls12;" ^
  "$script=Join-Path $env:TEMP 'wooklydev-dotnet-install.ps1';" ^
  "Invoke-WebRequest -UseBasicParsing -Uri 'https://dot.net/v1/dotnet-install.ps1' -OutFile $script;" ^
  "& $script -Channel 8.0 -Quality GA -InstallDir $env:WOOKLY_DOTNET_DIR -NoPath;" ^
  "if ($LASTEXITCODE -ne 0) { exit $LASTEXITCODE }"

if errorlevel 1 (
    echo.
    echo [ERROR] .NET 8 SDK download/install failed.
    echo Check the Internet connection, proxy, or PowerShell policy and try again.
    exit /b 1
)

call :check_sdk "%WOOKLY_DOTNET_DIR%\dotnet.exe"
if not defined NETLOOM_DOTNET (
    echo.
    echo [ERROR] .NET 8 SDK installation completed but a usable SDK was not detected.
    exit /b 1
)

goto :ready

:check_sdk
if not exist "%~1" exit /b 0
"%~1" --list-sdks 2>nul | %SystemRoot%\System32\findstr.exe /l /b /c:"8." >nul
if not errorlevel 1 set "NETLOOM_DOTNET=%~1"
exit /b 0

:ready
for %%I in ("%NETLOOM_DOTNET%") do set "DOTNET_ROOT=%%~dpI"
set "DOTNET_MULTILEVEL_LOOKUP=0"
exit /b 0
