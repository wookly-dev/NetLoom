@echo off
setlocal
cd /d "%~dp0"
set "WOOKLY_DOTNET_DIR=%LOCALAPPDATA%\WooklyDev\dotnet8"

call "%~dp0ensure_dotnet_sdk.bat"
if errorlevel 1 goto :fail
if not defined NETLOOM_DOTNET goto :fail

"%NETLOOM_DOTNET%" run --project "src\NetLoom.App\NetLoom.App.csproj"
if errorlevel 1 goto :fail
exit /b 0

:fail
echo.
echo [ERROR] NetLoom source run failed.
pause
exit /b 1
