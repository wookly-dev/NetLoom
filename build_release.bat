@echo off
setlocal
cd /d "%~dp0"

set "WOOKLY_DOTNET_DIR=%LOCALAPPDATA%\WooklyDev\dotnet8"

echo ==============================================
echo NetLoom v0.7.5 - Windows Build
echo ==============================================
echo.
echo If .NET 8 SDK is missing, it will be downloaded
echo once into the short per-user WooklyDev SDK cache.
echo Future NetLoom builds will reuse the same SDK.

call "%~dp0ensure_dotnet_sdk.bat"
if errorlevel 1 goto :fail
if not defined NETLOOM_DOTNET goto :fail

echo.
echo Using .NET 8 SDK:
echo %NETLOOM_DOTNET%
"%NETLOOM_DOTNET%" --version
if errorlevel 1 goto :fail

echo.
echo Restoring packages...
"%NETLOOM_DOTNET%" restore "src\NetLoom.App\NetLoom.App.csproj" -r win-x64
if errorlevel 1 goto :fail

echo.
echo Publishing NetLoom...
if exist "publish" rmdir /s /q "publish"
"%NETLOOM_DOTNET%" publish "src\NetLoom.App\NetLoom.App.csproj" ^
  -c Release ^
  -r win-x64 ^
  --self-contained true ^
  --no-restore ^
  /p:PublishSingleFile=true ^
  /p:IncludeNativeLibrariesForSelfExtract=true ^
  /p:DebugType=None ^
  /p:DebugSymbols=false ^
  -o "publish"
if errorlevel 1 goto :fail

if not exist "publish\NetLoom.exe" (
  echo.
  echo [ERROR] Publish command ended without creating publish\NetLoom.exe.
  goto :fail
)

echo.
echo ==============================================
echo Build complete
echo Output: %CD%\publish\NetLoom.exe
echo ==============================================
echo.
echo The published EXE is self-contained.
echo A separate .NET Desktop Runtime is not required
echo on the PC where NetLoom.exe is executed.
pause
exit /b 0

:fail
echo.
echo ==============================================
echo [ERROR] Build failed.
echo No successful build is being reported.
echo ==============================================
pause
exit /b 1
