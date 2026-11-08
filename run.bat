@echo off
setlocal
cd /d "%~dp0"
echo.
echo  SYSTEM SCANNER V2 - CYBER COMMAND
echo  Local-only diagnostics. Repairs require individual confirmation.
echo.
where py >nul 2>nul
if %errorlevel%==0 (
  py -3 server.py
) else (
  python server.py
)
if errorlevel 1 (
  echo.
  echo Scanner exited with an error. Confirm Python 3.10+ is installed.
  pause
)
endlocal