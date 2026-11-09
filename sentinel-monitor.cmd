@echo off
setlocal
cd /d "%~dp0"
if not exist "%~dp0.venv\Scripts\python.exe" (
  echo Project .venv Python is missing. Follow the README setup instructions first.
  pause
  exit /b 1
)
"%~dp0.venv\Scripts\python.exe" "%~dp0scripts\local_monitor.py" --interactive
set "sentinel_launcher_exit=%errorlevel%"
if not "%sentinel_launcher_exit%"=="0" pause
exit /b %sentinel_launcher_exit%
