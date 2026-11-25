@echo off
REM ============================================================
REM  Regenerate pwa_data.h from pwa.html
REM  Double-click this file, or run it from a terminal.
REM  Must sit in the same folder as gen_pwa_data.py and pwa.html.
REM ============================================================

cd /d "%~dp0"

REM Find a Python launcher: prefer "py", fall back to "python".
where py >nul 2>nul
if %errorlevel%==0 (
  set "PY=py"
) else (
  where python >nul 2>nul
  if %errorlevel%==0 (
    set "PY=python"
  ) else (
    echo.
    echo   ERROR: Python not found on PATH.
    echo   Install Python 3 from https://python.org and re-run.
    echo.
    pause
    exit /b 1
  )
)

if not exist "gen_pwa_data.py" (
  echo.
  echo   ERROR: gen_pwa_data.py not found in this folder.
  echo   Put this .bat next to gen_pwa_data.py and pwa.html.
  echo.
  pause
  exit /b 1
)

if not exist "pwa.html" (
  echo.
  echo   ERROR: pwa.html not found in this folder.
  echo.
  pause
  exit /b 1
)

echo Generating pwa_data.h from pwa.html ...
%PY% gen_pwa_data.py pwa.html pwa_data.h
if %errorlevel%==0 (
  echo.
  echo   Done. pwa_data.h regenerated. Rebuild your firmware next.
) else (
  echo.
  echo   FAILED — see the error above.
)
echo.
pause
