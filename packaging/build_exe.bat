@echo off
REM  Builds dist\FFStudio.exe (needs Python 3.8+).
setlocal
cd /d "%~dp0"

REM  Use the first Python that runs: python, python3, then the py launcher.
set "PY="
for %%C in ("python" "python3" "py -3" "py") do if not defined PY (
  for /f "delims=" %%V in ('%%~C -c "import sys" 2^>nul ^&^& echo OK') do if "%%V"=="OK" set "PY=%%~C"
)
if not defined PY (
  echo   No working Python 3 was found. Install it from https://www.python.org/downloads/
  echo   ^(tick "Add python.exe to PATH"^), then run this again.  If you use pyenv, run "pyenv rehash" first.
  pause & exit /b 1
)

echo   Using Python:  %PY%
for /f "delims=" %%v in ('%PY% --version 2^>^&1') do echo   %%v
echo   Ensuring build + runtime dependencies...
call %PY% -m pip install --upgrade pyinstaller
if errorlevel 1 ( echo   Could not install PyInstaller - see above. & pause & exit /b 1 )
call %PY% ..\src\bootstrap.py

echo   Building FFStudio.exe (this takes a few minutes)...
call %PY% -m PyInstaller --noconfirm --distpath ..\dist --workpath ..\build ffstudio.spec
if errorlevel 1 ( echo. & echo   Build failed - see the messages above. & pause & exit /b 1 )

echo.
echo   Done: dist\FFStudio.exe
echo   ACTS 3.2.1 is not bundled; see README for setup.
pause
endlocal
exit /b 0
