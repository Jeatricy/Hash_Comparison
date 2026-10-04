@echo off
setlocal
cd /d "%~dp0"
set "HASH_TOOL_PYTHONW="

for /d %%D in ("%LocalAppData%\Programs\Python\Python*") do (
    if not defined HASH_TOOL_PYTHONW if exist "%%~fD\pythonw.exe" set "HASH_TOOL_PYTHONW=%%~fD\pythonw.exe"
)

if defined HASH_TOOL_PYTHONW (
    start "" "%HASH_TOOL_PYTHONW%" app.py
    exit /b 0
)

where pythonw >nul 2>nul
if %errorlevel%==0 (
    start "" pythonw app.py
    exit /b 0
)

where pyw >nul 2>nul
if %errorlevel%==0 (
    start "" pyw -3 app.py
    exit /b 0
)

echo No usable Python installation was found.
echo Please install Python 3.10 or later with Tcl/Tk support.
pause
