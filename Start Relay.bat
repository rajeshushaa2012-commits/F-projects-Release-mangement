@echo off
cd /d "%~dp0server"
echo Starting Relay server...
echo.
echo Once you see "Uvicorn running", open your browser to http://127.0.0.1:8420
echo Keep this window open while you use Relay. Close it to stop the server.
echo.
set PYEXE=C:\Users\Admin\AppData\Local\Programs\Python\Python314\python.exe
if not exist "%PYEXE%" set PYEXE=python
"%PYEXE%" -m uvicorn main:app --host 127.0.0.1 --port 8420
echo.
echo ---------------------------------------------------------
echo The server stopped or failed to start. See any error above.
echo ---------------------------------------------------------
pause
