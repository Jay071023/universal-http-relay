@echo off
setlocal
title Stop Load Balancer
cd /d "%~dp0"

echo Stopping supervisors...
for %%F in ("lb-server.supervisor.pid" "deploy-server.supervisor.pid") do (
    if exist "%%~F" for /f "delims=" %%p in (%%~F) do taskkill /T /F /PID %%p >nul 2>&1
)
echo Stopping lb-server child by PID file...
if exist "lb-server.pid" for /f "delims=" %%p in (lb-server.pid) do taskkill /T /F /PID %%p >nul 2>&1
timeout /t 2 /nobreak >nul
echo Project services stopped. Other applications using nearby ports were not touched.
echo Logs are kept in logs\ for diagnosis.
pause
endlocal
