@echo off
REM Build (if needed) and start the TLS client.   Usage: tcp_client.bat [server_ip] [port]
if not exist tcp_client.exe call build.bat || exit /b 1
if "%~1"=="" (
    tcp_client.exe 127.0.0.1
) else (
    tcp_client.exe %*
)
