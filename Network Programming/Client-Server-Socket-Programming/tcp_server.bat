@echo off
REM Build (if needed) and start the TLS server.   Usage: tcp_server.bat [bind_ip] [port]
if not exist tcp_server.exe call build.bat || exit /b 1
if not exist server_cert.pem (
    echo No certificates found - running certgen first.
    certgen.exe all || exit /b 1
)
tcp_server.exe %*
