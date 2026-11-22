@echo off
REM Build all three programs on Windows with MinGW-w64 gcc (e.g. from MSYS2).
REM If OpenSSL is not in the compiler's default paths, set OPENSSL_DIR first, e.g.:
REM     set OPENSSL_DIR=C:\msys64\mingw64
setlocal
set CFLAGS=-Wall -O2 -std=c11
set LDFLAGS=
if not "%OPENSSL_DIR%"=="" (
    set CFLAGS=%CFLAGS% -I"%OPENSSL_DIR%\include"
    set LDFLAGS=-L"%OPENSSL_DIR%\lib"
)
set COMMON=net.c cert_509X.c tls.c tls_crypto.c

echo Building certgen.exe ...
gcc %CFLAGS% certgen.c cert_509X.c -o certgen.exe %LDFLAGS% -lcrypto || exit /b 1
echo Building tcp_server.exe ...
gcc %CFLAGS% tcp_server.c %COMMON% -o tcp_server.exe %LDFLAGS% -lcrypto -lws2_32 || exit /b 1
echo Building tcp_client.exe ...
gcc %CFLAGS% tcp_client.c %COMMON% -o tcp_client.exe %LDFLAGS% -lcrypto -lws2_32 || exit /b 1
echo Done.
