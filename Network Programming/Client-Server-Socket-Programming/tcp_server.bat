gcc tcp_server.c -o tcp_server.exe -I/mingw64/openssl/include -L/mingw64/openssl/lib -lssl -lcrypto -lws2_32 -mconsole
tcp_server.exe
