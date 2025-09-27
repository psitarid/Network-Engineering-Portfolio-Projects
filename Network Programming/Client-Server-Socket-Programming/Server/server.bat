gcc server.c -o server.exe -I/mingw64/openssl/include -L/mingw64/openssl/lib -lssl -lcrypto -lws2_32 -mconsole
server.exe