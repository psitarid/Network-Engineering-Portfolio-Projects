gcc tcp_client.c -o tcp_client  -I/mingw64/openssl/include -L/mingw64/openssl/lib -lssl -lcrypto -lws2_32 -mconsole
tcp_client.exe 111.111.111.111
