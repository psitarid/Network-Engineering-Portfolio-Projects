gcc client.c -o client.exe  -I/mingw64/openssl/include -L/mingw64/openssl/lib -lssl -lcrypto -lws2_32 -mconsole
client.exe 192.168.1.3
