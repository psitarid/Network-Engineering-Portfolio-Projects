# Build with:   make            (Linux / macOS / MSYS2 MinGW64 shell)
# Clean with:   make clean
#
# On Windows (MinGW) the Winsock library is linked automatically.
# If OpenSSL lives somewhere non-standard:  make OPENSSL_DIR=/path/to/openssl

CC      ?= gcc
CFLAGS  ?= -Wall -Wextra -O2 -std=c11
OPENSSL_DIR ?=

ifneq ($(OPENSSL_DIR),)
  CFLAGS  += -I$(OPENSSL_DIR)/include
  LDFLAGS += -L$(OPENSSL_DIR)/lib -L$(OPENSSL_DIR)/lib64
endif

LDLIBS = -lcrypto
EXE    =
ifeq ($(OS),Windows_NT)
  LDLIBS += -lws2_32
  EXE     = .exe
else
  CFLAGS += -D_POSIX_C_SOURCE=200809L
endif

COMMON = net.o cert_509X.o tls.o tls_crypto.o

all: certgen$(EXE) tcp_server$(EXE) tcp_client$(EXE)

certgen$(EXE): certgen.o cert_509X.o
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

tcp_server$(EXE): tcp_server.o $(COMMON)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

tcp_client$(EXE): tcp_client.o $(COMMON)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

%.o: %.c net.h cert_509X.h tls.h tls_crypto.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o certgen$(EXE) tcp_server$(EXE) tcp_client$(EXE)

.PHONY: all clean
