# Client–Server Communication over TLS in C

A secure client–server application written in C, with **TLS 1.2 implemented from scratch**. The TCP layer uses **Winsock2** on Windows and POSIX sockets on Linux/macOS. **OpenSSL's libcrypto** provides only the low-level primitives (RSA, Diffie–Hellman, AES, SHA-256, X.509 parsing).

The project builds everything else by hand: the record layer, handshake messages, key schedule, certificate checks and alerts. The goal is to show what happens inside a TLS connection.

It uses one cipher suite, **`TLS_DHE_RSA_WITH_AES_256_CBC_SHA256`**, with **mutual authentication** (both the server and the client present certificates). It follows the real TLS 1.2 wire format (RFC 5246), so it **interoperates with standard OpenSSL** (`openssl s_server` / `openssl s_client`).

---

## Table of Contents

- [Features](#features)
- [How It Works](#how-it-works)
- [The TLS 1.2 Handshake](#the-tls-12-handshake)
- [Record Protection](#record-protection)
- [Project Structure](#project-structure)
- [Requirements](#requirements)
- [Build & Run](#build--run)
- [Example Output](#example-output)
- [Testing & Interoperability](#testing--interoperability)
- [Security Notes & Limitations](#security-notes--limitations)
- [Further Reading](#further-reading)

---

## Features

**Certificates (PKI)**
- 2048-bit RSA key generation
- A self-signed **Certificate Authority (CA)** that issues the server and client certificates
- X.509 v3 certificates with a random serial number, a **validity period**, and subject/issuer names
- Extensions: `basicConstraints`, `keyUsage`, `extendedKeyUsage` (serverAuth / clientAuth), key identifiers, and `subjectAltName` (server IPs)
- **Peer certificate verification**: chain to the trusted CA, CA signature, validity dates, purpose, and (on the client) that the server's IP is in the certificate

**TLS 1.2 (written by hand)**
- Record layer: framing, fragmentation, and reassembly of handshake messages
- The full handshake, including `CertificateRequest` and `CertificateVerify` for mutual authentication
- **Ephemeral Diffie–Hellman** (RFC 7919 `ffdhe2048` group) signed with RSA, which gives forward secrecy
- TLS 1.2 **PRF** (P_SHA256), master secret and key-block derivation
- `Finished` messages that detect any tampering with the handshake
- **AES-256-CBC + HMAC-SHA256** record encryption with explicit IVs and sequence numbers
- Alerts (`close_notify`, `bad_record_mac`, `bad_certificate`, `handshake_failure`, …)
- Secure renegotiation signalling (RFC 5746), required by modern OpenSSL clients

**Application**
- The server handles clients one after another and answers each encrypted message
- An interactive client: type messages and they are sent encrypted
- Configurable IP address and port from the command line
- **Cross-platform**: Windows (MinGW) and Linux/macOS

---

## How It Works

```
 ┌──────────────┐   1. certgen   ┌──────────────────────────────────────────┐
 │   certgen    │ ─────────────▶ │ ca_cert.pem      ca_key.pem              │
 │ (run once)   │                │ server_cert.pem  server_key.pem          │
 └──────────────┘                │ client_cert.pem  client_key.pem          │
                                 └──────────────────────────────────────────┘
                                         │                     │
                         loads server_*  │                     │  loads client_*
                         + ca_cert.pem   ▼                     ▼  + ca_cert.pem
                                 ┌──────────────┐       ┌──────────────┐
                                 │  tcp_server  │◀─────▶│  tcp_client  │
                                 └──────────────┘  TCP  └──────────────┘
                                   2. TCP connection on port 9002
                                   3. TLS 1.2 handshake (mutual authentication)
                                   4. Encrypted application data
```

1. **certgen** creates a CA, then uses it to sign a server certificate and a client certificate.
2. The **server** listens on TCP and the **client** connects.
3. Both sides run the **TLS handshake**. Each one checks that the other's certificate was signed by the CA they both trust.
4. All messages after the handshake are **encrypted and authenticated**.

---

## The TLS 1.2 Handshake

### Cipher suite: `DHE-RSA-AES256-SHA256` (0x006B)

| Component       | Algorithm                          | Purpose                                                            |
|-----------------|------------------------------------|--------------------------------------------------------------------|
| Key exchange    | **DHE** (Diffie–Hellman Ephemeral) | Agree on a shared secret. New keys every session give forward secrecy |
| Authentication  | **RSA** (PKCS#1 v1.5, SHA-256)     | Sign the DH parameters and the handshake to prove identity          |
| Bulk encryption | **AES-256-CBC**                    | Encrypt application data                                            |
| MAC / PRF       | **HMAC-SHA256**                    | Record integrity and key derivation                                 |

### Message flow

```
   CLIENT                                                         SERVER
     │ ── ClientHello ────────────────────────────────────────────▶ │  version, client_random,
     │                                                              │  cipher suites, extensions
     │ ◀──────────────────────────────────────────── ServerHello ── │  chosen version + suite, server_random
     │ ◀──────────────────────────────────────────── Certificate ── │  server cert (client verifies it)
     │ ◀────────────────────────────────────── ServerKeyExchange ── │  DH p, g, Ys + RSA signature
     │ ◀───────────────────────────────────── CertificateRequest ── │  "send me your certificate"
     │ ◀──────────────────────────────────────── ServerHelloDone ── │
     │                                                              │
     │ ── Certificate ────────────────────────────────────────────▶ │  client cert (server verifies it)
     │ ── ClientKeyExchange ──────────────────────────────────────▶ │  DH Yc
     │        both sides: pre_master = DH(Ys, Yc) → master secret → session keys
     │ ── CertificateVerify ──────────────────────────────────────▶ │  RSA signature over the transcript
     │ ── ChangeCipherSpec ───────────────────────────────────────▶ │
     │ ── Finished (encrypted) ───────────────────────────────────▶ │  PRF(master, transcript hash)
     │ ◀─────────────────────────────────────── ChangeCipherSpec ── │
     │ ◀──────────────────────────────────── Finished (encrypted) ─ │
     │                                                              │
     │ ◀═══════════════ Encrypted application data ═══════════════▶ │
```

### What each step proves

| Step | Check | Protects against |
|------|-------|------------------|
| Server `Certificate` | Signed by the CA, within its dates, `serverAuth`, server IP in `subjectAltName` | Connecting to an impostor |
| `ServerKeyExchange` signature | Signed over both randoms + DH params with the certificate's key | Man-in-the-middle swapping the DH values |
| Client `Certificate` + `CertificateVerify` | Client owns a CA-issued `clientAuth` certificate and its private key | Unauthorised clients |
| DH value range check | `1 < Y < p-1`, group ≥ 2048 bits | Small-subgroup / weak-group (Logjam) attacks |
| `Finished` | Both sides computed the same keys and saw the same handshake | Downgrade or tampering with any handshake message |

### Key schedule

```
pre_master_secret = g^(xy) mod p                     (DH shared secret, leading zeros stripped)
master_secret     = PRF(pre_master_secret, "master secret", client_random + server_random)[0..47]
key_block         = PRF(master_secret, "key expansion", server_random + client_random)
                  = client_MAC_key(32) | server_MAC_key(32) | client_AES_key(32) | server_AES_key(32)
verify_data       = PRF(master_secret, "client finished" / "server finished", SHA256(handshake_messages))[0..11]

PRF(secret, label, seed) = P_SHA256(secret, label + seed)
P_SHA256(secret, seed)   = HMAC(secret, A(1) + seed) + HMAC(secret, A(2) + seed) + ...
A(0) = seed,  A(i) = HMAC(secret, A(i-1))
```

---

## Record Protection

Every record after `ChangeCipherSpec` is protected with **MAC-then-encrypt** (RFC 5246 §6.2.3.2):

```
 MAC      = HMAC-SHA256(mac_key, seq_num(8) | type(1) | version(2) | length(2) | plaintext)
 fragment = IV(16) | AES-256-CBC( plaintext | MAC(32) | padding | padding_length )

 ┌──────┬─────────┬────────┬───────────────────────────────────────────────────────┐
 │ type │ version │ length │  IV  │  encrypted( data | MAC | padding )             │
 │ 1 B  │  3,3    │  2 B   │ 16 B │                                                 │
 └──────┴─────────┴────────┴───────────────────────────────────────────────────────┘
```

- A **new random IV** for every record
- A **64-bit sequence number** in the MAC, so records can't be replayed, reordered or dropped unnoticed
- A failed padding check and a failed MAC check produce the **same alert** (`bad_record_mac`), so an attacker can't tell them apart

---

## Project Structure

```
Client-Server-Socket-Programming/
├── certgen.c          # Tool: creates the CA, then issues the server and client certificates
├── tcp_server.c       # TLS server: load certs → listen → handshake → encrypted replies
├── tcp_client.c       # TLS client: load certs → connect → handshake → interactive encrypted chat
│
├── tls.h / tls.c      # TLS 1.2: record layer, handshake state machine, alerts, public API
├── tls_crypto.h / .c  # Cipher-suite primitives: PRF, DHE, RSA signatures, AES-CBC + HMAC records
├── cert_509X.h / .c   # RSA keys, X.509 v3 certificates, extensions, PEM I/O, peer verification
├── net.h / net.c      # Cross-platform sockets (Winsock2 / POSIX): bind, listen, accept, send_all…
│
├── Makefile           # Build on Linux / macOS / MSYS2
├── build.bat          # Build on Windows (MinGW gcc)
├── tcp_server.bat     # Build if needed, create certificates if missing, start the server
├── tcp_client.bat     # Build if needed, start the client (defaults to 127.0.0.1)
├── .gitignore         # Keeps build output and *.pem keys out of git
└── X.509 Certificate Generation Code Explanation.pdf
```

The TLS API is small:

```c
tls_session tls;
tls_init(&tls, socket, TLS_ROLE_CLIENT, my_cert, my_key, ca_cert, "127.0.0.1");
if (tls_handshake(&tls) == 0) {
    tls_write(&tls, "hello", 5);                // encrypt + send
    int n = tls_read(&tls, buf, sizeof(buf));   // receive + decrypt (0 = peer closed)
    tls_close(&tls);                            // close_notify
}
tls_free(&tls);                                 // free memory, wipe keys
```

---

## Requirements

| Requirement | Notes |
|-------------|-------|
| **C compiler** | GCC or Clang. On Windows: MinGW-w64 (e.g. via [MSYS2](https://www.msys2.org/)) |
| **OpenSSL 3.x** | Development headers and `libcrypto` |
| **OS** | Windows, Linux or macOS |

**Windows (MSYS2, in the MINGW64 shell)**
```bash
pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl make
```

**Ubuntu / Debian**
```bash
sudo apt install build-essential libssl-dev
```

**macOS**
```bash
brew install openssl@3
make OPENSSL_DIR=$(brew --prefix openssl@3)
```

---

## Build & Run

### 1. Build

```bash
make                 # Linux / macOS / MSYS2 shell
```
```bat
build.bat            :: Windows Command Prompt (set OPENSSL_DIR if OpenSSL isn't on the default paths)
```

This builds three programs: `certgen`, `tcp_server` and `tcp_client`.

### 2. Create the certificates (once)

```bash
./certgen            # same as: ./certgen all
```

You'll be asked for the Country, Organization and Common Name of each certificate. Press Enter to accept the defaults. For the server, you'll also be asked for the **IP address(es)** clients will use to reach it (default `127.0.0.1`). The client refuses a server whose certificate doesn't list the IP it connected to.

Run `./certgen ca`, `./certgen server` or `./certgen client` to regenerate a single certificate. For example, run `./certgen server` when the server moves to a new IP.

> 🔒 `*.pem` files include private keys and are listed in `.gitignore`. Don't commit them.

### 3. Start the server

```bash
./tcp_server                     # listens on 0.0.0.0:9002
./tcp_server 192.168.1.10 9443   # custom bind address and port
```

### 4. Start the client (in another terminal)

```bash
./tcp_client 127.0.0.1           # port defaults to 9002
./tcp_client 192.168.1.10 9443
```

The client sends `Is anyone there?` and then lets you type messages. Type `quit` (or press Ctrl+D / Ctrl+Z) to close the session.

> **Two machines?** Copy `ca_cert.pem`, `client_cert.pem` and `client_key.pem` to the client machine. Make sure the server certificate was issued for the server's real IP (`./certgen server`).

### 5. Inspect the certificates (optional)

```bash
openssl x509 -in server_cert.pem -text -noout
openssl verify -CAfile ca_cert.pem server_cert.pem client_cert.pem
```

---

## Example Output

**Client**
```
- Connected to server successfully.

- Starting TLS 1.2 handshake as client
  >> ClientHello
  << ServerHello
  ** server chose TLS 1.2, TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
  << Certificate
  Peer certificate
    subject : /C=GR/O=Network Portfolio/CN=server
    issuer  : /C=GR/O=Network Portfolio/CN=CA
    valid   : Nov 22 22:21:47 2026 GMT  ->  Nov 22 22:21:47 2027 GMT
  ** peer certificate verified (trusted CA, valid dates, correct purpose, IP matches)
  << ServerKeyExchange
  ** DH parameters signed by the server: OK (2048-bit group)
  << CertificateRequest
  << ServerHelloDone
  >> Certificate
  >> ClientKeyExchange
  ** master secret and session keys derived
  >> CertificateVerify
  >> ChangeCipherSpec
  >> Finished (encrypted)
  << ChangeCipherSpec
  << Finished (encrypted)
- Handshake complete: TLS 1.2, TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, mutual authentication

- Message sent: Is anyone there?
- Received message: You have reached the server!

Type a message and press Enter ("quit" or Ctrl+D / Ctrl+Z to exit).
> hello over TLS
- Message sent: hello over TLS
- Received message: Server received: hello over TLS
```

**Server**
```
- Connection received from 127.0.0.1:55198

- Starting TLS 1.2 handshake as server
  << ClientHello
  ** client offers TLS 1.2 and TLS_DHE_RSA_WITH_AES_256_CBC_SHA256
  >> ServerHello
  >> Certificate
  >> ServerKeyExchange
  >> CertificateRequest
  >> ServerHelloDone
  << Certificate
  ** peer certificate verified (trusted CA, valid dates, correct purpose)
  << ClientKeyExchange
  ** master secret and session keys derived
  << CertificateVerify
  ** client proved ownership of its certificate key
  << ChangeCipherSpec
  << Finished (encrypted)
  >> ChangeCipherSpec
  >> Finished (encrypted)
- Handshake complete: TLS 1.2, TLS_DHE_RSA_WITH_AES_256_CBC_SHA256, mutual authentication

- Received message: Is anyone there?
- Message sent.
```

---

## Testing & Interoperability

The implementation was tested against **OpenSSL 3.0** in both directions. This is the strongest available check that the wire format, key schedule and record encryption are correct.

**This project's client → OpenSSL server**
```bash
openssl s_server -accept 9002 -tls1_2 -cipher DHE-RSA-AES256-SHA256 \
    -cert server_cert.pem -key server_key.pem -CAfile ca_cert.pem -Verify 1
./tcp_client 127.0.0.1
```

**OpenSSL client → this project's server**
```bash
./tcp_server
openssl s_client -connect 127.0.0.1:9002 -tls1_2 -cipher DHE-RSA-AES256-SHA256 \
    -cert client_cert.pem -key client_key.pem -CAfile ca_cert.pem -verify_ip 127.0.0.1
#  → New, TLSv1.2, Cipher is DHE-RSA-AES256-SHA256 ... Verify return code: 0 (ok)
```

**Failure cases (each one is rejected with the correct alert)**

| Scenario | Result |
|----------|--------|
| Client presents no certificate | Server: `handshake_failure` |
| Client only speaks TLS 1.3, or offers other cipher suites | Server: `handshake_failure` |
| Server certificate doesn't contain the IP the client used | Client: `IP address mismatch` → `bad_certificate` |
| Certificate signed by a different CA | `unable to get local issuer certificate` → `bad_certificate` |
| A man-in-the-middle flips one bit of an encrypted record | Receiver: `bad_record_mac`, connection closed |

The code also runs cleanly under AddressSanitizer and UndefinedBehaviorSanitizer, and compiles without warnings with `-Wall -Wextra` on GCC (Linux) and MinGW-w64 (Windows).

---

## Security Notes & Limitations

This is a **learning project**. Use a maintained library such as OpenSSL's `libssl`, BoringSSL or mbedTLS for anything real.

- **One cipher suite, TLS 1.2 only.** CBC mode with MAC-then-encrypt is legacy design. Modern TLS uses AEAD ciphers (AES-GCM, ChaCha20-Poly1305) and TLS 1.3.
- **Not fully constant-time.** Padding and MAC failures produce the same alert, but timing differences remain (the "Lucky 13" class of attacks).
- **No session resumption, renegotiation, or Extended Master Secret (RFC 7627).**
- **No revocation checking** (CRL / OCSP).
- **A demo CA.** `certgen` keeps the CA private key next to the other files. A real CA keeps it offline.
- The server handles **one client at a time**.

---

## Further Reading

- [RFC 5246 – The TLS Protocol Version 1.2](https://datatracker.ietf.org/doc/html/rfc5246)
- [RFC 5280 – Internet X.509 PKI Certificate and CRL Profile](https://datatracker.ietf.org/doc/html/rfc5280)
- [RFC 7919 – Negotiated Finite Field DH Ephemeral Parameters for TLS](https://datatracker.ietf.org/doc/html/rfc7919)
- [RFC 5746 – TLS Renegotiation Indication Extension](https://datatracker.ietf.org/doc/html/rfc5746)
- [The Illustrated TLS 1.2 Connection](https://tls12.xargs.org/)
- [OpenSSL 3 documentation](https://www.openssl.org/docs/man3.0/)
- [Microsoft – Getting Started with Winsock](https://learn.microsoft.com/en-us/windows/win32/winsock/getting-started-with-winsock)
