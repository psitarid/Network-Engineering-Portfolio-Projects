[IN PROGRESS...]

# CLIENT-SERVER COMMUNICATION OVER TLS (IN C PROGRAMMING LANGUAGE)

This project is my attempt on a secure client-server communication using TLS in C. 
Initially both the client and the server create a self-signed X509 certificate and check its validity. Then a TCP connection is established and then TLS handshake begins.

1. Client ----- [ Ver ] [ Rand# ] [ Ciphers ] -----> Server<br>

     • Ver : The latest TLS version supported by the client.<br>
     • Rand# : A large random number which will be used as a seed to generate the session keys later.<br>
     • Ciphers : A list with all the available cipher suites supported by the client.<br>

3. Server ----- [ Ver ] [ Rand# ] [CipherSuite] -----> Client <br>

     • Ver : The latest TLS version that is mutually supported by both the client and the server.<br>
     • Rand# : A large random number wich will be used as a seed to generate the session keys later.<br>
     • CipherSuite : The server's choice of cipher suite out of the client's 'Ciphers' list.<br>
       The cipher suite chosen for this project is "DHE-RSA-AES256-SHA256"<br>
         - Key Exchange: Diffie-Hellman Ephemeral<br>
         - Authentication: RSA<br>
         - Bulk Encryption: AES-256-CBC<br>
         - MAC: SHA256<br>
