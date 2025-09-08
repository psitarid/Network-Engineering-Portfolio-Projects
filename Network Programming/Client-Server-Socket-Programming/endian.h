#ifndef PORTABLE_ENDIAN_H
#define PORTABLE_ENDIAN_H

#include <stdint.h>
#include <winsock2.h>   // for htonl / ntohl on Windows
#include <ws2tcpip.h>

#if defined(_WIN32)

// Windows does not provide htobe64/be64toh, so we implement them.
#define htobe64(x) (((uint64_t)htonl((uint32_t)((x) >> 32))) | \
                   ((uint64_t)htonl((uint32_t)(x)) << 32))

#define be64toh(x) (((uint64_t)ntohl((uint32_t)((x) >> 32))) | \
                   ((uint64_t)ntohl((uint32_t)(x)) << 32))

#else
    // On Linux, BSD, etc. these may already exist in <endian.h> or <sys/endian.h>
    #include <arpa/inet.h>
    #if defined(__APPLE__)
        #include <libkern/OSByteOrder.h>
        #define htobe64(x) OSSwapHostToBigInt64(x)
        #define be64toh(x) OSSwapBigToHostInt64(x)
    #elif defined(__linux__)
        #include <endian.h>
    #endif
#endif

#endif // PORTABLE_ENDIAN_H
