#ifndef MIMUW_SIK_TCP_SOCKETS_COMMON_H
#define MIMUW_SIK_TCP_SOCKETS_COMMON_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <fcntl.h>
#include <cstdio>
#include <cstring>
#include <cstdint>
#include <csignal>

#include "err.h"

#define DEFAULT_CONTROL "38422"
#define DEFAULT_RTIME 250
#define UDP_MAX_SIZE 65507
#define LOOKUP_HEADER "ZERO_SEVEN_COME_IN\n"
#define LOOKUP_HEADER_SIZE 19
#define REXMIT_HEADER "LOUDER_PLEASE "
#define REXMIT_HEADER_SIZE strlen(REXMIT_HEADER)

using byte_t = uint8_t;

inline static uint16_t read_port(char *string) {
    for (char *c = string; *c != '\0'; c++) {
        if (*c < '0' || *c > '9') {
            fatal("%s is not a valid port number", string);
        }
    }

    errno = 0;
    unsigned long port = strtoul(string, nullptr, 10);
    PRINT_ERRNO();
    if (port > UINT16_MAX) {
        fatal("%u is not a valid port number", port);
    }

    return (uint16_t) port;
}

inline static void bind_socket(int socket_fd, uint16_t port) {
    // making the socket non-blocking
    fcntl(socket_fd, F_SETFL, O_NONBLOCK);

    struct sockaddr_in address{};
    address.sin_family = AF_INET; // IPv4
    address.sin_addr.s_addr = htonl(INADDR_ANY); // listening on all interfaces
    address.sin_port = htons(port);

    // bind the socket to a concrete address
    CHECK_ERRNO(bind(socket_fd, (struct sockaddr *) &address,
                     (socklen_t) sizeof(address)));
}

inline static int open_udp_socket() {
    int socket_fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        PRINT_ERRNO();
    }

    return socket_fd;
}

inline static struct sockaddr_in get_address(char *host, uint16_t port) {
    struct addrinfo hints{};
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *address_result;
    CHECK(getaddrinfo(host, nullptr, &hints, &address_result));

    struct sockaddr_in address{};
    address.sin_family = AF_INET; // IPv4
    address.sin_addr.s_addr =
            ((struct sockaddr_in *) (address_result->ai_addr))->sin_addr.s_addr; // IP address
    address.sin_port = htons(port);

    freeaddrinfo(address_result);

    return address;
}

inline void send_message(int socket_fd, const struct sockaddr_in *send_address,
                  const void *message, size_t message_length) {
    int send_flags = 0;
    auto address_length = (socklen_t) sizeof(*send_address);
    errno = 0;
    ssize_t sent_length = sendto(socket_fd, message, message_length, send_flags,
                                 (struct sockaddr *) send_address, address_length);
    if (sent_length < 0) {
        PRINT_ERRNO();
    }
    ENSURE(sent_length == (ssize_t) message_length);
}

inline size_t read_message(int socket_fd, struct sockaddr_in *client_address,
                    void *buffer, size_t max_length) {
    auto address_length = (socklen_t) sizeof(*client_address);
    int flags = 0; // we do not request anything special
    errno = 0;
    ssize_t len = recvfrom(socket_fd, buffer, max_length, flags,
                           (struct sockaddr *) client_address, &address_length);
    if (errno == EAGAIN) {
        return 0;
    }
    if (len < 0) {
        PRINT_ERRNO();
    }
    return (size_t) len;
}

inline static void install_signal_handler(int signal, void (*handler)(int), int flags) {
    struct sigaction action{};
    sigset_t block_mask;

    sigemptyset(&block_mask);
    action.sa_handler = handler;
    action.sa_mask = block_mask;
    action.sa_flags = flags;

    CHECK_ERRNO(sigaction(signal, &action, nullptr));
}

#endif //MIMUW_SIK_TCP_SOCKETS_COMMON_H
