#ifndef MIMUW_SIK_TCP_SOCKETS_COMMON_H
#define MIMUW_SIK_TCP_SOCKETS_COMMON_H

#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdint.h>
#include <arpa/inet.h>

#include "err.h"

inline static uint16_t read_port(char *string) {
    errno = 0;
    unsigned long port = strtoul(string, nullptr, 10);
    PRINT_ERRNO();
    if (port > UINT16_MAX) {
        fatal("%u is not a valid port number", port);
    }

    return (uint16_t) port;
}

inline static struct sockaddr_in get_address(char *host, uint16_t port) {
    struct addrinfo hints;
    memset(&hints, 0, sizeof(struct addrinfo));
    hints.ai_family = AF_INET; // IPv4
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    struct addrinfo *address_result;
    CHECK(getaddrinfo(host, NULL, &hints, &address_result));

    struct sockaddr_in address;
    address.sin_family = AF_INET; // IPv4
    address.sin_addr.s_addr =
            ((struct sockaddr_in *) (address_result->ai_addr))->sin_addr.s_addr; // IP address
    address.sin_port = htons(port);

    freeaddrinfo(address_result);

    return address;
}

void send_message(int socket_fd, const struct sockaddr_in *send_address,
                  const char *message, size_t message_length) {
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

#endif //MIMUW_SIK_TCP_SOCKETS_COMMON_H
