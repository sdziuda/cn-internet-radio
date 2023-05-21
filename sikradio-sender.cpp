#include <boost/program_options.hpp>
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <ctime>
#include <cstdio>
#include <thread>
#include <mutex>
#include "common.h"

#define DEFAULT_PORT "28422"
#define DEFAULT_PSIZE 512
#define DEFAULT_FSIZE 131072
#define DEFAULT_NAME "Nienazwany Nadajnik"

using std::string;
namespace po = boost::program_options;

bool finished = false;

void help_and_exit(string name) {
    std::cerr << "usage: " << name << " -a [multicast_address: required] "
              << "-p [PSIZE: default 512] -f [FSIZE: default " << DEFAULT_FSIZE
              << "] -P [data_port: default " << DEFAULT_PORT << "] -C "
              << "[control_port: default " << DEFAULT_CONTROL << "] -R [RTIME: "
              << "default " << DEFAULT_RTIME << "] -n [name: default "
              << DEFAULT_NAME << "]" << std::endl;
    exit(1);
}

bool check_name(string name) {
    if (name.size() == 0) {
        return false;
    }

    if (name[0] == ' ' || name[name.size() - 1] == ' ') {
        return false;
    }

    for (char c : name) {
        if (c < 32 || c > 127) {
            return false;
        }
    }

    return true;
}

bool check_size(size_t size) {
    return size >= 1 && size <= UDP_MAX_SIZE - sizeof(uint64_t) * 2;
}

void read_program_options(int argc, char *argv[], string &address, string &d_port,
                          string &c_port, size_t &psize, size_t &fsize, uint64_t &rtime,
                          string &name) {
    if (argc < 2) {
        help_and_exit(argv[0]);
    }

    po::options_description desc("Program options");
    desc.add_options()
        ("a,a", po::value<string>(), "address")
        ("P,P", po::value<string>()->default_value(DEFAULT_PORT), "port")
        ("C,C", po::value<string>()->default_value(DEFAULT_CONTROL), "control port")
        ("p,p", po::value<size_t>()->default_value(DEFAULT_PSIZE), "PSIZE")
        ("f,f", po::value<size_t>()->default_value(DEFAULT_FSIZE), "FSIZE")
        ("R,R", po::value<uint64_t>()->default_value(DEFAULT_RTIME), "RTIME")
        ("n,n", po::value<string>()->default_value(DEFAULT_NAME), "name");

    po::variables_map vm;

    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch (std::exception &e) {
        std::cerr << "error: " << e.what() << std::endl;
        exit(1);
    }

    if (vm.count("a") == 0) {
        std::cerr << "error: missing address" << std::endl;
        exit(1);
    }

    address = vm["a"].as<string>();
    d_port = vm["P"].as<string>();
    c_port = vm["C"].as<string>();
    psize = vm["p"].as<size_t>();
    fsize = vm["f"].as<size_t>();
    rtime = vm["R"].as<uint64_t>();
    name = vm["n"].as<string>();

    if (!check_name(name)) {
        std::cerr << "error: invalid name" << std::endl;
        exit(1);
    }

    if (!check_size(psize)) {
        std::cerr << "error: invalid PSIZE" << std::endl;
        exit(1);
    }
}

void listen_control(char* addr, uint16_t port) {
    byte_t buffer[UDP_MAX_SIZE];
    memset(buffer, 0, sizeof(buffer));

    int socket_fd = open_udp_socket();
    struct ip_mreq ip_mreq;
    ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (inet_aton(addr, &ip_mreq.imr_multiaddr) == 0) {
        fatal("inet_aton - invalid multicast address\n");
    }

    CHECK_ERRNO(setsockopt(socket_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*)&ip_mreq,
                           sizeof(ip_mreq)));
    bind_socket(socket_fd, port);

    struct sockaddr_in sender_address;

    while (!finished) {
        size_t read_length = read_message(socket_fd, &sender_address, buffer,
                                          sizeof(buffer));
        if (read_length == 0) {
            continue;
        }

        printf("%.*s\n", (int)read_length, buffer);
    }

    CHECK_ERRNO(setsockopt(socket_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, (void*)&ip_mreq,
                           sizeof(ip_mreq)));
}

int main(int argc, char *argv[]) {
    string address_input, d_port_input, c_port_input, name;
    size_t psize, fsize;
    uint64_t rtime;

    install_signal_handler(SIGINT, catch_int, SA_RESTART);

    read_program_options(argc, argv, address_input, d_port_input, c_port_input,
                         psize, fsize, rtime, name);

    std::cerr << "address: " << address_input << std::endl;
    std::cerr << "data port: " << d_port_input << std::endl;
    std::cerr << "control port: " << c_port_input << std::endl;
    std::cerr << "psize: " << psize << std::endl;
    std::cerr << "fsize: " << fsize << std::endl;
    std::cerr << "rtime: " << rtime << std::endl;
    std::cerr << "name: " << name << std::endl;

    char *addr = (char *) address_input.c_str();
    char *d_port = (char *) d_port_input.c_str();
    char *c_port = (char *) c_port_input.c_str();
    byte_t buffer[psize + sizeof(uint64_t) * 2];
    memset(buffer, 0, sizeof(buffer));

    uint16_t d_port_num = read_port(d_port);
    uint16_t c_port_num = read_port(c_port);
    if (c_port_num == d_port_num) {
        std::cerr << "error: data port and control port must be different" << std::endl;
        exit(1);
    }

    std::thread control_thread(listen_control, addr, c_port_num);

    int socket_fd = open_udp_socket();
    struct sockaddr_in send_address = get_address(addr, d_port_num);
    uint64_t session_id = time(nullptr);
    uint64_t net_session_id = htonll(session_id);
    uint64_t first_byte_num = 0;
    memcpy(buffer, &net_session_id, sizeof(net_session_id));

    while (true) {
        uint64_t net_first_byte_num = htonll(first_byte_num);
        memcpy(buffer + sizeof(uint64_t), &net_first_byte_num, sizeof(uint64_t));

        size_t read_bytes = fread(buffer + sizeof(uint64_t) * 2, sizeof(byte_t),
                                  psize, stdin);

        if (read_bytes < psize) {
            break;
        }

        send_message(socket_fd, &send_address, &buffer, sizeof(buffer));

        first_byte_num += psize;
    }

    finished = true;
    control_thread.join();

    CHECK_ERRNO(close(socket_fd));

    return 0;
}
