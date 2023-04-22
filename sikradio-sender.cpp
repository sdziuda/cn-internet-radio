#include <boost/program_options.hpp>
#include <iostream>
#include "common.h"

#define DEFAULT_PORT "28422"
#define DEFAULT_PSIZE 512
#define DEFAULT_NAME "Nienazwany nadajnik"

using namespace std;
namespace po = boost::program_options;

void read_program_options(int argc, char *argv[], string &address, string &port,
                          size_t &psize) {
    if (argc < 2) {
        cerr << "usage: " << argv[0] << " -a [address: required] "
                                        "-p [PSIZE: default 512] "
                                        "-P [port: default 28422] "
                                        "-n [name: default Nienazwany nadajnik]"
                                        << endl;
        exit(1);
    }

    po::options_description desc("Program options");
    desc.add_options()
        ("a,a", po::value<string>(), "address")
        ("P,P", po::value<string>()->default_value(DEFAULT_PORT), "port")
        ("p,p", po::value<size_t>()->default_value(DEFAULT_PSIZE), "PSIZE")
        ("n,n", po::value<string>()->default_value(DEFAULT_NAME), "name");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("a") == 0) {
        cerr << "error: missing address" << endl;
        exit(1);
    }

    address = vm["a"].as<string>();
    port = vm["P"].as<string>();
    psize = vm["p"].as<size_t>();
}

int main(int argc, char *argv[]) {
    string address_input, port_input;
    size_t psize;

    read_program_options(argc, argv, address_input, port_input, psize);
    cerr << "a: " << address_input << endl;
    cerr << "P: " << port_input << endl;
    cerr << "p: " << psize << endl;

    char *addr = (char *) address_input.c_str();
    char *port = (char *) port_input.c_str();
    char buffer[psize + sizeof(uint64_t) * 2];
    memset(buffer, 0, sizeof(buffer));

    uint16_t port_num = read_port(port);
    struct sockaddr_in send_address = get_address(addr, port_num);

    int socket_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        perror("invalid socket");
        exit(1);
    }

    uint64_t session_id = time(nullptr);
    cerr << "session_id: " << session_id << endl;
    uint64_t net_session_id = htonl(session_id);
    uint64_t first_byte_num = 0;
    memcpy(buffer, &net_session_id, sizeof(net_session_id));

    while (true) {
        uint64_t net_first_byte_num = htonl(first_byte_num);
        memcpy(buffer + sizeof(net_session_id), &net_first_byte_num, sizeof(net_first_byte_num));

        ssize_t read_bytes = read(STDIN_FILENO, buffer + sizeof(net_session_id) + sizeof(net_first_byte_num), psize - 1);
        cerr << "read_bytes: " << read_bytes << endl;
        if (read_bytes < 0) {
            perror("read error");
            exit(1);
        } else if ((size_t) read_bytes < psize - 1) {
            break;
        }
        buffer[psize - 1] = '\0';

        send_message(socket_fd, &send_address, &buffer, sizeof(buffer));

        first_byte_num += psize;
    }

    CHECK_ERRNO(close(socket_fd));

    return 0;
}
