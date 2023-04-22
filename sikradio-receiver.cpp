#include <boost/program_options.hpp>
#include <iostream>
#include "common.h"

#define DEFAULT_PORT "28422"
#define DEFAULT_BSIZE 65536

using namespace std;
namespace po = boost::program_options;

void read_program_options(int argc, char *argv[], string &address, string &port,
                          size_t &bsize) {
    if (argc < 2) {
        cerr << "usage: " << argv[0] << " -a [address: required] "
                                        "-P [port: default 28422] "
                                        "-b [BSIZE: default 65536]"
                                        << endl;
        exit(1);
    }

    po::options_description desc("Program options");

    desc.add_options()
        ("a,a", po::value<string>(), "address")
        ("P,P", po::value<string>()->default_value(DEFAULT_PORT), "port")
        ("b,b", po::value<size_t>()->default_value(DEFAULT_BSIZE), "BSIZE");

    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc), vm);
    po::notify(vm);

    if (vm.count("a") == 0) {
        cerr << "error: missing address" << endl;
        exit(1);
    }

    address = vm["a"].as<string>();
    port = vm["P"].as<string>();
    bsize = vm["b"].as<size_t>();
}

int main(int argc, char *argv[]) {
    string address_input, port_input;
    size_t bsize;

    read_program_options(argc, argv, address_input, port_input, bsize);
    cerr << "a: " << address_input << endl;
    cerr << "P: " << port_input << endl;
    cerr << "b: " << bsize << endl;

    char *addr = (char *) address_input.c_str();
    char *port = (char *) port_input.c_str();
    char buffer[bsize];
    memset(buffer, 0, sizeof(buffer));

    uint16_t port_num = read_port(port);
    int socket_fd = bind_socket(port_num);
    struct sockaddr_in sender_address{};
    size_t read_length;

    do {
        read_length = read_message(socket_fd, &sender_address, &buffer, sizeof(buffer));
        if (read_length > 0) {
            cerr << "Received " << read_length << " bytes from "
                 << inet_ntoa(sender_address.sin_addr) << ":"
                 << ntohs(sender_address.sin_port) << endl;
            size_t psize = read_length - sizeof(uint64_t) * 2;

            uint64_t session_id;
            memcpy(&session_id, buffer, sizeof(uint64_t));
            session_id = ntohl(session_id);
            cerr << "session_id: " << session_id << endl;
            uint64_t first_byte_num;
            memcpy(&first_byte_num, buffer + sizeof(uint64_t), sizeof(uint64_t));
            first_byte_num = ntohl(first_byte_num);
            cerr << "first_byte_num: " << first_byte_num << endl;
            cerr << "psize: " << psize << endl;

            cerr.write(buffer + sizeof(uint64_t) * 2, psize);
        }
    } while (read_length > 0);

    CHECK_ERRNO(close(socket_fd));

    return 0;
}
