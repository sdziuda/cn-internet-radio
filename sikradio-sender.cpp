#include <boost/program_options.hpp>
#include <iostream>
#include "common.h"

using namespace std;
namespace po = boost::program_options;

void read_program_options(int argc, char *argv[], string &address, string &port,
                          size_t &psize) {
    if (argc < 2) {
        cerr << "usage: " << argv[0] << " -a [address: required] "
                                        "-p [psize: default 512] "
                                        "-P [port: default 28422] "
                                        "-n [name: default Nienazwany nadajnik]"
                                        << endl;
        exit(1);
    }

    po::options_description desc("Program options");
    desc.add_options()
        ("a,a", po::value<string>(), "address")
        ("P,P", po::value<string>()->default_value("28422"), "port")
        ("p,p", po::value<size_t>()->default_value(512), "PSIZE")
        ("n,n", po::value<string>()->default_value("Nienazwany nadajnik"), "name");

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
    cerr << "P: " << port_input << endl;
    cerr << "a: " << address_input << endl;
    cerr << "p: " << psize << endl;

    char *addr = (char *) address_input.c_str();
    char *port = (char *) port_input.c_str();
    char *buffer = new char[psize + 1];

    uint16_t port_num = read_port(port);
    struct sockaddr_in send_address = get_address(addr, port_num);

    int socket_fd = socket(PF_INET, SOCK_DGRAM, 0);
    if (socket_fd < 0) {
        perror("invalid socket");
        exit(1);
    }

    size_t session_id = time(nullptr);

    while (true) {
        ssize_t read_bytes = read(STDIN_FILENO, buffer, psize);
        cerr << "read_bytes: " << read_bytes << endl;
        if (read_bytes < 0) {
            perror("read error");
            exit(1);
        } else if ((size_t) read_bytes < psize) {
            break;
        }
        buffer[psize] = '\0';

        send_message(socket_fd, &send_address, buffer, psize);
    }

    delete[] buffer;
    CHECK_ERRNO(close(socket_fd));

    return 0;
}
