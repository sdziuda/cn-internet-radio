#include <boost/program_options.hpp>
#include <iostream>
#include "common.h"

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
    byte_t buffer[bsize];
    memset(buffer, 0, sizeof(buffer));

    uint16_t port_num = read_port(port);
    int socket_fd = bind_socket(port_num);
    struct sockaddr_in source_address = get_address(addr, 0);
    struct sockaddr_in sender_address{};
    size_t read_length;
    size_t psize = 0;
    uint64_t session_id = 0;
    uint64_t byte_0 = 0;

    do {
        read_length = read_message(socket_fd, &sender_address, buffer, sizeof(buffer));
        if (read_length > 0) {
            if (strcmp(inet_ntoa(source_address.sin_addr),
                       inet_ntoa(sender_address.sin_addr)) != 0) {
                cerr << "Received packet from wrong address, skipping" << endl;
                continue;
            }

            uint64_t tmp_id;
            memcpy(&tmp_id, buffer, sizeof(uint64_t));
            tmp_id = ntohl(tmp_id);

            uint64_t first_byte_num;
            memcpy(&first_byte_num, buffer + sizeof(uint64_t), sizeof(uint64_t));
            first_byte_num = ntohl(first_byte_num);

            if (session_id == 0) {
                session_id = tmp_id;
                byte_0 = first_byte_num;
                psize = read_length - sizeof(uint64_t) * 2;
            } else if (session_id > tmp_id) {
                continue;
            } else if (session_id < tmp_id) {
                session_id = 0;
                memset(buffer, 0, sizeof(buffer));
                continue;
            } else {
                size_t header_len = sizeof(uint64_t) * 2 + psize;
                size_t buf_position = first_byte_num - byte_0 + header_len;
                memcpy(buffer + buf_position, buffer + sizeof(uint64_t) * 2, psize);
                for (size_t i = sizeof(uint64_t) * 2; i < buf_position; i += psize) {
                    if (buffer[i] == 0) {
                        cerr << "MISSING: BEFORE " << first_byte_num << " EXPECTED "
                             << first_byte_num - (buf_position - i) << endl;
                    }
                }

                if (buf_position >= (3 * bsize) / 4) {
                    size_t write_size = buf_position + psize - header_len;
                    fwrite(buffer + header_len, sizeof(byte_t), write_size, stdout);
                    byte_0 = first_byte_num + psize;
                    memset(buffer, 0, sizeof(buffer));
                }
            }
        }
    } while (read_length > 0);

    CHECK_ERRNO(close(socket_fd));

    return 0;
}
