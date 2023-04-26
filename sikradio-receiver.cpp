#include <boost/program_options.hpp>
#include <iostream>
#include <csignal>
#include <thread>
#include <mutex>
#include "common.h"

#define DEFAULT_BSIZE 65536
#define UDP_MAX_SIZE 65507

using namespace std;
namespace po = boost::program_options;

static bool finish = false;
byte_t *buffer;
mutex buffer_mutex;
bool new_session = true;
size_t written_to_buffer = 0;

static void catch_int(int sig) {
    finish = true;
    cerr << "Signal " << sig << " caught, exiting..." << endl;
}

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

void print_buffer(size_t bsize, size_t psize) {
    size_t it = 0;
    size_t written_from_buffer = 0;

    unique_lock<mutex> lock(buffer_mutex, defer_lock);

    while (!finish && !new_session) {
        lock.lock();
        fwrite(buffer + it, sizeof(byte_t), psize, stdout);
        lock.unlock();

        written_from_buffer += psize;
        it += psize;
        if (it + psize >= bsize) {
            it = 0;
        }
        while (written_from_buffer >= written_to_buffer) {
            this_thread::sleep_for(chrono::milliseconds(10));
        }
    }
}

int main(int argc, char *argv[]) {
    string address_input, port_input;
    size_t bsize;

//    install_signal_handler(SIGINT, catch_int, SA_RESTART);

    read_program_options(argc, argv, address_input, port_input, bsize);
    cerr << "a: " << address_input << endl;
    cerr << "P: " << port_input << endl;
    cerr << "b: " << bsize << endl;

    char *addr = (char *) address_input.c_str();
    char *port = (char *) port_input.c_str();

    buffer = new byte_t[bsize];
    byte_t rcv_buffer[UDP_MAX_SIZE];
    memset(buffer, 0, bsize * sizeof(byte_t));
    memset(rcv_buffer, 0, sizeof(rcv_buffer));

    uint16_t port_num = read_port(port);
    int socket_fd = bind_socket(port_num);
    struct sockaddr_in source_address = get_address(addr, 0);
    struct sockaddr_in sender_address{};
    size_t read_length;
    size_t psize = 0;
    uint64_t session_id = 0;
    uint64_t byte_0 = 0;
    thread printer;
    bool p_started = false;
    set<uint64_t> received_packets;

    do {
        read_length = read_message(socket_fd, &sender_address, rcv_buffer,
                                   sizeof(rcv_buffer));
        if (read_length > 0) {
            if (strcmp(inet_ntoa(source_address.sin_addr),
                       inet_ntoa(sender_address.sin_addr)) != 0) {
                cerr << "Received packet from wrong address, skipping" << endl;
                continue;
            }

            uint64_t tmp_id;
            memcpy(&tmp_id, rcv_buffer, sizeof(uint64_t));
            tmp_id = ntohl(tmp_id);

            uint64_t first_byte_num;
            memcpy(&first_byte_num, rcv_buffer + sizeof(uint64_t), sizeof(uint64_t));
            first_byte_num = ntohl(first_byte_num);

            if (session_id == 0) {
                session_id = tmp_id;
                byte_0 = first_byte_num;
                psize = read_length - sizeof(uint64_t) * 2;
                new_session = false;
                written_to_buffer = 0;
            } else if (session_id > tmp_id) {
                continue;
            } else if (session_id < tmp_id) {
                session_id = 0;
                received_packets.clear();
                new_session = true;
                printer.join();
                p_started = false;
                memset(buffer, 0, bsize * sizeof(byte_t));
                continue;
            }

            received_packets.insert(first_byte_num);
            uint64_t earliest = max(byte_0, first_byte_num - bsize + (bsize % psize));
            for (uint64_t i = earliest; i < first_byte_num; i += psize) {
                if (received_packets.find(i) == received_packets.end()) {
                    cerr << "MISSING: BEFORE " << first_byte_num
                         << " EXPECTED " << i << endl;
                }
            }

            size_t buf_position = first_byte_num - byte_0;
            if (buf_position >= bsize) {
                buf_position = buf_position % bsize + (bsize % psize);
            }
            if (buf_position + psize >= bsize) {
                buf_position = 0;
            }

            unique_lock<mutex> lock(buffer_mutex);
            memcpy(buffer + buf_position, rcv_buffer + sizeof(uint64_t) * 2,
                   read_length - sizeof(uint64_t) * 2);
            lock.unlock();

            if (first_byte_num - byte_0 > written_to_buffer) {
                written_to_buffer = first_byte_num - byte_0;
            }

            if (first_byte_num >= byte_0 + ((3 * bsize) / 4) && !p_started) {
                p_started = true;
                printer = thread(print_buffer, bsize, psize);
            }

        }
    } while (!finish && read_length > 0);

    if (p_started) {
        printer.join();
    }
    delete[] buffer;
    CHECK_ERRNO(close(socket_fd));

    return 0;
}
