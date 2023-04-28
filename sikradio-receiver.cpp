#include <boost/program_options.hpp>
#include <iostream>
#include <csignal>
#include <thread>
#include <mutex>
#include <cstring>
#include <sys/socket.h>
#include <cstdio>
#include "common.h"

#define DEFAULT_BSIZE 65536
#define UDP_MAX_SIZE 65507

using std::string;
namespace po = boost::program_options;

const char BLANK = 0;

static bool finish = false;
static bool p_finish = false;
byte_t *buffer;
std::mutex buffer_mutex;
size_t written_to_buffer = 0;
std::set<uint64_t> received_packets;

static void catch_int(int sig) {
    finish = true;
    std::cerr << "Signal " << sig << " caught, exiting..." << std::endl;
}

void read_program_options(int argc, char *argv[], string &address, string &port,
                          size_t &bsize) {
    if (argc < 2) {
        std::cerr << "usage: " << argv[0] << " -a [address: required] "
                                             "-P [port: default 28422] "
                                             "-b [BSIZE: default 65536]"
                                             << std::endl;
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
        std::cerr << "error: missing address" << std::endl;
        exit(1);
    }

    address = vm["a"].as<string>();
    port = vm["P"].as<string>();
    bsize = vm["b"].as<size_t>();
}

void print_buffer(size_t bsize, size_t psize) {
    size_t it = 0;
    size_t written_from_buffer = 0;

    std::unique_lock<std::mutex> lock(buffer_mutex, std::defer_lock);

    while (true) {
        lock.lock();
        if (p_finish) return;

        if (written_from_buffer <= written_to_buffer) {
            if (received_packets.find(written_from_buffer) != received_packets.end()) {
                fwrite(buffer + it, sizeof(byte_t), psize, stdout);
                memset(buffer + it, BLANK, psize);
            } else {
                for (size_t i = 0; i < psize; i++) {
                    std::cout << BLANK;
                }
            }

            written_from_buffer += psize;
            it += psize;
            if (it + psize >= bsize) {
                it = 0;
            }
        }
        lock.unlock();
    }
}

int main(int argc, char *argv[]) {
    string address_input, port_input;
    size_t bsize;

    install_signal_handler(SIGINT, catch_int, SA_RESTART);

    read_program_options(argc, argv, address_input, port_input, bsize);

    char *addr = (char *) address_input.c_str();
    char *port = (char *) port_input.c_str();

    buffer = new byte_t[bsize];
    byte_t rcv_buffer[UDP_MAX_SIZE];
    memset(buffer, BLANK, bsize * sizeof(byte_t));
    memset(rcv_buffer, 0, sizeof(rcv_buffer));

    uint16_t port_num = read_port(port);
    int socket_fd = bind_socket(port_num);
    struct sockaddr_in source_address = get_address(addr, 0);
    struct sockaddr_in sender_address{};
    size_t read_length;
    size_t psize = 0;
    uint64_t session_id = 0;
    bool session_set = false;
    uint64_t byte_0 = 0;
    std::thread printer;
    bool p_started = false;
    std::unique_lock<std::mutex> lock(buffer_mutex, std::defer_lock);

    do {
        read_length = read_message(socket_fd, &sender_address, rcv_buffer,
                                   sizeof(rcv_buffer));
        if (read_length > 0) {
            if (read_length < 16) {
                std::cerr << "Received packet of wrong size, skipping" << std::endl;
                continue;
            }
            if (source_address.sin_addr.s_addr != sender_address.sin_addr.s_addr) {
                std::cerr << "Received packet from wrong address, skipping" << std::endl;
                continue;
            }

            uint64_t tmp_id;
            memcpy(&tmp_id, rcv_buffer, sizeof(uint64_t));
            tmp_id = ntohll(tmp_id);

            uint64_t first_byte_num;
            memcpy(&first_byte_num, rcv_buffer + sizeof(uint64_t), sizeof(uint64_t));
            first_byte_num = ntohll(first_byte_num);

            if (!session_set) {
                session_id = tmp_id;
                session_set = true;
                byte_0 = first_byte_num;
                psize = read_length - sizeof(uint64_t) * 2;
                written_to_buffer = 0;
            } else if (session_id > tmp_id) {
                continue;
            } else if (session_id < tmp_id) {
                session_set = false;

                lock.lock();
                p_finish = true;
                received_packets.clear();
                lock.unlock();
                printer.join();
                p_started = false;

                memset(buffer, BLANK, bsize * sizeof(byte_t));
                continue;
            }

            if (read_length != psize + sizeof(uint64_t) * 2) {
                std::cerr << "Received packet of wrong size, skipping" << std::endl;
                continue;
            }

            lock.lock();
            if (written_to_buffer > bsize && first_byte_num < written_to_buffer - bsize) {
                std::cerr << "Received package too old, skipping" << std::endl;
                lock.unlock();
                continue;
            }
            received_packets.insert(first_byte_num);
            lock.unlock();

            uint64_t earliest;
            if (first_byte_num < bsize) {
                earliest = byte_0;
            } else {
                earliest = std::max(byte_0, first_byte_num - bsize + (bsize % psize));
            }
            for (uint64_t i = earliest; i < first_byte_num; i += psize) {
                lock.lock();
                if (received_packets.find(i) == received_packets.end()) {
                   std::cerr << "MISSING: BEFORE " << first_byte_num
                             << " EXPECTED " << i << std::endl;
                }
                lock.unlock();
            }

            size_t buf_position = first_byte_num - byte_0;
            if (buf_position >= bsize) {
                buf_position = buf_position % bsize + (bsize % psize);
            }
            if (buf_position + psize >= bsize) {
                buf_position = 0;
            }

            lock.lock();
            memcpy(buffer + buf_position, rcv_buffer + sizeof(uint64_t) * 2,
                   read_length - sizeof(uint64_t) * 2);
            if (first_byte_num - byte_0 > written_to_buffer) {
                written_to_buffer = first_byte_num - byte_0;
            }
            lock.unlock();

            if (first_byte_num >= byte_0 + ((3 * bsize) / 4) && !p_started) {
                p_started = true;
                p_finish = false;
                printer = std::thread(print_buffer, bsize, psize);
            }
        }
    } while (!finish);

    lock.lock();
    p_finish = true;
    lock.unlock();
    if (p_started) {
        printer.join();
    }
    delete[] buffer;
    CHECK_ERRNO(close(socket_fd));

    return 0;
}
