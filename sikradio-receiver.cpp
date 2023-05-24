#include <boost/program_options.hpp>
#include <iostream>
#include <csignal>
#include <thread>
#include <mutex>
#include <cstring>
#include <sys/socket.h>
#include <cstdio>
#include "common.h"

#define DEFAULT_DISCOVER "255.255.255.255"
#define DEFAULT_UI "18422"
#define DEFAULT_PORT "28422"
#define DEFAULT_BSIZE 65536
#define DEFAULT_NAME ""

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

void helpAndExit(string name) {
    std::cerr << "usage: " << name << " "
              << "-d [discovery_address: default " << DEFAULT_DISCOVER << "] "
              << "-C [control_port: default " << DEFAULT_CONTROL << "] "
              << "-U [ui_port: default " << DEFAULT_UI << "] "
              << "-b [BSIZE: default " << DEFAULT_BSIZE << "] "
              << "-R [RTIME: default " << DEFAULT_RTIME << "] "
              << "-n [name: default None]"
              << std::endl;
    exit(1);
}

void read_program_options(int argc, char *argv[], string &d_address, string &c_port,
                          string &u_port, size_t &bsize, uint64_t &rtime, string &name,
                          string &address, string &port) {
    if (argc < 2) {
        helpAndExit(argv[0]);
    }

    po::options_description desc("Program options");

    desc.add_options()
        ("d,d", po::value<string>()->default_value(DEFAULT_DISCOVER), "discovery address")
        ("C,C", po::value<string>()->default_value(DEFAULT_CONTROL), "control port")
        ("U,U", po::value<string>()->default_value(DEFAULT_UI), "ui port")
        ("b,b", po::value<size_t>()->default_value(DEFAULT_BSIZE), "BSIZE")
        ("R,R", po::value<uint64_t>()->default_value(DEFAULT_RTIME), "RTIME")
        ("n,n", po::value<string>()->default_value(DEFAULT_NAME), "name")
        ("a,a", po::value<string>(), "multicast address")
        ("P,P", po::value<string>()->default_value(DEFAULT_PORT), "data port");

    po::variables_map vm;

    try {
        po::store(po::parse_command_line(argc, argv, desc), vm);
        po::notify(vm);
    } catch (std::exception &e) {
        std::cerr << "error: " << e.what() << std::endl;
        exit(1);
    }

    d_address = vm["d"].as<string>();
    c_port = vm["C"].as<string>();
    u_port = vm["U"].as<string>();
    bsize = vm["b"].as<size_t>();
    rtime = vm["R"].as<uint64_t>();
    name = vm["n"].as<string>();
    address = vm["a"].as<string>();
    port = vm["P"].as<string>();
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
    string d_address_input, c_port_input, u_port_input, name_input, address_input, d_port_input;
    size_t bsize;
    uint64_t rtime;

    install_signal_handler(SIGINT, catch_int, SA_RESTART);

    read_program_options(argc, argv, d_address_input, c_port_input, u_port_input,
                         bsize, rtime, name_input, address_input, d_port_input);

    char *addr = (char *) address_input.c_str();
    char *d_addr = (char *) d_address_input.c_str();
    char *d_port = (char *) d_port_input.c_str();
    char *c_port = (char *) c_port_input.c_str();
    char *u_port = (char *) u_port_input.c_str();

    buffer = new byte_t[bsize];
    byte_t rcv_buffer[UDP_MAX_SIZE];
    memset(buffer, BLANK, bsize * sizeof(byte_t));
    memset(rcv_buffer, 0, sizeof(rcv_buffer));

    uint16_t d_port_num = read_port(d_port);
    int socket_fd = open_udp_socket();
    struct ip_mreq ip_mreq;
    ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (inet_aton(addr, &ip_mreq.imr_multiaddr) == 0) {
        fatal("inet_aton - invalid multicast address\n");
    }

    CHECK_ERRNO(setsockopt(socket_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, (void*)&ip_mreq,
                           sizeof(ip_mreq)));
    bind_socket(socket_fd, d_port_num);

    uint16_t c_port_num = read_port(c_port);
    struct sockaddr_in c_address = get_address(d_addr, c_port_num);
    int c_socket_fd = open_udp_socket();
    int optval = 1;
    CHECK_ERRNO(setsockopt(c_socket_fd, SOL_SOCKET, SO_BROADCAST, (void *)&optval,
                           sizeof optval));

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

            uint64_t tmp_id;
            memcpy(&tmp_id, rcv_buffer, sizeof(uint64_t));
            tmp_id = be64toh(tmp_id);

            uint64_t first_byte_num;
            memcpy(&first_byte_num, rcv_buffer + sizeof(uint64_t), sizeof(uint64_t));
            first_byte_num = be64toh(first_byte_num);

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
            int msg_size = read_length - sizeof(uint64_t) * 2;
            std::cout.write((char *) (buffer + buf_position), msg_size);
            if (first_byte_num - byte_0 > written_to_buffer) {
                written_to_buffer = first_byte_num - byte_0;
            }
            lock.unlock();

//            byte_t control_msg[LOOKUP_HEADER_SIZE];
//            memcpy(control_msg, LOOKUP_HEADER, LOOKUP_HEADER_SIZE);
//            send_message(c_socket_fd, &c_address, control_msg, LOOKUP_HEADER_SIZE);
//            struct sockaddr_in control_address{};
//            byte_t c_buffer[UDP_MAX_SIZE];
//
//            while (true) {
//                size_t reply_length = read_message(c_socket_fd, &control_address,
//                                                   c_buffer, sizeof(c_buffer));
//                if (reply_length == 0) {
//                    continue;
//                }
//
//                string reply((char *)c_buffer, reply_length);
//                std::cerr << "Received: " << reply;
//                break;
//            }

            string msg = "LOUDER_PLEASE 0\n";
            if (strncmp((char *) (buffer + buf_position), "as\n", 3) == 0) {
                msg = "LOUDER_PLEASE 3\n";
            }
            byte_t rexmit_msg[strlen(msg.c_str())];
            memcpy(rexmit_msg, msg.c_str(), strlen(msg.c_str()));
            sender_address.sin_port = htons(c_port_num);
            send_message(c_socket_fd, &sender_address, rexmit_msg, strlen(msg.c_str()));

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
    CHECK_ERRNO(setsockopt(socket_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, (void*)&ip_mreq,
                           sizeof(ip_mreq)));
    CHECK_ERRNO(close(socket_fd));

    return 0;
}
