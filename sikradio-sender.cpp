#include <boost/program_options.hpp>
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <sys/time.h>
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

bool control_finished = false;
std::mutex send_mutex;
byte_t *retransmission_buffer = nullptr;
std::set<uint64_t> retransmission_set;

namespace {
    void help_and_exit(const string &name) {
        std::cerr << "usage: " << name << " "
                  << "-a [multicast_address: required] "
                  << "-p [PSIZE: default " << DEFAULT_PSIZE << "] "
                  << "-f [FSIZE: default " << DEFAULT_FSIZE << "] "
                  << "-P [data_port: default " << DEFAULT_PORT << "] "
                  << "-C [control_port: default " << DEFAULT_CONTROL << "] "
                  << "-R [RTIME: default " << DEFAULT_RTIME << "] "
                  << "-n [name: default " << DEFAULT_NAME << "]"
                  << std::endl;
        exit(1);
    }

    bool check_name(string name) {
        if (name.empty()) {
            return false;
        }

        if (name[0] == ' ' || name[name.size() - 1] == ' ') {
            return false;
        }

        if (!std::ranges::all_of(name, [](char c) { return c >= 32 && c <= 127; })) {
            return false;
        }

        return true;
    }

    bool check_size(size_t size) {
        return size >= 1 && size <= UDP_MAX_SIZE - sizeof(uint64_t) * 2;
    }

    void read_program_options(int argc, char *argv[], string &address, string &d_port,
                              string &c_port, size_t &psize, size_t &fsize,
                              uint64_t &rtime, string &name) {
        if (argc < 2) {
            help_and_exit(argv[0]);
        }

        po::options_description desc("Program options");
        desc.add_options()
                ("a,a", po::value<string>(), "address")
                ("P,P", po::value<string>()->default_value(DEFAULT_PORT), "data port")
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
            fatal("missing address");
        }

        address = vm["a"].as<string>();
        d_port = vm["P"].as<string>();
        c_port = vm["C"].as<string>();
        psize = vm["p"].as<size_t>();
        fsize = vm["f"].as<size_t>();
        rtime = vm["R"].as<uint64_t>();
        name = vm["n"].as<string>();

        if (!check_name(name)) {
            fatal("invalid name");
        }

        if (!check_size(psize)) {
            fatal("invalid PSIZE");
        }
    }

    void create_lookup_reply(byte_t *response, char *addr, char *port, char *name) {
        size_t index = 0;
        memcpy(response + index, "BOREWICZ_HERE ", 14);
        index += 14;
        memcpy(response + index, addr, strlen(addr));
        index += strlen(addr);
        response[index++] = ' ';
        memcpy(response + index, port, strlen(port));
        index += strlen(port);
        response[index++] = ' ';
        memcpy(response + index, name, strlen(name));
        index += strlen(name);
        response[index++] = '\n';
    }

    void parse_rexmit(const string &message, std::set<uint64_t> &rexmit) {
        size_t index = 14;
        while (index < message.size()) {
            size_t comma = message.find(',', index);
            if (comma == string::npos) {
                comma = message.size();
            }
            uint64_t number = stoull(message.substr(index, comma - index));
            rexmit.insert(number);
            index = comma + 1;
        }
    }


    void resend(std::set<uint64_t> rexmit, uint64_t session_id, size_t psize,
                int socket_fd, uint16_t port_num, char *addr) {
        std::unique_lock<std::mutex> lock(send_mutex, std::defer_lock);

        struct sockaddr_in send_address{};
        send_address.sin_family = AF_INET;
        send_address.sin_port = htons(port_num);
        if (inet_aton(addr, &send_address.sin_addr) == 0) {
            fatal("inet_aton - invalid multicast address");
        }

        byte_t buffer[psize + 2 * sizeof(uint64_t)];
        memcpy(buffer, &session_id, sizeof(uint64_t));

        while (!rexmit.empty()) {
            uint64_t number = *rexmit.begin();
            rexmit.erase(rexmit.begin());

            uint64_t net_number = htobe64(number);
            memcpy(buffer + sizeof(uint64_t), &net_number, sizeof(uint64_t));

            lock.lock();
            if (retransmission_set.find(number) == retransmission_set.end()) {
                lock.unlock();
                continue;
            }


            size_t index = number - *retransmission_set.begin();
            std::cerr << "retransmit: " << index << " ";
            memcpy(buffer + 2 * sizeof(uint64_t), retransmission_buffer + index, psize);
            std::cerr.write((char *) (buffer + 2 * sizeof(uint64_t)), psize);

            send_message(socket_fd, &send_address, buffer,
                         psize + 2 * sizeof(uint64_t));
            lock.unlock();
        }
    }


    void listen_control(char *addr, char *port, uint16_t port_num, char *name,
                        uint64_t rtime, uint64_t session_id, size_t psize,
                        int send_socket_fd, uint16_t send_port_num) {
        byte_t buffer[UDP_MAX_SIZE];
        memset(buffer, 0, sizeof(buffer));

        int socket_fd = open_udp_socket();
        bind_socket(socket_fd, port_num);

        struct sockaddr_in sender_address{};

        std::set<uint64_t> packets_to_resend;
        struct timeval last{};
        gettimeofday(&last, nullptr);
        std::thread retransmission;
        bool r_started = false;

        while (!control_finished) {
            struct timeval now{}, diff{};
            gettimeofday(&now, nullptr);
            timersub(&now, &last, &diff);
            uint64_t time_passed = diff.tv_sec * 1000 + diff.tv_usec / 1000;
            if (time_passed >= rtime || !r_started) {
                last = now;
                if (r_started) {
                    retransmission.join();
                }
                retransmission = std::thread(resend, packets_to_resend, session_id,
                                             psize, send_socket_fd, send_port_num,
                                             addr);
                r_started = true;
                packets_to_resend.clear();
            }

            size_t read_length = read_message(socket_fd, &sender_address, buffer,
                                              sizeof(buffer));
            if (read_length == 0) {
                continue;
            }

            string message = string((char *) buffer, read_length);
            std::cerr << "message: " << message;

            if (strcmp(message.c_str(), LOOKUP_HEADER) == 0) {
                byte_t reply[14 + strlen(addr) + strlen(port) + strlen(name) + 3];
                create_lookup_reply(reply, addr, port, name);
                send_message(socket_fd, &sender_address, &reply, sizeof(reply));
            } else if (strncmp(message.c_str(), REXMIT_HEADER,
                               REXMIT_HEADER_SIZE) == 0) {
                parse_rexmit(message, packets_to_resend);
            }
        }

        if (r_started) {
            retransmission.join();
        }
        CHECK_ERRNO(close(socket_fd));
    }
}

int main(int argc, char *argv[]) {
    string address_input, d_port_input, c_port_input, name;
    size_t psize, fsize;
    uint64_t rtime;

    read_program_options(argc, argv, address_input, d_port_input, c_port_input,
                         psize, fsize, rtime, name);

    char *addr = (char *) address_input.c_str();
    char *d_port = (char *) d_port_input.c_str();
    char *c_port = (char *) c_port_input.c_str();
    byte_t read_buffer[psize];
    byte_t buffer[psize + sizeof(uint64_t) * 2];
    memset(buffer, 0, sizeof(buffer));

    uint16_t d_port_num = read_port(d_port);
    uint16_t c_port_num = read_port(c_port);
    if (c_port_num == d_port_num) {
        fatal("data port and control port cannot be the same");
    }

    int socket_fd = open_udp_socket();
    struct sockaddr_in send_address{};
    send_address.sin_family = AF_INET;
    send_address.sin_port = htons(d_port_num);
    if (inet_aton(addr, &send_address.sin_addr) == 0) {
        fatal("inet_aton - invalid multicast address");
    }
    struct ip_mreq ip_mreq{};
    ip_mreq.imr_interface.s_addr = htonl(INADDR_ANY);
    if (inet_aton(addr, &ip_mreq.imr_multiaddr) == 0) {
        fatal("inet_aton - invalid multicast address\n");
    }
    CHECK_ERRNO(setsockopt(socket_fd, IPPROTO_IP, IP_ADD_MEMBERSHIP, &ip_mreq,
                           sizeof(ip_mreq)));

    uint64_t session_id = time(nullptr);
    uint64_t net_session_id = htobe64(session_id);
    uint64_t first_byte_num = 0;
    memcpy(buffer, &net_session_id, sizeof(net_session_id));

    try {
        retransmission_buffer = new byte_t[fsize];
    } catch(std::bad_alloc& e) {
        fatal("invalid fsize");
    }

    std::unique_lock<std::mutex> lock(send_mutex, std::defer_lock);
    std::thread control_thread(listen_control, addr, c_port, c_port_num,
                               (char *) name.c_str(), rtime, net_session_id,
                               psize, socket_fd, d_port_num);

    while (true) {
        uint64_t net_first_byte_num = htobe64(first_byte_num);
        memcpy(buffer + sizeof(uint64_t), &net_first_byte_num, sizeof(uint64_t));

        size_t read_bytes = fread(read_buffer, sizeof(byte_t), psize, stdin);

        if (read_bytes < psize) {
            break;
        }

        memcpy(buffer + sizeof(uint64_t) * 2, read_buffer, psize);

        lock.lock();
        if (retransmission_set.size() >= fsize / psize) {
            retransmission_set.erase(retransmission_set.begin());
            retransmission_set.insert(first_byte_num);
        } else {
            retransmission_set.insert(first_byte_num);
        }

        size_t buf_position = first_byte_num;
        if (buf_position >= fsize) {
            buf_position = buf_position % fsize + (fsize % psize);
        }
        if (buf_position + psize > fsize) {
            buf_position = 0;
        }
        memcpy(retransmission_buffer + buf_position, read_buffer, psize);

        send_message(socket_fd, &send_address, &buffer, sizeof(buffer));
        lock.unlock();

        first_byte_num += psize;
    }

    control_finished = true;
    control_thread.join();
    delete[] retransmission_buffer;

    CHECK_ERRNO(setsockopt(socket_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &ip_mreq,
                           sizeof(ip_mreq)));
    CHECK_ERRNO(close(socket_fd));

    return 0;
}
