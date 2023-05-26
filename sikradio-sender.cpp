#include <boost/program_options.hpp>
#include <iostream>
#include <cstring>
#include <sys/socket.h>
#include <ctime>
#include <cstdio>
#include <queue>
#include <thread>
#include <mutex>
#include <atomic>
#include <condition_variable>
#include "common.h"

#define DEFAULT_PORT "28422"
#define DEFAULT_PSIZE 512
#define DEFAULT_FSIZE 131072
#define DEFAULT_NAME "Nienazwany Nadajnik"

using std::string;
namespace po = boost::program_options;

std::atomic_bool finished = false;
bool stop_sleeping = false;
std::mutex buffer_mutex;
std::mutex packets_queue_mutex;
std::mutex sleep_mutex;
std::condition_variable sleep_cv;
byte_t *retransmission_buffer = nullptr;
std::set<uint64_t> retransmission_set;
std::queue<uint64_t> packets_to_resend;

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
            fatal(e.what());
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
        memcpy(response + index, LOOKUP_REPLY_HEADER, LOOKUP_REPLY_HEADER_SIZE);
        index += LOOKUP_REPLY_HEADER_SIZE;
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

    // checks and parses requests into packets_to_resend set
    void parse_rexmit(const string &message) {
        if (message[message.size() - 1] != '\n') {
            return;
        }

        size_t index = REXMIT_HEADER_SIZE;
        while (index < message.size() - 1) {
            if ((message[index] < '0' || message[index] > '9') && message[index] != ',') {
                return;
            }
            index++;
        }

        std::unique_lock<std::mutex> lock(packets_queue_mutex, std::defer_lock);
        index = REXMIT_HEADER_SIZE;
        while (index < message.size()) {
            size_t comma = message.find(',', index);
            if (comma == string::npos) {
                comma = message.size();
            }
            uint64_t number = stoull(message.substr(index, comma - index));
            lock.lock();
            packets_to_resend.push(number);
            lock.unlock();
            index = comma + 1;
        }
    }

    size_t get_position_in_buffer(uint64_t num, size_t psize, size_t fsize) {
        size_t buf_position = num;
        if (buf_position >= fsize) {
            buf_position = buf_position % fsize + (fsize % psize);
        }
        if (buf_position + psize > fsize) {
            buf_position = 0;
        }
        return buf_position;
    }

    // saves the input data for later in case of retransmission
    void save_for_retransmission(uint64_t num, size_t psize, size_t fsize, byte_t *buffer) {
        std::unique_lock<std::mutex> lock(buffer_mutex);
        if (retransmission_set.size() >= fsize / psize) {
            retransmission_set.erase(retransmission_set.begin());
            retransmission_set.insert(num);
        } else {
            retransmission_set.insert(num);
        }

        size_t buf_position = get_position_in_buffer(num, psize, fsize);
        memcpy(retransmission_buffer + buf_position, buffer, psize);
        lock.unlock();
    }

    // function for the thread handling retransmission
    void resend(uint64_t net_session_id, size_t psize, size_t fsize, uint16_t port_num,
                char *addr, uint64_t rtime) {
        std::unique_lock<std::mutex> lock(buffer_mutex, std::defer_lock);
        std::unique_lock<std::mutex> set_lock(packets_queue_mutex, std::defer_lock);

        // setting up socket and address
        int socket_fd = open_udp_socket();
        struct sockaddr_in send_address{};
        send_address.sin_family = AF_INET;
        send_address.sin_port = htons(port_num);
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

        byte_t buffer[psize + 2 * sizeof(uint64_t)];
        memcpy(buffer, &net_session_id, sizeof(uint64_t));

        while (!finished) {
            // setting the start timestamp
            auto start = std::chrono::system_clock::now();

            // moving packets to be retransmitted to this_series queue
            set_lock.lock();
            std::queue<uint64_t> this_series;
            this_series.swap(packets_to_resend);
            set_lock.unlock();

            // retransmitting packets
            while (!this_series.empty()) {
                uint64_t number = this_series.front();
                this_series.pop();

                uint64_t net_number = htobe64(number);
                memcpy(buffer + sizeof(uint64_t), &net_number, sizeof(uint64_t));

                lock.lock();
                if (retransmission_set.find(number) == retransmission_set.end()) {
                    lock.unlock();
                    continue;
                }

                size_t id = get_position_in_buffer(number, psize, fsize);
                memcpy(buffer + sizeof(uint64_t) * 2, retransmission_buffer + id, psize);
                lock.unlock();

                send_message(socket_fd, &send_address, buffer, psize + sizeof(uint64_t) * 2);
            }

            // calculating the remaining time of this retransmission period
            auto stop = std::chrono::system_clock::now();
            auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(stop - start);
            uint64_t sleep = rtime - duration.count();
            if (sleep <= 0) {
                continue;
            }

            // sleeping for the remaining rtime, unless main thread finished
            std::unique_lock<std::mutex> sleep_lock(sleep_mutex);
            sleep_cv.wait_for(sleep_lock, std::chrono::milliseconds(sleep), [] {
                return stop_sleeping;
            });
        }

        CHECK_ERRNO(setsockopt(socket_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &ip_mreq,
                               sizeof(ip_mreq)));
        CHECK_ERRNO(close(socket_fd));
    }

    // function for the thread listening for control messages
    void listen_control(char *addr, char *port, uint16_t port_num, char *name) {
        byte_t buffer[UDP_MAX_SIZE];
        memset(buffer, 0, sizeof(buffer));

        int socket_fd = open_udp_socket();
        bind_socket(socket_fd, port_num);

        struct sockaddr_in sender_address{};

        while (!finished) {
            size_t read_length = read_message(socket_fd, &sender_address, buffer,
                                              sizeof(buffer));
            if (read_length == 0) {
                continue;
            }

            string message = string((char *) buffer, read_length);

            if (strcmp(message.c_str(), LOOKUP_HEADER) == 0) {
                byte_t reply[LOOKUP_REPLY_HEADER_SIZE + strlen(addr) + strlen(port) +
                             strlen(name) + 3];
                create_lookup_reply(reply, addr, port, name);
                send_message(socket_fd, &sender_address, &reply, sizeof(reply));
            } else if (strncmp(message.c_str(), REXMIT_HEADER, REXMIT_HEADER_SIZE) == 0) {
                parse_rexmit(message);
            }
            sender_address = {};
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

    // setting up the socket and the multicast address
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

    std::unique_lock<std::mutex> lock(buffer_mutex, std::defer_lock);
    std::thread control_thread(listen_control, addr, d_port, c_port_num,
                               (char *) name.c_str());
    std::thread retransmission_thread(resend, net_session_id, psize, fsize, d_port_num,
                                      addr, rtime);

    // the main loop, reading data from input and sending it to the multicast
    while (true) {
        uint64_t net_first_byte_num = htobe64(first_byte_num);
        memcpy(buffer + sizeof(uint64_t), &net_first_byte_num, sizeof(uint64_t));

        size_t read_bytes = fread(read_buffer, sizeof(byte_t), psize, stdin);

        if (read_bytes < psize) {
            break;
        }

        memcpy(buffer + sizeof(uint64_t) * 2, read_buffer, psize);

        if (fsize >= psize) {
            save_for_retransmission(first_byte_num, psize, fsize, read_buffer);
        }

        send_message(socket_fd, &send_address, &buffer, sizeof(buffer));

        first_byte_num += psize;
    }

    finished = true;
    control_thread.join();
    {
        std::lock_guard<std::mutex> sleep_lock(sleep_mutex);
        stop_sleeping = true;
        sleep_cv.notify_one();
    }
    retransmission_thread.join();
    delete[] retransmission_buffer;

    CHECK_ERRNO(setsockopt(socket_fd, IPPROTO_IP, IP_DROP_MEMBERSHIP, &ip_mreq,
                           sizeof(ip_mreq)));
    CHECK_ERRNO(close(socket_fd));

    return 0;
}
