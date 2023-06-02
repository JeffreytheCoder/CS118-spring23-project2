#ifndef SERVER_H
#define SERVER_H

#include "helper.hpp"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <sys/types.h>
#include <fstream>


#define PORT 5152
#define BUFFER_SIZE 104857600
const unsigned int UDP_PROTOCOL_ID = 17;
const unsigned int TCP_PROTOCOL_ID = 6;

class Packet {
    public:
        Packet(char *buffer, ssize_t bytes_received) {
            this->buffer = buffer;
            this->bytes_received = bytes_received;
            ip_header = (struct iphdr *)buffer;
            cout << "before checkcorrupted" << endl;
            corrupted = checkCorruptedIP(ip_header);
            cout << "after checkcorrupted" << endl;
            if (corrupted) return;
            protocol_id = (unsigned int)ip_header->protocol;
            src_ip = inet_ntoa(*(struct in_addr *)&ip_header->saddr);
            dest_ip = inet_ntoa(*(struct in_addr *)&ip_header->daddr);

            if (protocol_id == UDP_PROTOCOL_ID) {
                udp_header = (struct udphdr *)(buffer + ip_header->ihl * 4);
                if (checkCorruptedUDP(ip_header,(unsigned short *)(udp_header))) {
                    corrupted = true;
                    return;
                }
                src_port = ntohs(udp_header->source);
                dest_port = ntohs(udp_header->dest);
                tcp_header = NULL;
            } else if (protocol_id == TCP_PROTOCOL_ID) {
                cout << "ok let's deal with tcp" << endl;
                tcp_header = (struct tcphdr *)(buffer + ip_header->ihl * 4);
                cout << "before checkcorrupted TCP" << endl;
                if (checkCorruptedTCP(ip_header,(unsigned short *)(tcp_header))) {
                    corrupted = true;
                    return;
                }
                cout << "after checkcorrupted TCP" << endl;
                src_port = ntohs(tcp_header->source);
                dest_port = ntohs(tcp_header->dest);
                udp_header = NULL;
            }
        }
        void decreaseTTL() {
            ip_header->ttl = htons(ntohs(ip_header->ttl) - 1);
        }

        void replaceSource(vector<string>& splits) {
            auto ip_str = splits[0];
            auto port_str = splits[1];
            struct in_addr ip_addr;
            ip_addr.s_addr = inet_addr(ip_str.c_str());
            unsigned short port = std::stoi(port_str);
            unsigned short port_net_order = htons(port);
            ip_header->saddr = ip_addr.s_addr;
            if (udp_header != NULL) {
                udp_header->source = port_net_order;
            } else if (tcp_header != NULL) {
                tcp_header->source = port_net_order;
            }
        }

        void replaceDestination(vector<string>& splits) {

            auto ip_str = splits[0];
            auto port_str = splits[1];
            struct in_addr ip_addr;
            ip_addr.s_addr = inet_addr(ip_str.c_str());
            unsigned short port = std::stoi(port_str);
            unsigned short port_net_order = htons(port);
            ip_header->daddr = ip_addr.s_addr;
            if (udp_header != NULL) {
                udp_header->dest = port_net_order;
            } else if (tcp_header != NULL) {
                tcp_header->dest = port_net_order;
            }
        }

        void compute_payload_checksum() {
            if (udp_header != NULL) {
                compute_udp_checksum(ip_header, (unsigned short *)udp_header);
            } else if (tcp_header != NULL) {
                compute_tcp_checksum(ip_header, (unsigned short *)tcp_header);
            }
        }

        void recomputeTTL() {
            cout << "checksum in decrease TTL before: " << ntohs(ip_header->check) << endl;
            decreaseTTL();
            compute_ip_checksum(ip_header);
            compute_payload_checksum();
            cout << "checksum in decrease TTL after: " << ntohs(ip_header->check) << endl;
        }

        char *buffer;
        iphdr *ip_header;
        udphdr *udp_header;  
        tcphdr *tcp_header; 
        int dest_fd;  
        ssize_t bytes_received;
        bool corrupted;
        unsigned int protocol_id;
        string src_ip;
        string dest_ip;
        unsigned int src_port;
        unsigned int dest_port;
};



class Server {
    public:
        Server() {
            parseConfig();
            dynamic_port_num = 49152;
            server_fd = 0;
            initServerSock();
            printAllAttributes();
        }
        ~Server() {
            close(server_fd);
        }
        void run();
        void printAllAttributes();
        void parseConfig();
        void initServerSock();
        void detectNewMapping(string lan_IP_Port);
        string server_lanIp;
        string server_wanIp;
        string wanClientIP;
        vector<string> lanClientIPs;
        unordered_map<string, string> LANtoWAN;
        unordered_map<string, string> WANtoLAN;
        vector<vector<string>> denyRules;
        int dynamic_port_num;
        int server_fd;
        struct sockaddr_in server_addr;
        unordered_map<string, int> ip_fd_map;
};

struct ThreadArgs {
    int client_fd;
    Server* server;
};

#endif 

// cout << dest_fd << endl;
// cout << packet.src_port << endl;
// cout << packet.dest_port << endl;
// cout << packet.src_ip << endl;
// cout << packet.dest_ip << endl;
// std::cout << "TTL: " << (unsigned int)ip_header->ttl << std::endl;
// cout << "checksum in decrease TTL before: " << ntohs(ip_header->check) << endl;
// cout << "udp checksum before: " << ntohs(packet.udp_header->check) << endl;
// std::cout << "TTL: " << (unsigned int)ip_header->ttl << std::endl;
// cout << "checksum in decrease TTL after: " << ntohs(ip_header->check) << endl;
// cout << "udp checksum after: " << ntohs(packet.udp_header->check) << endl;
// cout << bufferToHex(buffer, bytes_received) << endl;