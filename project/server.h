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
            ttl = (unsigned int)ip_header->ttl;
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
                computeUdpChecksum(ip_header, (unsigned short *)udp_header);
            } else if (tcp_header != NULL) {
                cout << "tcp ttl?" << (unsigned int)tcp_header->th_off << endl;
                computeTcpChecksum(ip_header, (unsigned short *)tcp_header);
            }
        }

        void recomputeTTL() {
            cout << "checksum in decrease TTL before: " << ntohs(ip_header->check) << endl;
            decreaseTTL();
            computeIpChecksum(ip_header);
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
        int ttl;
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
        string lanIPRange;
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


//  if (Count(server->lanIPRange, src_ip) && Count(server->lanIPRange, dest_ip)) {
//                 int dest_fd = server->ip_fd_map[dest_ip];
//                 packet.recomputeTTL();
//                 write(dest_fd, buffer, bytes_received);
//             } else if (Count(server->lanIPRange, src_ip) && !Count(server->lanIPRange, dest_ip)) {
//                 cout << "here we are, in lan to wan world!!!" << endl;
//                 string lan_IP_Port = src_ip + ":" + to_string(packet.src_port);
//                 server->detectNewMapping(lan_IP_Port);
//                 string wan_IP_Port = server->LANtoWAN[lan_IP_Port];
//                 cout << wan_IP_Port << endl;
//                 vector<string> wan_IP_Port_split = split(wan_IP_Port, ':');
//                 int dest_fd = server->ip_fd_map[server->server_wanIp];
//                 packet.replaceSource(wan_IP_Port_split);
//                 packet.recomputeTTL();
//                 cout << bufferToHex(buffer, bytes_received) << endl;
//                 write(dest_fd, buffer, bytes_received);
//             } else if (!Count(server->lanIPRange, src_ip)&& dest_ip == server->server_wanIp) {
//                 cout << "holly we are in the outer to inner world!!!" << endl;
//                 string wan_IP_Port = server->server_wanIp + ":" + to_string(packet.dest_port);
//                 if (!server->WANtoLAN.count(wan_IP_Port)) {
//                     cout << wan_IP_Port << endl;
//                     cout << "no fk why......" << endl;
//                     continue;
//                 }
//                 string lan_IP_Port = server->WANtoLAN[wan_IP_Port];
//                 cout << lan_IP_Port << endl;
//                 vector<string> lan_IP_Port_split = split(lan_IP_Port, ':');
//                 int dest_fd = server->ip_fd_map[lan_IP_Port_split[0]];
//                 packet.replaceDestination(lan_IP_Port_split);
//                 packet.recomputeTTL();
//                 cout << bufferToHex(buffer, bytes_received) << endl;
//                 write(dest_fd, buffer, bytes_received);
//             } else {
//                 cout << "no fk why??????......" << endl;
//                 continue;
//             }