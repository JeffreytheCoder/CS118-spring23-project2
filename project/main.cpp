#include <iostream>  
#include <string>
#include <unordered_map>
#include <vector>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <pthread.h>
#include <regex.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <sys/socket.h>
#include <arpa/inet.h>

using namespace std;

struct iphdr {
    unsigned int version:4;
    unsigned int ihl:4;
    unsigned char tos;
    unsigned short tot_len;
    unsigned short id;
    unsigned short frag_off;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short check;
    unsigned int saddr;
    unsigned int daddr;
    // options and padding
};

#define PORT 5152
#define BUFFER_SIZE 104857600

// Router config
string lanIP;
string wanIP;
string wanClientIP;
vector<string> lanClientIPs;
unordered_map<string, string> LANtoWAN;
unordered_map<string, string> WANtoLAN;
vector<vector<string>> denyRules;

void print_ip_address(int ip)
{
    struct in_addr inaddr;
    inaddr.s_addr = ip;
    std::cout << inet_ntoa(inaddr) << std::endl;
}

// parse input into config
void parseConfig() {
    string line;

    // Router's LAN IP and the WAN IP
    getline(std::cin, line);
    size_t pos = line.find(' ');
    lanIP = line.substr(0, pos);  
    wanIP = line.substr(pos + 1);

    std::cout << "Server's LAN IP: " << lanIP << endl  
            << "Server's WAN IP: " << wanIP << endl;
    std::cout << "finished\n";

    // Read WAN & LAN client IPs
    getline(std::cin, line);
    wanClientIP = line;
    std::cout << "64\n";

    while (getline(std::cin, line)) {
        if (line.empty()) {
            break;
        }   
        lanClientIPs.push_back(line);
        getline(std::cin, line);
        std::cout << "70\n";
    }

    // check if end of file
    if (std::cin.eof()) {
        std::cout << "End of file reached.\n";
    }

    // NAT table
    // std::cout << "75\n";
    // while (getline(std::cin, line) && line != "") {
    //     // Parse line into string structs for internal and external
    //     std::cout << line << std::endl;
    //     pos = line.find(' ');
    //     string lanstring = line.substr(0, pos) + ':' + line.substr(pos + 1);
    //     pos = line.find(' ', pos + 1);
    //     string wanstring = wanIP + ':' + line.substr(pos + 1);

    //     // Add entry to NAPT table vector
    //     LANtoWAN[lanstring] = wanstring;
    //     WANtoLAN[wanstring] = lanstring;
        
    //     std::cout << "87\n";
    // }
    std::cout << "parse finished\n";
    
    // TODO: Read deny rules config
}

void *handle_client(void *arg) {
    int client_fd = *((int *)arg);
    std::cout << client_fd;
    char *buffer = (char *)malloc(BUFFER_SIZE * sizeof(char));

    // receive request data from client and store into buffer
    ssize_t bytes_received = recv(client_fd, buffer, BUFFER_SIZE, 0);
    if (bytes_received > 0) {
        // parse IP packet
        struct iphdr *ip_header = (struct iphdr *)buffer;
        // Print information
        std::cout << "IP Version: " << ip_header->version << std::endl;
        std::cout << "Header Length: " << ip_header->ihl << std::endl;
        std::cout << "Total Length: " << ntohs(ip_header->tot_len) << std::endl;
        std::cout << "Identification: " << ntohs(ip_header->id) << std::endl;
        std::cout << "TTL: " << (unsigned int)ip_header->ttl << std::endl;
        std::cout << "Protocol: " << (unsigned int)ip_header->protocol << std::endl;
        std::cout << "Checksum: " << ntohs(ip_header->check) << std::endl;
        std::cout << "Source IP: ";
        print_ip_address(ip_header->saddr);
        std::cout << "Destination IP: ";
        print_ip_address(ip_header->daddr);
        
    }
    close(client_fd);
    free(arg);
    free(buffer);
    return NULL;
}

int main() {
    parseConfig();

    // TODO: Setup socket, accept connections, parse packets, handle forwarding/NAPT/deny rules

    // 1. Create a listening socket and accept multiple connections
    int server_fd;
    struct sockaddr_in server_addr;

    // create server socket
    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // reuse local address when binding the socket
    int optval = 1;
    if (setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval)) == -1) {
        perror("setsockopt failed");
        exit(EXIT_FAILURE);
    }

    // config socket
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    // bind socket to port
    std::cout << "154\n";
    if (::bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
        perror("bind failed");
        exit(EXIT_FAILURE);
    }

    // listen for connections
    std::cout << "161\n";
    if (listen(server_fd, 10) < 0) {
        perror("listen failed");
        exit(EXIT_FAILURE);
    }

    std::cout << "Server listening on port";
    std::cout << "wtf";
    while (true) {
        std::cout << "while";
        // client info
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int client_fd = 0;

        // accept client connection
        std::cout << "accepting";
        if ((client_fd = accept(server_fd, 
                                (struct sockaddr *)&client_addr, 
                                &client_addr_len)) < 0) {
            perror("accept failed");
            continue;
        }
        std::cout << client_fd;

        // create a new thread to handle client request
        pthread_t thread_id;
        pthread_create(&thread_id, NULL, handle_client, (void *)client_fd);
        pthread_detach(thread_id);
    }

    if (close(server_fd) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }

    // 2. Read packets from the connections and parse into string structs for source and destination
    // 3. Check if the packet matches any deny rules and drop if so
    // 4. Check if the destination string matches any static NAPT entries and rewrite if so
    // 5. If no static match, check if source string exists in dynamic port map and rewrite if so
    // 6. If no rewriting needed, forward packet out the correct connection based on destination IP
    // 7. For new source strings, allocate a new port number from the dynamic range and add to port map
    // 8. Deduct TTL, recalculate checksums, and handle TCP/UDP properly
    // 9. Meet timing requirements and handle stress tests
  
    return 0; 
}