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
#include <stdlib.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h> // for iphdr structure
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <cstring>


#include <bitset>

#include <iostream>
#include <sstream>
#include <iomanip>

std::string bufferToHex(const char* buffer, std::size_t size) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for(std::size_t i = 0; i < size; ++i) {
        ss << std::setw(2) << static_cast<unsigned>(static_cast<unsigned char>(buffer[i]));
    }
    return ss.str();
}

/* Compute checksum for count bytes starting at addr, using one's complement of one's complement sum*/
static unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
  register unsigned long sum = 0;
  while (count > 1) {
    sum += * addr++;
    count -= 2;
  }
  //if any bytes left, pad the bytes and add
  if(count > 0) {
    sum += ((*addr)&htons(0xFF00));
  }
  //Fold sum to 16 bits: add carrier to result
  while (sum>>16) {
      sum = (sum & 0xffff) + (sum >> 16);
  }
  //one's complement
  sum = ~sum;
  return ((unsigned short)sum);
}

void compute_ip_checksum(struct iphdr* iphdrp){
  iphdrp->check = 0;
  iphdrp->check = compute_checksum((unsigned short*)iphdrp, iphdrp->ihl<<2);
}


void compute_udp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {
    register unsigned long sum = 0;
    struct udphdr *udphdrp = (struct udphdr*)(ipPayload);
    unsigned short udpLen = htons(udphdrp->len);
    //printf("~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~udp len=%dn", udpLen);
    //add the pseudo header 
    //printf("add pseudo headern");
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 17
    sum += htons(IPPROTO_UDP);
    //the length
    sum += udphdrp->len;
 
    //add the IP payload
    //printf("add ip payloadn");
    //initialize checksum to 0
    udphdrp->check = 0;
    while (udpLen > 1) {
        sum += * ipPayload++;
        udpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(udpLen > 0) {
        //printf("+++++++++++++++padding: %dn", udpLen);
        sum += ((*ipPayload)&htons(0xFF00));
    }
      //Fold sum to 16 bits: add carrier to result
    //printf("add carriern");
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
    //printf("one's complementn");
      sum = ~sum;
    //set computation result
    udphdrp->check = ((unsigned short)sum == 0x0000)?0xFFFF:(unsigned short)sum;
}

void printBufferAsBits(const char *buffer, std::size_t size) {
    for(std::size_t i = 0; i < size; ++i) {
        std::bitset<8> bits(buffer[i]);
        std::cout << bits << ' ';
    }
    std::cout << std::endl;
}


class Checksum {
private:
    uint32_t val;

public:
    Checksum() : val(0) {}

    void add(const char *buf, size_t len) {
        for (size_t i = 0; i < len - 1; i += 2) {
            val += (static_cast<uint8_t>(buf[i]) << 8) + static_cast<uint8_t>(buf[i + 1]);
        }

        // If the buffer length is odd, add the last byte
        if (len % 2 == 1) {
            val += (static_cast<uint8_t>(buf[len - 1]) << 8);
        }
    }

    uint16_t finish() {
        // Add the carries back
        while (val > 0xFFFF) {
            val = (val >> 16) + (val & 0xFFFF);
        }
        // The checksum result is the sum's one's complement
        return ~val & 0xFFFF;
    }
};


pthread_mutex_t mut = PTHREAD_MUTEX_INITIALIZER;

#define PORT 5152
#define BUFFER_SIZE 104857600
const int UDP_PROTOCOL_ID = 17;
const int TCP_PROTOCOL_ID = 6;

// Router config
std::string lanIP;
std::string wanIP;
std::string wanClientIP;
std::vector<std::string> lanClientIPs;
std::unordered_map<std::string, std::string> LANtoWAN;
std::unordered_map<std::string, std::string> WANtoLAN;
std::vector<std::vector<std::string>> denyRules;
int port_num = 49152;

std::string print_ip_address(int ip)
{
    struct in_addr inaddr;
    inaddr.s_addr = ip;
    return inet_ntoa(inaddr);
}

// parse input into config
void parseConfig() {
    std::string line;

    // Router's LAN IP and the WAN IP
    std::getline(std::cin, line);
    size_t pos = line.find(' ');
    lanIP = line.substr(0, pos);  
    wanIP = line.substr(pos + 1);

    pthread_mutex_lock(&mut);

    std::cout << "Server's LAN IP: " << lanIP << std::endl  
            << "Server's WAN IP: " << wanIP << std::endl;
    std::cout << "finished" << std::endl;

    pthread_mutex_unlock(&mut);
    // Read WAN & LAN client IPs
    std::getline(std::cin, line);
    wanClientIP = line;

    // pthread_mutex_lock(&mut);
    // std::cout << "64" << std::endl;
    // pthread_mutex_unlock(&mut);
    

    while (getline(std::cin, line)) {
        if (line.empty()) {
            break;
        }   
        lanClientIPs.push_back(line);
        // std::cout << "70" << endl;
    }

    // NAT table
   //  std::cout << "75" << endl;
    while (getline(std::cin, line) && line != "") {
        // Parse line into string structs for internal and external
        std::cout << line << std::endl;
        pos = line.find(' ');
        std::string lanstring = line.substr(0, pos) + ':' + line.substr(pos + 1);
        pos = line.find(' ', pos + 1);
        std::string wanstring = wanIP + ':' + line.substr(pos + 1);
        // Add entry to NAPT table vector
        LANtoWAN[lanstring] = wanstring;
        WANtoLAN[wanstring] = lanstring;
        // std::cout << "87" << endl;
    }
    
    
    // pthread_mutex_lock(&mut);
    // std::cout << "parse finished" << std::endl;
    // pthread_mutex_unlock(&mut);
    
    // TODO: Read deny rules config
}

std::string stringifyIPPort(int ip, int source_port) {
    return print_ip_address(ip) + ":" + std::to_string(source_port);
}

bool Contains(std::vector<std::string> &v, std::string x) {
    for (auto &s : v) {
        if (s == x) {
            // std::cout << s << std::endl;
            // std::cout << x << std::endl;
            return true;
        }
    }
    return false;
}

// uint16_t compute_checksum(uint8_t *buffer, size_t length) {
//     uint32_t sum = 0;
//     uint16_t *buffer_16 = (uint16_t *)buffer;

//     // Calculate the sum of all 16-bit words in the buffer
//     for (; length > 1; length -= 2) {
//         sum += *buffer_16++;
//     }

//     // If the length of the buffer is odd, add the remaining byte
//     if (length == 1) {
//         sum += *(uint8_t *)buffer_16;
//     }

//     // Fold the 32-bit sum to 16 bits
//     while (sum >> 16) {
//         sum = (sum & 0xffff) + (sum >> 16);
//     }

//     return ~sum;  // Return the one's complement of the checksum
// }

// uint16_t compute_udp_checksum(struct iphdr *ip_header, struct udphdr *udp_header) {
//     // Pseudo-header (needed for checksum computation)
//     struct {
//         uint32_t src_ip;
//         uint32_t dest_ip;
//         uint8_t zero;
//         uint8_t protocol;
//         uint16_t udp_length;
//     } pseudo_header;

//     pseudo_header.src_ip = ip_header->saddr;
//     pseudo_header.dest_ip = ip_header->daddr;
//     pseudo_header.zero = 0;
//     pseudo_header.protocol = IPPROTO_UDP;
//     pseudo_header.udp_length = udp_header->len;

//     // The checksum is calculated over the pseudo-header, the UDP header, and the payload
//     size_t buffer_length = sizeof(pseudo_header) + ntohs(udp_header->len);
//     uint8_t *buffer = (uint8_t *)malloc(buffer_length);

//     memcpy(buffer, &pseudo_header, sizeof(pseudo_header));
//     memcpy(buffer + sizeof(pseudo_header), udp_header, ntohs(udp_header->len));

//     uint16_t checksum = compute_checksum(buffer, buffer_length);
//     free(buffer);
    
//     return checksum;
// }

// uint16_t compute_ip_checksum(struct iphdr *ip_header) {
//     uint32_t sum = 0;
//     uint16_t *ip_header_16 = (uint16_t *)ip_header;

//     // Calculate the sum of all 16-bit words in the header
//     for (int i = 0; i < ip_header->ihl*2; i++) {
//         sum += ip_header_16[i];
//     }

//     // Fold the 32-bit sum to 16 bits
//     while (sum >> 16) {
//         sum = (sum & 0xffff) + (sum >> 16);
//     }

//     return ~sum;  // Return the one's complement of the checksum
// }


void dealWithUDPPacket(char *buffer, struct iphdr *ip_header, int client_fd) {
    std::cout << "Buffer: " << buffer << std::endl;

    struct udphdr *udp_header = (struct udphdr*)(buffer + ip_header->ihl*4);
    auto source_port = ntohs(udp_header->source);
    auto dest_port = ntohs(udp_header->dest);
    std::string source_ip = print_ip_address(ip_header->saddr);
    std::string dest_ip = print_ip_address(ip_header->daddr);
    std::string source_ip_port = stringifyIPPort(ip_header->saddr, source_port);
    std::string dest_ip_port = stringifyIPPort(ip_header->daddr, dest_port);
    std::cout << "Source Port: " << source_ip << std::endl;
    std::cout << "Destination Port: " << dest_ip << std::endl;
    std::cout << "Source IP Port: " << source_ip_port << std::endl;
    std::cout << "Destionation IP Port: " << dest_ip_port << std::endl;
    // for (auto ip : lanClientIPs) {
    //     std::cout << ip << std::endl;
    //     std::cout << lanClientIPs.size() << std::endl;
    // }
    if (Contains(lanClientIPs, source_ip) && Contains(lanClientIPs, dest_ip)) {
        
        std::cout << "TTL: " << (unsigned int)ip_header->ttl << std::endl;
        ip_header->ttl = htons(ntohs(ip_header->ttl) - 1);
        std::cout << "TTL: " << (unsigned int)ip_header->ttl << std::endl;

        // recompute checksum
        std::cout << "checksum: " << ntohs(ip_header->check) << std::endl;
        std::cout << "checksum: " << ntohs(udp_header->check) << std::endl;
        compute_ip_checksum(ip_header);
        compute_udp_checksum(ip_header, (unsigned short *)(buffer + ip_header->ihl*4));

        std::cout << "checksum: " << ntohs(ip_header->check) << std::endl;
        std::cout << "checksum: " << ntohs(udp_header->check) << std::endl;

        sendto(client_fd, buffer, ntohs(ip_header->tot_len), 0, (struct sockaddr *)&(ip_header->daddr), sizeof(ip_header->daddr));
        std::cout << "Local LAN sent" << std::endl;

    } else if (Contains(lanClientIPs, source_ip)) {
        // send the packet buffer to the destination
        //write(client_fd, buffer, sizeof(buffer));
    //     auto replace_source_ip_port = LANtoWAN[source_ip_port];
    //     auto new_source_port = std::stoi(replace_source_ip_port.substr(replace_source_ip_port.find(':') + 1));
    //     auto new_source_ip = std::stoi(replace_source_ip_port.substr(0, replace_source_ip_port.find(':')));
    //     udp_header->source = htons(new_source_port);  // Replace with new port
    //     udp_header->check = 0;  // Zero out checksum for calculation
    //     udp_header->check = compute_udp_checksum(ip_header, udp_header);  // Recalculate
        
    //     // Replace source IP and recalculate IP checksum
    //     ip_header->saddr = inet_addr(new_source_ip);  // Replace with new IP
    //     ip_header->check = 0;  // Zero out checksum for calculation
    //     ip_header->check = compute_ip_checksum(ip_header);  // Recalculate

    //    // Send the modified packet
    //     sendto(client_fd, buffer, ntohs(ip_header->tot_len), 0, (struct sockaddr *)&(ip_header->daddr), sizeof(ip_header->daddr));
    }
}
void dealWithTCPPacket(char *buffer, struct iphdr *ip_header, int client_fd) {
    
}

void *handle_client(void *arg) {
    pthread_mutex_lock(&mut);
    //std::cout << "we are here!!!!" << std::endl;
    int client_fd = *((int *)arg);
    // pthread_mutex_lock(&mut);
    // std::cout << client_fd << std::endl;
    //pthread_mutex_unlock(&mut);
    
    char *buffer = (char *)malloc(BUFFER_SIZE * sizeof(char));

    // receive request data from client and store into buffer
    ssize_t bytes_received = read(client_fd, buffer, BUFFER_SIZE);
    if (bytes_received > 0) {
        std::cout << bufferToHex(buffer, bytes_received) << std::endl;
        printBufferAsBits(buffer, bytes_received);
        // parse IP packet
        struct iphdr *ip_header = (struct iphdr *)buffer;
        // Print information
        // pthread_mutex_lock(&mut);
        std::cout << "IP Version: " << ip_header->version << std::endl;
        std::cout << "Header Length: " << ip_header->ihl << std::endl;
        std::cout << "Total Length: " << ntohs(ip_header->tot_len) << std::endl;
        std::cout << "Identification: " << ntohs(ip_header->id) << std::endl;
        std::cout << "TTL: " << (unsigned int)ip_header->ttl << std::endl;
        std::cout << "Protocol: " << (unsigned int)ip_header->protocol << std::endl;
        std::cout << "Checksum: " << ntohs(ip_header->check) << std::endl;
        std::cout << "Source IP: " << std::endl;
        std::cout << print_ip_address(ip_header->saddr) << std::endl;
        std::cout << "Destination IP: " << std::endl;
        std::cout << print_ip_address(ip_header->daddr) << std::endl;

        int transport_protocol = (int)ip_header->protocol;
        if (transport_protocol == UDP_PROTOCOL_ID) {
            std::cout << "with UDP now" << std::endl;
            dealWithUDPPacket(buffer, ip_header, client_fd);
        } else if (transport_protocol == TCP_PROTOCOL_ID) {
            dealWithTCPPacket(buffer, ip_header, client_fd);
        }
        
    }
    close(client_fd);
    free(arg);
    free(buffer);
    pthread_mutex_unlock(&mut);
    return NULL;
}




class Server {
public:
    Server() {
        server_fd = 0;
    }
    void initiateServer() {
            // 1. Create a listening socket and accept multiple connections
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
        // std::cout << "154" << endl;
        if (::bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) {
            perror("bind failed");
            exit(EXIT_FAILURE);
        }

        // listen for connections
        // std::cout << "161" << endl;
        if (listen(server_fd, 10) < 0) {
            perror("listen failed");
            exit(EXIT_FAILURE);
        }
    }

    void runServer() {
        while (true) {
            // std::cout << "while" << endl;
            // client info
            struct sockaddr_in client_addr;
            socklen_t client_addr_len = sizeof(client_addr);
            int *client_fd = new int;

            // accept client connection
            // std::cout << "accepting" << endl;
            if ((*client_fd = accept(server_fd, 
                                    (struct sockaddr *)&client_addr, 
                                    &client_addr_len)) < 0) {
                perror("accept failed");
                // continue;
            }
            // std::cout << client_fd << std::endl;

            // create a new thread to handle client request
            pthread_t thread_id;
            pthread_create(&thread_id, NULL, handle_client, client_fd);
            pthread_detach(thread_id);
        
        }
        

        if (close(server_fd) < 0) {
            perror("socket failed");
            exit(EXIT_FAILURE);
        }
    }

    
private:
    int server_fd;
    struct sockaddr_in server_addr;
};

int main() {
    parseConfig();

    // TODO: Setup socket, accept connections, parse packets, handle forwarding/NAPT/deny rules
    Server server = Server();
    server.initiateServer();
    server.runServer();
   

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