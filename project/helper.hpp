#ifndef HELPER_HPP
#define HELPER_HPP

#include <iostream>
#include <string>
#include <vector>
#include <unordered_map>
#include <set>
#include <netinet/ip.h> // for iphdr structure
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <sstream>
#include <numeric>
#include <iomanip>

using namespace std;

inline void checkFailure(int status, string msg)
{
    if (status < 0)
    {
        perror(msg.c_str());
        exit(EXIT_FAILURE);
    }
}

inline unsigned short calcChecksum(unsigned short *inputData, unsigned int byteCount)
{
    // Initialize sum and identify data endpoint
    unsigned long sum = 0;
    auto addrEnd = inputData + byteCount / 2;

    // Apply STL's accumulate to compute sum
    sum = std::accumulate(inputData, addrEnd, sum);
    
    // Add in last byte for odd byteCount
    if (byteCount % 2) sum += (*addrEnd & htons(0xFF00));
    
    // Convert 32-bit sum to 16-bit
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);

    // Compute and return one's complement as checksum
    sum = ~sum;
    return static_cast<unsigned short>(sum);
}

inline unsigned short calcIpChecksum(struct iphdr *ipHeader)
{
    // Initialize checksum to zero in IP header and compute using calcChecksum
    ipHeader->check = 0;
    unsigned short checksum = calcChecksum((unsigned short *)ipHeader, ipHeader->ihl << 2);

    // Reassign the computed checksum to the IP header and return it
    ipHeader->check = checksum;
    return checksum;
}

inline vector<string> split(string str, char delimiter)
{
    vector<string> internal;
    string temp;
    for (char c : str)
    {
        if (c == delimiter)
        {
            internal.push_back(temp);
            temp = "";
        }
        else
        {
            temp.push_back(c);
        }
    }
    internal.push_back(temp);
    return internal;
}

inline unsigned short calcTcpChecksum(struct iphdr *ipHeader, unsigned short *ipPayloadData)
{
    // Start with a zero sum and derive TCP length
    unsigned long sum = 0;
    unsigned short tcpLength = ntohs(ipHeader->tot_len) - (ipHeader->ihl << 2);

    // Get TCP header reference
    struct tcphdr *tcpHeader = (struct tcphdr *)(ipPayloadData);

    // Lambda function to split and add IP
    auto ipSum = [](unsigned long ip) -> unsigned long {
        return ((ip >> 16) & 0xFFFF) + (ip & 0xFFFF);
    };

    // Include pseudo header (source IP, destination IP, protocol, and length) in sum
    sum += ipSum(ipHeader->saddr);
    sum += ipSum(ipHeader->daddr);
    sum += htons(IPPROTO_TCP);
    sum += htons(tcpLength);

    // Set TCP header checksum to zero and compute sum with IP payload
    tcpHeader->check = 0;
    auto startPayload = ipPayloadData;
    auto endPayload = startPayload + tcpLength / 2;
    sum += std::accumulate(startPayload, endPayload, 0);

    // Address any extra byte
    if (tcpLength % 2) sum += ((*endPayload) & htons(0xFF00));

    // Convert 32-bit sum to 16 bits
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum;

    // Update checksum in TCP header and return it
    tcpHeader->check = (unsigned short)sum;
    return (unsigned short)sum;
}

inline unsigned short calcUdpChecksum(struct iphdr *ipHeader, unsigned short *udpHeader)
{
    // Start with a zero sum and get UDP header reference
    unsigned long sum = 0;
    struct udphdr *udpHeaderPtr = (struct udphdr *)(udpHeader);

    // Retrieve UDP length
    unsigned short udpLength = htons(udpHeaderPtr->len);

    // Lambda function to split and add IP
    auto ipSum = [](unsigned long ip) -> unsigned long {
        return ((ip >> 16) & 0xFFFF) + (ip & 0xFFFF);
    };

    // Include pseudo header (source IP, destination IP, protocol, and length) in sum
    sum += ipSum(ipHeader->saddr);
    sum += ipSum(ipHeader->daddr);
    sum += htons(IPPROTO_UDP);
    sum += udpHeaderPtr->len;

    // Set UDP header checksum to zero and compute sum with IP payload
    udpHeaderPtr->check = 0;
    auto startPayload = udpHeader;
    auto endPayload = startPayload + udpLength / 2;
    sum += std::accumulate(startPayload, endPayload, 0);

    // Address any extra byte
    if (udpLength % 2) sum += ((*endPayload) & htons(0xFF00));

    // Convert 32-bit sum to 16 bits
    while (sum >> 16) sum = (sum & 0xffff) + (sum >> 16);
    sum = ~sum;

    // Update checksum in UDP header with special case of zero handled
    if ((unsigned short)sum == 0x0000) {
        udpHeaderPtr->check = 0xFFFF;
    }
    else {
        udpHeaderPtr->check = (unsigned short)sum;
    }

    // Return checksum
    return udpHeaderPtr->check;
}

inline bool checkCorruptedIP(struct iphdr *ip_header)
{
    unsigned short cur_checksum = (unsigned short)(ip_header->check);
    unsigned short computed_check = calcIpChecksum(ip_header);
    std::cout << "Checksum: " << ntohs(ip_header->check) << std::endl;
    cout << cur_checksum << endl;
    cout << computed_check << endl;
    if (cur_checksum != computed_check)
    {
        return true;
    }
    else
    {
        return false;
    }
}

inline bool checkCorruptedUDP(struct iphdr *ip_header, unsigned short *udp_header)
{
    std::cout << "Checksum2: " << ntohs(ip_header->check) << std::endl;

    struct udphdr *udp_header_struct = (struct udphdr *)(udp_header);
    cout << "UDP Checksum: " << ntohs(udp_header_struct->check) << endl;
    unsigned short cur_checksum = static_cast<unsigned short>(udp_header_struct->check);
    auto computed_check = calcUdpChecksum(ip_header, udp_header);
    cout << cur_checksum << endl;
    cout << computed_check << endl;
    udp_header_struct->check = cur_checksum;
    std::cout << "Checksum3: " << ntohs(ip_header->check) << std::endl;
    cout << "UDP Checksum: " << ntohs(udp_header_struct->check) << endl;
    if (cur_checksum != computed_check)
    {
        return true;
    }
    else
    {
        return false;
    }
}

inline bool checkCorruptedTCP(struct iphdr *ip_header, unsigned short *tcp_header)
{
    struct tcphdr *tcp_header_struct = (struct tcphdr *)(tcp_header);
    unsigned short cur_checksum = static_cast<unsigned short>(tcp_header_struct->check);
    auto computed_check = calcTcpChecksum(ip_header, tcp_header);
    ;
    cout << cur_checksum << endl;
    cout << computed_check << endl;
    tcp_header_struct->check = cur_checksum;
    std::cout << "Checksum3: " << ntohs(ip_header->check) << std::endl;
    cout << "TCP Checksum: " << ntohs(tcp_header_struct->check) << endl;
    if (cur_checksum != computed_check)
    {
        return true;
    }
    else
    {
        return false;
    }
}

inline bool Count(vector<string> &v, string &s)
{
    return find(v.begin(), v.end(), s) != v.end();
}

inline bool Count2(string &p, string &s)
{
    if (p.size() > s.size())
        return false;
    return p == s.substr(0, p.size());
}

inline std::string bufferToHex(const char *buffer, std::size_t size)
{
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (std::size_t i = 0; i < size; ++i)
    {
        ss << setw(2) << static_cast<unsigned>(static_cast<unsigned char>(buffer[i])) << "  ";
    }
    return ss.str();
}

#endif