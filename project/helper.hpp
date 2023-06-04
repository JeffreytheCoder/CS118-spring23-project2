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

inline unsigned short computeChecksum(unsigned short *addr, unsigned int count)
{
    // Initialize sum
    unsigned long totalSum = 0;

    // Calculate end address of the data
    auto addrEnd = addr + count / 2;

    // Compute sum using accumulate function from STL
    totalSum = std::accumulate(addr, addrEnd, totalSum);

    // If count is odd, add the last byte after padding
    if (count % 2)
    {
        totalSum += (*addrEnd & htons(0xFF00));
    }

    // Fold 32-bit sum to 16 bits
    while (totalSum >> 16)
    {
        totalSum = (totalSum & 0xffff) + (totalSum >> 16);
    }

    // Compute one's complement
    totalSum = ~totalSum;

    // Return the checksum
    return static_cast<unsigned short>(totalSum);
}

inline unsigned short computeIpChecksum(struct iphdr *iphdrp)
{
    // Reset the checksum in IP header
    iphdrp->check = 0;

    // Calculate checksum using previously defined function
    unsigned short checksum = computeChecksum((unsigned short *)iphdrp, iphdrp->ihl << 2);

    // Assign the computed checksum back to the IP header
    iphdrp->check = checksum;

    // Return the checksum
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

inline unsigned short computeTcpChecksum(struct iphdr *pIph, unsigned short *ipPayload)
{
    // Initialize sum
    unsigned long sum = 0;

    // Calculate the TCP length
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl << 2);

    // Point to the TCP header
    struct tcphdr *tcpHeader = (struct tcphdr *)(ipPayload);

    // Lambda function to split and add IP
    auto ipSum = [](unsigned long ip) -> unsigned long {
        return ((ip >> 16) & 0xFFFF) + (ip & 0xFFFF);
    };

    // Add pseudo header
    // Add source IP
    sum += ipSum(pIph->saddr);

    // Add destination IP
    sum += ipSum(pIph->daddr);

    // Add protocol and reserved: 6
    sum += htons(IPPROTO_TCP);

    // Add length
    sum += htons(tcpLen);

    // Reset the checksum in TCP header
    tcpHeader->check = 0;

    // Add IP payload
    auto startPayload = ipPayload;
    auto endPayload = startPayload + tcpLen / 2;
    sum += std::accumulate(startPayload, endPayload, 0);

    // If there is any leftover byte, add it into the sum
    if (tcpLen % 2) {
        sum += ((*endPayload) & htons(0xFF00));
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;

    // Assign computed checksum to TCP header
    tcpHeader->check = (unsigned short)sum;

    // Return checksum
    return (unsigned short)sum;
}

inline unsigned short computeUdpChecksum(struct iphdr *pIph, unsigned short *udphdr)
{
    // Initialize sum variable
    unsigned long sum = 0;

    // Point to the UDP header
    struct udphdr *udpHeaderPtr = (struct udphdr *)(udphdr);

    // Obtain the UDP length
    unsigned short udpLen = htons(udpHeaderPtr->len);

    // Lambda function to split and add IP
    auto ipSum = [](unsigned long ip) -> unsigned long {
        return ((ip >> 16) & 0xFFFF) + (ip & 0xFFFF);
    };

    // Add pseudo header
    // Add source IP
    sum += ipSum(pIph->saddr);

    // Add destination IP
    sum += ipSum(pIph->daddr);

    // Add protocol and reserved: 17
    sum += htons(IPPROTO_UDP);

    // Add length
    sum += udpHeaderPtr->len;

    // Reset the checksum in UDP header
    udpHeaderPtr->check = 0;

        // Add IP payload
    auto startPayload = udphdr;
    auto endPayload = startPayload + udpLen / 2;
    sum += std::accumulate(startPayload, endPayload, 0);

    // If there is any leftover byte, add it into the sum
    if (udpLen % 2) {
        sum += ((*endPayload) & htons(0xFF00));
    }

    // Fold 32-bit sum to 16 bits
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    sum = ~sum;

    // Assign computed checksum to UDP header and handle special case of zero
    unsigned short udpChecksumResult = ((unsigned short)sum == 0x0000) ? 0xFFFF : (unsigned short)sum;
    udpHeaderPtr->check = udpChecksumResult;

    // Return checksum
    return udpChecksumResult;
}

inline bool checkCorruptedIP(struct iphdr *ip_header)
{
    unsigned short cur_checksum = (unsigned short)(ip_header->check);
    unsigned short computed_check = computeIpChecksum(ip_header);
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
    auto computed_check = computeUdpChecksum(ip_header, udp_header);
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
    auto computed_check = computeTcpChecksum(ip_header, tcp_header);
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