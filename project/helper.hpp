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
//include setw
#include <iomanip>


using namespace std;

inline void checkFailure(int status, string msg) {
    if (status < 0) {
        perror(msg.c_str());
        exit(EXIT_FAILURE);
    }
}

inline unsigned short compute_checksum(unsigned short *addr, unsigned int count) {
  unsigned long sum = 0;
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

inline unsigned short compute_ip_checksum(struct iphdr* iphdrp){
  iphdrp->check = 0;
  unsigned short computed_check =  compute_checksum((unsigned short*)iphdrp, iphdrp->ihl<<2);
  iphdrp->check = computed_check;
  return computed_check;
}

inline vector<string> split(string str, char delimiter) {
    vector<string> internal;
    string temp;
    for (char c : str) {
        if (c == delimiter) {
            internal.push_back(temp);
            temp = "";
        } else {
            temp.push_back(c);
        }
    }
    internal.push_back(temp);
    return internal;
}

inline unsigned short compute_tcp_checksum(struct iphdr *pIph, unsigned short *ipPayload) {
    unsigned long sum = 0;
    unsigned short tcpLen = ntohs(pIph->tot_len) - (pIph->ihl<<2);
    struct tcphdr *tcphdrp = (struct tcphdr*)(ipPayload);
    //add the pseudo header 
    //the source ip
    sum += (pIph->saddr>>16)&0xFFFF;
    sum += (pIph->saddr)&0xFFFF;
    //the dest ip
    sum += (pIph->daddr>>16)&0xFFFF;
    sum += (pIph->daddr)&0xFFFF;
    //protocol and reserved: 6
    sum += htons(IPPROTO_TCP);
    //the length
    sum += htons(tcpLen);
 
    //add the IP payload
    //initialize checksum to 0
    tcphdrp->check = 0;
    while (tcpLen > 1) {
        sum += * ipPayload++;
        tcpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(tcpLen > 0) {
        //printf("+++++++++++padding, %dn", tcpLen);
        sum += ((*ipPayload)&htons(0xFF00));
    }
      //Fold 32-bit sum to 16 bits: add carrier to result
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
      sum = ~sum;
    //set computation result
    tcphdrp->check = (unsigned short)sum;
    return (unsigned short)sum;
}



inline unsigned short compute_udp_checksum(struct iphdr *pIph, unsigned short *udphdr) {
    unsigned long sum = 0;
    struct udphdr *udphdrp = (struct udphdr*)(udphdr);
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
        sum += * udphdr++;
        udpLen -= 2;
    }
    //if any bytes left, pad the bytes and add
    if(udpLen > 0) {
        //printf("+++++++++++++++padding: %dn", udpLen);
        sum += ((*udphdr)&htons(0xFF00));
    }
      //Fold sum to 16 bits: add carrier to result
    //printf("add carriern");
      while (sum>>16) {
          sum = (sum & 0xffff) + (sum >> 16);
      }
    //printf("one's complementn");
      sum = ~sum;
    //set computation result
    unsigned short computed_udp_checksum = ((unsigned short)sum == 0x0000)?0xFFFF:(unsigned short)sum;
    udphdrp->check = computed_udp_checksum;
    return computed_udp_checksum;
}

inline bool checkCorruptedIP(struct iphdr * ip_header) {
    unsigned short cur_checksum = (unsigned short)(ip_header->check);
    unsigned short computed_check = compute_ip_checksum(ip_header);
    std::cout << "Checksum: " << ntohs(ip_header->check) << std::endl;
    cout << cur_checksum << endl;
    cout << computed_check << endl;
    if (cur_checksum != computed_check) {
        return true;
    } else {
        return false;
    }
}



inline bool checkCorruptedUDP(struct iphdr * ip_header, unsigned short * udp_header) {
    std::cout << "Checksum2: " << ntohs(ip_header->check) << std::endl;
    
    struct udphdr *udp_header_struct = (struct udphdr*)(udp_header);
    cout << "UDP Checksum: " << ntohs(udp_header_struct->check) << endl;
    unsigned short cur_checksum = static_cast<unsigned short>(udp_header_struct->check);
    auto computed_check = compute_udp_checksum(ip_header, udp_header);
    cout << cur_checksum << endl;
    cout << computed_check << endl;
    udp_header_struct->check = cur_checksum;
    std::cout << "Checksum3: " << ntohs(ip_header->check) << std::endl;
    cout << "UDP Checksum: " << ntohs(udp_header_struct->check) << endl;
    if (cur_checksum != computed_check) {
        return true;
    } else {
        return false;
    }
}

inline bool checkCorruptedTCP(struct iphdr * ip_header, unsigned short * tcp_header) {
    struct tcphdr *tcp_header_struct = (struct tcphdr*)(tcp_header);
    unsigned short cur_checksum = static_cast<unsigned short>(tcp_header_struct->check);
    auto computed_check = compute_tcp_checksum(ip_header, tcp_header);;
    cout << cur_checksum << endl;
    cout << computed_check << endl;
    tcp_header_struct->check = cur_checksum;
    std::cout << "Checksum3: " << ntohs(ip_header->check) << std::endl;
    cout << "TCP Checksum: " << ntohs(tcp_header_struct->check) << endl;
    if (cur_checksum != computed_check) {
        return true;
    } else {
        return false;
    }
}

inline bool Count(vector<string>& v, string& s) {
    return find(v.begin(), v.end(), s) != v.end();
}

inline std::string bufferToHex(const char* buffer, std::size_t size) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for(std::size_t i = 0; i < size; ++i) {
        ss << setw(2) << static_cast<unsigned>(static_cast<unsigned char>(buffer[i])) << "  ";
    }
    return ss.str();
}


#endif