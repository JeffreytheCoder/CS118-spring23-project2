#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

// Struct to store IP and port info 
struct IPPort {
    std::string ip;
    int port;
};

// Struct for NAPT translation table entry
struct NATEntry {
    IPPort internal;
    IPPort external;
};

// Vector to store NAPT table
std::vector<NATEntry> natTable;  

// Hash map to store port numbers for dynamic NAPT 
std::unordered_map<IPPort, int> portMap;  

// Vector to store deny rules
std::vector<IPPort> denyRules;   

int main() {
  std::string line;

  // First line is the router's LAN IP and the WAN IP
  std::getline(std::cin, line);
  size_t pos = line.find(' ');
  std::string lanIp = line.substr(0, pos);
  std::string wanIp = line.substr(pos + 1);

  std::cout << "Server's LAN IP: " << lanIp << std::endl  
            << "Server's WAN IP: " << wanIp << std::endl;
              
  // Read static NAPT table config              
  std::getline(std::cin, line);
  while (line != "") {
      // Parse line into IPPort structs for internal and external     
      size_t pos = line.find(' ');
      IPPort internal = {.ip = line.substr(0, pos), .port = stoi(line.substr(pos + 1))};  
      pos = line.find(' ', pos + 1);
      IPPort external = {.ip = wanIp, .port = stoi(line.substr(pos + 1))};
      
      // Add entry to NAPT table vector
      natTable.push_back({internal, external});  
      
      std::getline(std::cin, line);
  }
  
  // Read deny rules config
  std::getline(std::cin, line);
  while (line != "") {
      // Parse line into source and destination IPPort 
      size_t pos = line.find(' ');
      IPPort src = {.ip = line.substr(0, pos), .port = stoi(line.substr(pos + 1))};  
      pos = line.find(' ', pos + 1);
      IPPort dst = {.ip = line.substr(pos + 1), .port = stoi(line.substr(pos + 1))};   
      
      // Add rule to denyRules vector
      denyRules.emplace_back(src, dst);
    
      std::getline(std::cin, line);       
  }  

  // TODO: Setup socket, accept connections, parse packets, handle forwarding/NAPT/deny rules  
  
  return 0; 
}