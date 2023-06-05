### Members
- Jeffrey Yu, 305587107
- Haobo Yuan, 905510030
- Yu Shen, 505572058

### High level design
We implemneted a server application with Network Address Port Translation (NAPT), built in C++.
- It uses the socket programming interface and POSIX threads to manage client connections and process their packets.
- The Server class has the central role, it maintains mappings for LAN-to-WAN and WAN-to-LAN communications. 
- The Server object listens for client connections and each connection is managed by a separate thread created in the run() method.
- Each thread invokes the handleClient function that processes client requests, handles IP packet parsing, performs source/destination replacements based on the current NAT table, and writes the processed packets to the appropriate destination socket.
- The server can also detect new mappings, meaning it can dynamically add clients to its NAT table.
- The server prints its configuration, including IP addresses, port mappings, and denial rules using the printAllAttributes function.

### Problems we ran into
At first, we wrote a lot of code but couldn't even pass the first setting test case. We thought it was issues with checksum but we tweak it many times, still not passing. Then we "modulized" out code into components, debugged each component, and finally found out it was issues with `write()` that couldn't direct router's packet to the destination host. We learned that modulization is important.