#include "server.h"

void Server::parseConfig() {
    string line;
    // Router's LAN IP and the WAN IP
    getline(cin, line);
    size_t pos = line.find(' ');
    server_lanIp = line.substr(0, pos);  
    server_wanIp = line.substr(pos + 1);

    
    // Read WAN & LAN client IPs
    getline(cin, line);
    wanClientIP = line;
    
    while (getline(cin, line) && line != "") {
        lanClientIPs.push_back(line);
    }

    // NAT table
    while (getline(cin, line) && line != "") {
        // Parse line into string structs for internal and external
        cout << line << endl;
        vector<string> split_strs = split(line, ' ');
        string lanstring = split_strs[0] + ':' + split_strs[1];
        string wanstring = server_wanIp + ':' + split_strs[2];
        // Add entry to NAPT table vector
        LANtoWAN[lanstring] = wanstring;
        WANtoLAN[wanstring] = lanstring;
    }
    // TODO: Read deny rules config
}

void Server::initServerSock(){
        // 1. Create a listening socket and accept multiple connections
        // create server socket
        int init_socket_status = (server_fd = socket(AF_INET, SOCK_STREAM, 0));
        checkFailure(init_socket_status, "socket failed");

        // reuse local address when binding the socket
        int optval = 1;
        int set_socket_status = setsockopt(server_fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));
        checkFailure(set_socket_status, "setsockopt failed");

        // config socket
        server_addr.sin_family = AF_INET;
        server_addr.sin_addr.s_addr = INADDR_ANY;
        server_addr.sin_port = htons(PORT);

        // bind socket to port
        int bind_status = ::bind(server_fd, (struct sockaddr *)&server_addr, sizeof(server_addr));
        checkFailure(bind_status, "bind failed");

        // listen for connections
        int listen_status = listen(server_fd, 10);
        checkFailure(listen_status, "listen failed");
}

void Server::detectNewMapping(string lan_IP_Port) {
    if (!LANtoWAN.count(lan_IP_Port)) {
        string wan_IP_Port = server_wanIp + ":" + to_string(dynamic_port_num);
        LANtoWAN[lan_IP_Port] = wan_IP_Port;
        WANtoLAN[wan_IP_Port] = lan_IP_Port;
        dynamic_port_num++;
    }
}

static void* handleClient(void* arg) {
    //std::cout << "we are here!!!!" << std::endl;
    ThreadArgs* args = static_cast<ThreadArgs*>(arg);
    int client_fd = args->client_fd;
    Server* server = args->server;
    int count = 0;
    while (true) {
        
        char *buffer = (char *)malloc(BUFFER_SIZE * sizeof(char));
        // receive request data from client and store into buffer
        ssize_t bytes_received = read(client_fd, buffer, BUFFER_SIZE);
        if (bytes_received > 0) {
            cout << "yes we are here!!!!" << endl;
            cout << count << endl;
            count++;
            // parse IP packet
            struct iphdr *ip_header = (struct iphdr *)buffer;
            // Print information
            cout << "ok this is before packet" << endl;
            Packet packet = Packet(buffer, bytes_received);
            cout << "ok this is after packet" << endl;
            if (packet.corrupted) {
                std::cout << "corrupted" << std::endl;
                continue;
            }
            auto src_ip = packet.src_ip;
            auto dest_ip = packet.dest_ip;
            if (Count(server->lanClientIPs, src_ip) && Count(server->lanClientIPs, dest_ip)) {
                int dest_fd = server->ip_fd_map[dest_ip];
                packet.recomputeTTL();
                write(dest_fd, buffer, bytes_received);
            } else if (Count(server->lanClientIPs, src_ip) && dest_ip == "10.0.0.10") {
                cout << "here we are, in lan to wan world!!!" << endl;
                string lan_IP_Port = src_ip + ":" + to_string(packet.src_port);
                server->detectNewMapping(lan_IP_Port);
                string wan_IP_Port = server->LANtoWAN[lan_IP_Port];
                cout << wan_IP_Port << endl;
                vector<string> wan_IP_Port_split = split(wan_IP_Port, ':');
                int dest_fd = server->ip_fd_map["0.0.0.0"];
                packet.replaceSource(wan_IP_Port_split);
                packet.recomputeTTL();
                cout << bufferToHex(buffer, bytes_received) << endl;
                write(dest_fd, buffer, bytes_received);
            } else if (src_ip == "10.0.0.10" && dest_ip == server->server_wanIp) {
                cout << "holly we are in the outer to inner world!!!" << endl;
                string wan_IP_Port = server->server_wanIp + ":" + to_string(packet.dest_port);
                if (!server->WANtoLAN.count(wan_IP_Port)) {
                    cout << wan_IP_Port << endl;
                    cout << "no fk why......" << endl;
                    continue;
                }
                string lan_IP_Port = server->WANtoLAN[wan_IP_Port];
                cout << lan_IP_Port << endl;
                vector<string> lan_IP_Port_split = split(lan_IP_Port, ':');
                int dest_fd = server->ip_fd_map[lan_IP_Port_split[0]];
                packet.replaceDestination(lan_IP_Port_split);
                packet.recomputeTTL();
                cout << bufferToHex(buffer, bytes_received) << endl;
                write(dest_fd, buffer, bytes_received);
            } else {
                cout << "no fk why??????......" << endl;
                continue;
            }
        } 
        free(buffer);
    }
    // close(client_fd);
    // free(arg);
    return NULL;
}


void Server::run() {
    int cur_count = 0;
     while (true) {
        struct sockaddr_in client_addr;
        socklen_t client_addr_len = sizeof(client_addr);
        int *client_fd = new int;

        // accept client connection
        if ((*client_fd = accept(server_fd, 
                                (struct sockaddr *)&client_addr, 
                                &client_addr_len)) < 0) {
            perror("accept failed");
        }
        char* ip_char = inet_ntoa(client_addr.sin_addr);
        if (cur_count == 0) {
            ip_fd_map[wanClientIP] = *client_fd;
        }
        else if (cur_count <= lanClientIPs.size()) {
            string client_ip = lanClientIPs[cur_count - 1];
            cout << "client_fd: " << *client_fd << endl;
            cout << "client ip: " << client_ip << endl;
            cout << "client port: " << ntohs(client_addr.sin_port) << endl;
            ip_fd_map[client_ip] = *client_fd;
        }
        pthread_t thread_id;
        ThreadArgs *thread_args = new ThreadArgs;
        thread_args->client_fd = *client_fd;
        thread_args->server = this;
        pthread_create(&thread_id, NULL, handleClient, thread_args);
        pthread_detach(thread_id);
        cur_count++;
    }
    
    if (close(server_fd) < 0) {
        perror("socket failed");
        exit(EXIT_FAILURE);
    }
}

void Server::printAllAttributes() {
    cout << "Server LAN IP: " << server_lanIp << endl;
    cout << "Server WAN IP: " << server_wanIp << endl;
    cout << "WAN Client IP: " << wanClientIP << endl;
    cout << "LAN Client IPs: " << endl;
    for (string ip : lanClientIPs) {
        cout << ip << endl;
    }
    cout << "LAN to WAN: " << endl;
    for (auto it = LANtoWAN.begin(); it != LANtoWAN.end(); it++) {
        cout << it->first << " " << it->second << endl;
    }
    cout << "WAN to LAN: " << endl;
    for (auto it = WANtoLAN.begin(); it != WANtoLAN.end(); it++) {
        cout << it->first << " " << it->second << endl;
    }
    cout << "Deny Rules: " << endl;
    for (vector<string> rule : denyRules) {
        for (string s : rule) {
            cout << s << " ";
        }
        cout << endl;
    }
    cout << "Dynamic Port Number: " << dynamic_port_num << endl;
    cout << "Server FD: " << server_fd << endl;
    cout << "Server Address: " << inet_ntoa(server_addr.sin_addr) << " " << ntohs(server_addr.sin_port) << endl;
}