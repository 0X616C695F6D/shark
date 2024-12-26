#include <iostream>
#include <vector>
#include <string>
#include <unordered_map>
#include <csignal>
#include <cstring>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>

#define BUFFER_SIZE 65536
#define MAX_CONNS 5

using namespace std;

class Connection {
	public:
		string src_ip;
		string dest_ip;
		unsigned short src_port;
		unsigned short dest_port;
		string protocol;
		int packet_count;


	Connection()
		    : src_ip(""), dest_ip(""), src_port(0), dest_port(0), protocol(""),
			packet_count(0) {}
		
	Connection(const string &src_ip, const string &dest_ip, unsigned short src_port,
			unsigned short dest_port, const string &protocol)
			: src_ip(src_ip), dest_ip(dest_ip), src_port(src_port),
			dest_port(dest_port), protocol(protocol), packet_count(1) {}

	void increment_packet_count() {
		packet_count++;
	}

	void print_stats(int index) const {
		cout << "Connection " << index + 1 << ":\n"
			 << " Source: " << src_ip << ":" << src_port << "\n"
			 << " Destination: " << dest_ip << ":" << dest_port << "\n"
			 << " Protocol: " << protocol << "\n"
			 << " Packet Count: " << packet_count << "\n\n";
	}
};

unordered_map<string, Connection> connections;
int running = 1; 

void handle_signal(int signal) {
	running = 0;
}

const string get_protocol(unsigned short dest_port){
	if (dest_port == 21) { return "FTP"; }
	if (dest_port == 23) { return "Telnet"; }
	if (dest_port == 80) { return "HTTP"; }
	if (dest_port == 443) { return "HTTPS"; }
	return "TCP";
}

string generate_conn_key(const string &src_ip, const string &dest_ip,
		unsigned short src_port, unsigned short dest_port) {
	return src_ip  + ":" + to_string(src_port) + "->" +
	       dest_ip + ":" + to_string(dest_port);
}

void add_or_update_conn(const string &src_ip, const string &dest_ip,
		unsigned short src_port, unsigned short dest_port,
		const string &protocol) {
	string key = generate_conn_key(src_ip, dest_ip, src_port, dest_port);
	if (connections.find(key) != connections.end()) {
		connections[key].increment_packet_count();
	} else if (connections.size() < MAX_CONNS) {
		connections[key] = Connection(src_ip, dest_ip, src_port, dest_port, protocol);
	}
}

void print_statistics() {
	cout << "===Connection Statistics===\n";
	int index = 0;
	for (const auto &pair : connections) {
		pair.second.print_stats(index++);
	}
}

int main() {
	int sockfd;
	char buffer[BUFFER_SIZE];

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sockfd < 0) {
		perror("Failed to open a socket");
		return 1;
	}

	cout << "===Socket created===\n";
	signal(SIGINT, handle_signal);

	while (running && connections.size() < MAX_CONNS) {
		struct sockaddr_in source;
		socklen_t addr_len = sizeof(source);

		ssize_t data_size = recvfrom(sockfd, buffer, BUFFER_SIZE, 0,
				(struct sockaddr *)&source, &addr_len);
		if (data_size < 0) {
			perror("Failed to receive packets");
			continue;
		}

		struct iphdr *ip_header = (struct iphdr *)buffer;
		char src_ip[INET_ADDRSTRLEN], dest_ip[INET_ADDRSTRLEN];

		inet_ntop(AF_INET, &ip_header->saddr, src_ip, INET_ADDRSTRLEN);
		inet_ntop(AF_INET, &ip_header->daddr, dest_ip, INET_ADDRSTRLEN);
		
		 if (ip_header->protocol == IPPROTO_TCP) {
            struct tcphdr *tcp_header = (struct tcphdr *)
				(buffer + (ip_header->ihl * 4));
            unsigned short src_port = ntohs(tcp_header->source);
            unsigned short dest_port = ntohs(tcp_header->dest);

            string protocol = get_protocol(dest_port);
            add_or_update_conn(src_ip, dest_ip, src_port, dest_port, protocol);
        }
	}

	print_statistics();
	close(sockfd);
	return 0;
}
