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
#include <iomanip>
#include <string>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <memory>

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
		unique_ptr<ofstream> payload_file;
		string filename;


	Connection()
		    : src_ip(""), dest_ip(""), src_port(0), dest_port(0), protocol(""),
			packet_count(0) {}
		
	Connection(const string &src_ip, const string &dest_ip, unsigned short src_port,
			unsigned short dest_port, const string &protocol)
			: src_ip(src_ip), dest_ip(dest_ip), src_port(src_port),
			dest_port(dest_port), protocol(protocol), packet_count(1) {
				filename = src_ip + ":" + to_string(src_port) +
					"_" + dest_ip + ":" + to_string(dest_port) + ".txt";


				payload_file = make_unique<ofstream>(filename, ios::app);
				if (payload_file && payload_file->is_open()) {
					(*payload_file) << "Connection Details:\n"
							 << "Source: " << src_ip << ":" << src_port << "\n"
							 << "Dest: " << dest_ip << ":" << dest_port << "\n"
							 << "Protocol: " << protocol << "\n"
							 << "=== Payload Data ===\n\n";
			}
	}

	Connection(Connection&& other) noexcept
		: src_ip(move(other.src_ip)),
		  dest_ip(move(other.dest_ip)),
		  src_port(move(other.src_port)),
		  dest_port(move(other.dest_port)),
		  protocol(move(other.protocol)),
		  packet_count(move(other.packet_count)),
		  payload_file(move(other.payload_file)),
		  filename(move(other.filename)) {}

	Connection& operator=(Connection&& other) noexcept {
		if (this != &other) {
			src_ip = move(other.src_ip);
			src_port = move(other.src_port);
			dest_ip = move(other.dest_ip);
			dest_port = move(other.dest_port);
			protocol = move(other.protocol);
			packet_count = move(other.packet_count);
			payload_file = move(other.payload_file);
			filename = move(other.filename);
		}
		return *this;
	}

	Connection(const Connection&) = delete;
	Connection& operator=(const Connection&) = delete;

	~Connection() = default;

	void increment_packet_count() {
		packet_count++;
	}

	void store_payload(const char *buffer, size_t data_size, size_t offset) {
		if (!payload_file || !payload_file->is_open()) return;

		*payload_file << "<--- Packet" << packet_count << " ---\n";
		for (size_t i = offset; i < data_size; i++) {
			unsigned char c = buffer[i];
			*payload_file << (std::isprint(c) ? static_cast<char>(c) : '.');
		}
		*payload_file << "\n\n";
		payload_file->flush();
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
		const string &protocol, const char* buffer, size_t data_size) {
	string key = generate_conn_key(src_ip, dest_ip, src_port, dest_port);

	struct iphdr *ip_header = (struct iphdr *)buffer;
	struct tcphdr *tcp_header = (struct tcphdr *)
		(buffer + (ip_header->ihl * 4));

	size_t tcp_header_size = tcp_header->doff * 4;
	size_t ip_header_size = ip_header->ihl * 4;
	size_t offset = ip_header_size + tcp_header_size;

	if (connections.find(key) != connections.end()) {
		connections[key].increment_packet_count();
		connections[key].store_payload(buffer, data_size, offset);
	} else if (connections.size() < MAX_CONNS) {
		connections[key] = Connection(src_ip, dest_ip, src_port, dest_port, protocol);
		connections[key].store_payload(buffer, data_size, offset);
	}
}

void print_statistics() {
	cout << "===Connection Statistics===\n";
	int index = 0;
	for (const auto &pair : connections) {
		pair.second.print_stats(index++);
	}

}

void print_payload(const char *buffer, size_t data_size) {
	std::cout << "Offset    Hexadecimal                         " <<
				 "               ASCII\n";
	std::cout << "---------------------------------------------"  <<
		         "---------------------------------\n";

	for (size_t i = 0; i < data_size;  i += 16) {
		cout << setw(8) << setfill('0') << hex << i << "  ";

		for (size_t j = 0; j < 16; j++) {
			if (i + j < data_size) {
				cout << setw(2) << setfill('0') << hex <<
					(static_cast<unsigned>(buffer[i + j]) & 0xFF) << " ";
			} else {
				cout << "   ";
			}
			if (j == 7) cout << " ";
		}

        std::cout << " |";
        for (size_t j = 0; j < 16; j++) {
            if (i + j < data_size) {
                unsigned char c = buffer[i + j];
                std::cout << (std::isprint(c) ? static_cast<char>(c) : '.');
            }
        }
        std::cout << "|\n";
	}
	cout << dec;
	cout << "\n";
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

		print_payload(buffer, data_size);

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
            add_or_update_conn(src_ip, dest_ip, src_port, dest_port, protocol,
					buffer, data_size);
        }
	}

	print_statistics();
	close(sockfd);
	return 0;
}

