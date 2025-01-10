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
#include <chrono>
#include <bitset>
#include <sstream>
#include "json.hpp"

#define BUFFER_SIZE 65536
#define MAX_CONNS 5

using namespace std;
using json = nlohmann::json;

struct FrameSkin {
	int sequence_number;
	string encapsulation_type;
	string timestamp;
	double epoch_time;
	double relative_time;
	size_t size;
	vector<string> protocols;
	string src_mac;
	string dest_mac;
	string ip_flags;
	int ttl;
	string tcp_flags;
};

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
		vector<FrameSkin> frame_details;


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

	void add_frame_skin(const FrameSkin &details) {
		frame_details.push_back(details);
	}

	void print_stats(int index, bool frame_flag) const {
		cout << "Connection " << index + 1 << ":\n"
			 << "  Source: " << src_ip << ":" << src_port << "\n"
			 << "  Destination: " << dest_ip << ":" << dest_port << "\n"
			 << "  Protocol: " << protocol << "\n"
			 << "  Packet Count: " << packet_count << "\n\n";

		if (frame_flag) {
			for (const auto &frame : frame_details) {
				cout << "    Sequence Number: " << frame.sequence_number << "\n"
					 << "    Encapsulation: " << frame.encapsulation_type << "\n"
					 << "    Timestamp: " << frame.timestamp << "\n"
					 << "    Epoch time: " << frame.epoch_time << "\n"
					 << "    Relative time: " << frame.relative_time << "\n"
					 << "    Size: " << frame.size << "\n"
					 << "    Source MAC: " << frame.src_mac << "\n"
					 << "    Destintaion MAC: " << frame.dest_mac << "\n"
					 << "    IP flags: " << frame.ip_flags << "\n"
					 << "    TCP flags: " << frame.tcp_flags << "\n"
					 << "    TTL: " << frame.ttl << "\n"
					 << "    Protocols: ";
				for (const auto &proto : frame.protocols) cout << proto << " ";
				cout << "\n";
			}
		}
		cout << "\n";
	}

	json to_json() const {
		json frames_json = json::array();
		for (const auto &frame : frame_details) {
			frames_json.push_back({
				{"sequence_number", frame.sequence_number},
				{"encapsulation_type", frame.encapsulation_type},
				{"timestamp", frame.timestamp},
				{"epoch_time", frame.epoch_time},
				{"relative_time", frame.relative_time},
				{"size", frame.size},
				{"protocols", frame.protocols},
			});
		}
		return {
			{"src_ip", src_ip},
			{"src_port", src_port},
			{"dest_ip", dest_ip},
			{"dest_port", dest_port},
			{"protocol", protocol},
			{"packet_count", packet_count},
			{"frames", frames_json},
		};
	}
};

unordered_map<string, Connection> connections;
int running = 1; 
chrono::high_resolution_clock::time_point program_start_time;

double get_relative_time() {
	auto now = chrono::high_resolution_clock::now();
	return chrono::duration<double>(now - program_start_time).count();
}


string get_tcp_flags(const struct tcphdr *tcp_header) {
	string flags = "";
	if (tcp_header->syn) flags += "SYN";
	if (tcp_header->ack) flags += "ACK";
	if (tcp_header->fin) flags += "FIN";
	if (tcp_header->rst) flags += "RST";
	if (tcp_header->psh) flags += "PSH";
	if (tcp_header->urg) flags += "URG";
	return flags.empty() ? "NONE" : flags;
}

string get_ip_flags(uint16_t flag_bits) {
    std::bitset<16> flags(flag_bits);
    return "Reserved: " + to_string(flags[15]) + ", DF: " + to_string(flags[14]) + ", MF: " + to_string(flags[13]);
}

std::string format_mac_address(const uint8_t *mac) {
    std::ostringstream mac_stream;
    mac_stream << std::hex << std::setfill('0')
               << std::setw(2) << static_cast<int>(mac[0]) << ":"
               << std::setw(2) << static_cast<int>(mac[1]) << ":"
               << std::setw(2) << static_cast<int>(mac[2]) << ":"
               << std::setw(2) << static_cast<int>(mac[3]) << ":"
               << std::setw(2) << static_cast<int>(mac[4]) << ":"
               << std::setw(2) << static_cast<int>(mac[5]);
    return mac_stream.str();
}

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

FrameSkin generate_frames(int seq_num, const char *buffer, size_t size) {
	FrameSkin details;
	details.sequence_number = seq_num;
	details.encapsulation_type = "Ethernet";
	auto now = chrono::system_clock::now();
	auto epoch_time = chrono::system_clock::to_time_t(now);
	details.timestamp = ctime(&epoch_time);
	details.epoch_time = static_cast<double>(epoch_time);
	details.relative_time = get_relative_time();
	details.size = size;

	const uint8_t *eth_header = reinterpret_cast<const uint8_t *>(buffer);
	details.src_mac = format_mac_address(&eth_header[6]);
	details.dest_mac = format_mac_address(&eth_header[0]);

	struct iphdr *ip_header = (struct iphdr *)(buffer + 14);
	details.ttl = ip_header->ttl;
	details.ip_flags = get_ip_flags(ntohs(ip_header->frag_off));

	if (ip_header->protocol == IPPROTO_TCP) {
		struct tcphdr *tcp_header = (struct tcphdr *)(buffer + 14 + ip_header->ihl * 4);
        details.tcp_flags = get_tcp_flags(tcp_header);
	} else {
		details.tcp_flags = "N/A";
	}


	details.protocols = {"Ethernet", "IP", "TCP"};
	return details;
}

string generate_conn_key(const string &src_ip, const string &dest_ip,
		unsigned short src_port, unsigned short dest_port) {
	stringstream key;
	if (src_ip < dest_ip || (src_ip == dest_ip && src_port < dest_port)) {
		key << src_ip << ":" << src_port << "_" << dest_ip << ":" << dest_port;
	} else {
		key << dest_ip << ":" << dest_port << "_" << src_ip << ":" << src_port;
	}
	return key.str();
}

void add_or_update_conn(const string &src_ip, const string &dest_ip,
		unsigned short src_port, unsigned short dest_port,
		const string &protocol, const char* buffer, size_t data_size) {
	static int sequence_number = 1;
	string key = generate_conn_key(src_ip, dest_ip, src_port, dest_port);

	struct iphdr *ip_header = (struct iphdr *)buffer;
	struct tcphdr *tcp_header = (struct tcphdr *)
		(buffer + (ip_header->ihl * 4));

	size_t tcp_header_size = tcp_header->doff * 4;
	size_t ip_header_size = ip_header->ihl * 4;
	size_t offset = ip_header_size + tcp_header_size;

	FrameSkin frame = generate_frames(sequence_number++, buffer,
			data_size);

	if (connections.find(key) != connections.end()) {
		connections[key].increment_packet_count();
		connections[key].store_payload(buffer, data_size, offset);
		connections[key].add_frame_skin(frame);
	} else if (connections.size() < MAX_CONNS) {
		connections[key] = Connection(src_ip, dest_ip, src_port, dest_port, protocol);
		connections[key].store_payload(buffer, data_size, offset);
		connections[key].add_frame_skin(frame);
	}
}

void print_statistics(bool frame_flag) {
	// cout << "===Connection Statistics===\n";
	int index = 0;
	for (const auto &pair : connections) {
		pair.second.print_stats(index++, frame_flag);
	}

}

void write_json() {
    json connection_list = json::array();

    for (const auto& [key, connection] : connections) {
        connection_list.push_back(connection.to_json());
    }

	ofstream out_file("conns.json");
	if (out_file.is_open()) {
		out_file << connection_list.dump(4) << endl;
		out_file.close();
	} else {
		cerr << "Failed to write json file"  << endl;
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

int main(int argc, char *argv[]) {
	int sockfd;
	char buffer[BUFFER_SIZE];

	bool dump_flag = false;
	bool json_flag = false;
	bool frame_flag = false;

	for (int i = 1; i < argc; i++) {
		string arg = argv[i];
		if (arg == "-h" || arg == "--help") {
			cout << "Usage: " << argv[0] << " [options]\n";
			cout << " -d, --dump" << "    Print TCP information\n";
			cout << " -j, --json" << "    Write connections to JSON\n";
			cout << " -f, --frame" << "    Print all frame details\n";
			cout << " -h, --help" << "    Print this\n";
			return 0;
		}
		if (arg == "-d" || arg == "--dump") {
			dump_flag = true;
		}
		if (arg == "-j" || arg == "--json" || arg == "--JSON") {
			json_flag = true;
		}
		if (arg == "-f" || arg == "--frame") {
			frame_flag = true;
		}
	}

	sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
	if (sockfd < 0) {
		perror("Failed to open a socket");
		return 1;
	}

	// cout << "===Socket created===\n";
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

		if (dump_flag) { print_payload(buffer, data_size); }

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

	if (json_flag) { write_json(); }
	print_statistics(frame_flag);
	close(sockfd);
	return 0;
}

