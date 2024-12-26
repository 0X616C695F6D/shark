References
+ https://www.gnu.org/software/libc/manual/html_node/Local-Socket-Example.html
+ https://en.cppreference.com/w/cpp/container/unordered_map

Project
+ Similar to wireshark, I want to track individual connections and headers of
  these connections: IP, TCP headers and its payload
+ After tracking connections, build a profile for each individual connection and
  create a heuristic per connection stating its maliciousness or normality

Tasks
+ Collect each connections payload and save to a file or another data structure
+ Fine-tine an LLM on payload data from connections
	+ Take the simple case of HTTP first, telnet, nc, etc. Not encrypted.
+ Train LLM to determine 'malicious' traffic, or traffic out of the norm

Done
+ Create a connections object
+ Track individual connection headers: IP, TCP, protocol and packet count
+ Print simple statistics of each connection
