#include <Packet.hpp>
#include <WinSock2.h>

using namespace std;

namespace Transport {
	std::ostream& operator<<(std::ostream &strm, const mac_address &addr) {
		return strm << std::to_string(addr.byte1) << ":" << std::to_string(addr.byte2) << ":" << std::to_string(addr.byte3) << ":" << std::to_string(addr.byte4) << ":" << std::to_string(addr.byte5) << ":" << std::to_string(addr.byte6);
	}

	bool operator==(const mac_address& a, const mac_address& b) {
		return a.byte1 == b.byte1 && a.byte2 == b.byte2 && a.byte3 == b.byte3 && a.byte4 == b.byte4 && a.byte5 == b.byte5 && a.byte6 == b.byte6;
	}

	std::ostream& operator<<(std::ostream &strm, const ip_address& addr) {
		return strm << std::to_string(addr.byte1) << "." << std::to_string(addr.byte2) << "." << std::to_string(addr.byte3) << "." << std::to_string(addr.byte4);
	}

	bool operator==(const ip_address& a, const ip_address& b) {
		return a.byte1 == b.byte1 && a.byte2 == b.byte2 && a.byte3 == b.byte3 && a.byte4 == b.byte4;
	}

	void hton(ethernet_header* eh) {
		eh->type = (ether_type) htons(eh->type);
	}

	void hton(tcp_header* th) {
		th->sport = htons(th->sport);
		th->dport = htons(th->dport);
		th->sequence = htonl(th->sequence);
		th->acknowledge = htonl(th->acknowledge);
		th->window = htons(th->window);
		th->checksum = htons(th->checksum);
		th->urgent_pointer = htons(th->urgent_pointer);
	}

	void hton(icmp_header* ich) {
		ich->checksum = htons(ich->checksum);
		ich->id = htons(ich->id);
		ich->seq = htons(ich->seq);
	}

	void ntoh(ethernet_header* eh) {
		eh->type = (ether_type) ntohs(eh->type);
	}

	void ntoh(tcp_header* th) {
		th->sport = ntohs(th->sport);
		th->dport = ntohs(th->dport);
		th->sequence = ntohl(th->sequence);
		th->acknowledge = ntohl(th->acknowledge);
		th->window = ntohs(th->window);
		th->checksum = ntohs(th->checksum);
		th->urgent_pointer = ntohs(th->urgent_pointer);
	}

	void ntoh(icmp_header* ich) {
		ich->checksum = ntohs(ich->checksum);
		ich->id = ntohs(ich->id);
		ich->seq = ntohs(ich->seq);
	}
}
