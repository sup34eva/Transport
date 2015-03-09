#include <Packet.hpp>

using namespace std;

namespace Transport {
	std::ostream& operator<<(std::ostream &strm, const mac_address &addr) {
		return strm << std::to_string(addr.byte1) << ":" << std::to_string(addr.byte2) << ":" << std::to_string(addr.byte3) << ":" << std::to_string(addr.byte4) << ":" << std::to_string(addr.byte5) << ":" << std::to_string(addr.byte6);
	}

	std::ostream& operator<<(std::ostream &strm, const ip_address& addr) {
		return strm << std::to_string(addr.byte1) << "." << std::to_string(addr.byte2) << "." << std::to_string(addr.byte3) << "." << std::to_string(addr.byte4);
	}

	bool operator==(const ip_address& a, const ip_address& b) {
		return a.byte1 == b.byte1 && a.byte2 == b.byte2 && a.byte3 == b.byte3 && a.byte4 == b.byte4;
	}
}
