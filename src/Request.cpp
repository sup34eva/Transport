#include <Request.hpp>

using namespace std;

namespace Transport {
	Request::Request(ethernet_header ceh, ip_header cih, tcp_header cth, time_t cts, uint32_t clen) : eh(ceh), ih(cih), th(cth), ts(cts), len(clen) {
		//NOOP
	}
}