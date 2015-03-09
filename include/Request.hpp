#pragma once

#include <stdint.h>
#include <Packet.hpp>

namespace Transport {
	class Request {
		public:
			Request(ethernet_header ceh, ip_header cih, tcp_header cth, time_t cts, uint32_t clen);
			ethernet_header eh;
			ip_header ih;
			tcp_header th;
			time_t ts;
			uint32_t len;
	};
}