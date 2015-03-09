#pragma once

#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <thread>

#include <EventEmitter.hpp>
#include <Events.hpp>
#include <Packet.hpp>

namespace Transport {
	class Server : public EventEmitter<Server> {
		public:
			void listen(uint16_t port = NULL);
			protected:
				// Print payload data as hex
				void printHex(uint8_t* data, uint32_t length);

				// Convert network-endian struct to host-endian struct
				void ntohstr(tcp_header* th);
				void ntohstr(icmp_header* ich);
	};
}
