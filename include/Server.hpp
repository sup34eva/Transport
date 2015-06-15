#pragma once

#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <mutex>
#include <vector>

#include <EventEmitter.hpp>
#include <Events.hpp>
#include <Packet.hpp>

namespace Transport {
	class Server : public EventEmitter<Server> {
		public:
			void listen(uint16_t port = NULL);
			~Server();
		protected:
			// Print payload data as hex
			void printHex(uint8_t* data, uint32_t length);
		private:
			pcap_if_t *alldevs;
			std::vector<std::thread*> threads;
	};
}
