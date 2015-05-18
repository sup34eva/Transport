#pragma once

#include <EventEmitter.hpp>
#include <Packet.hpp>
#include <Events.hpp>
#include <iostream>
#include <pcap.h>

namespace Transport {
	class Client : public EventEmitter<Client> {
		protected:
			ethernet_header constructEH();
			ip_header constructIH();
			tcp_header constructTH();
		public:
			void send(void* data);
	};
}