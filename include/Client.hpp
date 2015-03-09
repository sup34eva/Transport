#pragma once

#include <EventEmitter.hpp>
#include <Packet.hpp>
#include <Events.hpp>
#include <iostream>
#include <pcap.h>

namespace Transport {
	class Client : public EventEmitter<Client> {
		protected:
			auto constructEH();
			auto constructIH();
			auto constructTH();
		public:
			void send(void* data);
	};
}