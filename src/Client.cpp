#pragma once

#include <Client.hpp>

using namespace std;

namespace Transport {
	Client::Client() : eh(constructEH()), ih(constructIH()), th(constructTH()) {
	}

	void Client::send(void* data, const uint32_t size) {
		char listBuf[PCAP_ERRBUF_SIZE];
		if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, listBuf) == -1) {
			return emit(Event::Error("Error in pcap_findalldevs: " + string(listBuf)));
		}

		htohntr(&th);

		threads.push_back(new thread([=](){
			pcap_if_t *d;
			char errbuf[PCAP_ERRBUF_SIZE];

			const uint32_t eth_len = sizeof(ethernet_header);
			const uint32_t ip_len = sizeof(ip_header);
			const uint32_t tcp_len = sizeof(tcp_header);
			auto packet = new uint8_t[eth_len + ip_len + tcp_len + size];

			memcpy(packet, &eh, eth_len);
			memcpy(packet + eth_len, &ih, ip_len);
			memcpy(packet + eth_len + ip_len, &th, tcp_len);
			if (size > 0) memcpy(packet + eth_len + ip_len + tcp_len, data, size);
			auto length = eth_len + ip_len + tcp_len + size;

			for (d = alldevs; d; d = d->next) {
				pcap_t *adhandle;
				if ((adhandle = pcap_open(d->name,	// name of the device
					100,							// portion of the packet to capture (only the first 100 bytes)
					PCAP_OPENFLAG_PROMISCUOUS,		// promiscuous mode
					1000,							// read timeout
					NULL,							// authentication on the remote machine
					errbuf							// error buffer
					)) == NULL) {
					emit(Event::Error("Unable to open the adapter. " + string(d->name) + " is not supported by WinPcap"));
					continue;
				}

				if (pcap_sendpacket(adhandle, packet, length) != 0) {
					emit(Event::Error("Error sending the packet: " + string(pcap_geterr(adhandle))));
					continue;
				}

				break;
			}
		}));
	}

	Client::~Client() {
		for (auto thr : threads) {
			thr->join();
			delete thr;
		}

		pcap_freealldevs(alldevs);
	}

	ethernet_header Client::constructEH() {
		ethernet_header eh;
		eh.dhost = { 0, 0, 0, 0, 0, 0 };
		eh.shost = { 0, 0, 0, 0, 0, 0 };
		eh.type = IPV4;
		return eh;
	}

	ip_header Client::constructIH() {
		ip_header ih;
		ih.tos = 0;
		ih.tlen = 0;
		ih.ttl = 128;
		ih.proto = TCP;
		ih.saddr = { 0, 0, 0, 0 };
		ih.daddr = { 0, 0, 0, 0 };
		return ih;
	}

	tcp_header Client::constructTH() {
		tcp_header th;
		th.sport = 0;
		th.dport = 0;
		return th;
	}

	// Converts Host-endian structs to Network-endian
	void Client::htohntr(tcp_header* th) {
		th->sport = htons(th->sport);
		th->dport = htons(th->dport);
		th->sequence = htonl(th->sequence);
		th->acknowledge = htonl(th->acknowledge);
		th->window = htons(th->window);
		th->checksum = htons(th->checksum);
		th->urgent_pointer = htons(th->urgent_pointer);
	}

	void Client::htohntr(icmp_header* ich) {
		ich->checksum = htons(ich->checksum);
		ich->id = htons(ich->id);
		ich->seq = htons(ich->seq);
	}
}