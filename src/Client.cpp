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

		threads.push_back(new thread([&](){
			pcap_if_t *d;
			char errbuf[PCAP_ERRBUF_SIZE];

			hton(&th);

			const uint32_t eth_len = sizeof(ethernet_header);
			const uint32_t arp_len = sizeof(arp_header);
			const uint32_t ip_len = sizeof(ip_header);
			const uint32_t tcp_len = sizeof(tcp_header);

			auto null_mac = mac_address{ 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };
			auto arp_eth = ethernet_header{ null_mac, eh.shost, ARP };
			auto arp_pack = arp_header{ 1, IPV4, 6, 4, 1, eh.shost, ih.saddr, null_mac, ih.daddr };
			auto arp = new uint8_t[eth_len + arp_len];

			auto length = eth_len + ip_len + tcp_len + size;
			auto packet = new uint8_t[length];

			memcpy(arp, &arp_eth, eth_len);
			memcpy(arp, &arp_pack, arp_len);

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

				if (pcap_sendpacket(adhandle, arp, eth_len + arp_len) != 0) {
					emit(Event::Error("Error resolving address: " + string(pcap_geterr(adhandle))));
					continue;
				}

				struct pcap_pkthdr* header;
				const uint8_t* pkt_data;
				int res;
				while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
					cout << "ARP" << endl;
					if (res == 0)
						continue;

					// Retrieve the Ethernet header
					auto arp_eh = (ethernet_header*)pkt_data;
					if (arp_eh->type != ARP)
						continue;

					// Retrieve the ARP header
					auto ah = (arp_header*)(pkt_data + eth_len);
					if (ah->tha == eh.shost) {
						eh.dhost = ah->sha;
						break;
					}
				}

				memcpy(packet, &eh, eth_len);
				memcpy(packet + eth_len, &ih, ip_len);
				memcpy(packet + eth_len + ip_len, &th, tcp_len);
				if (size > 0) memcpy(packet + eth_len + ip_len + tcp_len, data, size);

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
}