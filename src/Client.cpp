#pragma once

#include <Client.hpp>

using namespace std;

namespace Transport {
	auto Client::constructEH() {
		ethernet_header eh;
		eh.dhost = { 108, 46, 133, 140, 154, 56 };
		eh.shost = { 140, 137, 165, 13, 47, 123 };
		eh.type = 8;
		return eh;
	}
	auto Client::constructIH() {
		ip_header ih;
		//ih.ver_ihl = 69;
		ih.tos = 0;
		ih.tlen = 13312;
		//ih.identification = 19570;
		//ih.flags_fo = 64;
		ih.ttl = 128;
		ih.proto = 6;
		//ih.crc = 0;
		ih.saddr = { 192, 168, 1, 13 };
		ih.daddr = { 178, 62, 65, 213 };
		return ih;
	}
	auto Client::constructTH() {
		tcp_header th;
		th.sport = 55745;
		th.dport = 20480;
		/*th.seqnum = 1121682558;
		th.acknum = 2328941219;
		th.th_off = 128;
		th.flags = 16;
		th.win = 1026;
		th.crc = 61365;
		th.urgptr = 0;*/
		return th;
	}
	void Client::send(void* data) {
		try {
			// Retrieve the device list
			pcap_if_t *alldevs;
			char errbuf[PCAP_ERRBUF_SIZE];
			if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
			{
				throw Event::Error("Error in pcap_findalldevs: " + string(errbuf));
			}

			// Print the list
			pcap_if_t *d;
			int i = 0;
			for (d = alldevs; d; d = d->next)
			{
				cout << ++i << ". " << d->name;
				if (d->description)
					cout << " (" << d->description << ")" << endl;
				else
					cout << " (No description available)" << endl;
			}

			if (i == 0)
			{
				throw Event::Error("No interfaces found! Make sure WinPcap is installed.");
			}

			int inum = 0;
			cout << "Enter the interface number (1-" << i << "):";
			cin >> inum;

			if (inum < 1 || inum > i)
			{
				pcap_freealldevs(alldevs);
				throw Event::Error("Interface number out of range.");
			}

			// Jump to the selected adapter
			for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

			// Open the output device
			pcap_t *adhandle;
			if ((adhandle = pcap_open(d->name,	// name of the device
				100,							// portion of the packet to capture (only the first 100 bytes)
				PCAP_OPENFLAG_PROMISCUOUS,		// promiscuous mode
				1000,							// read timeout
				NULL,							// authentication on the remote machine
				errbuf							// error buffer
				)) == NULL)
			{
				pcap_freealldevs(alldevs);
				throw Event::Error("Unable to open the adapter. " + string(d->name) + " is not supported by WinPcap");
			}

			const uint32_t eth_len = sizeof(ethernet_header);
			const uint32_t ip_len = sizeof(ip_header);
			const uint32_t tcp_len = sizeof(tcp_header);
			uint8_t packet[eth_len + ip_len + tcp_len];
			ethernet_header eh = constructEH();
			ip_header ih = constructIH();
			tcp_header th = constructTH();

			memcpy(packet, &eh, eth_len);
			memcpy(packet + eth_len, &ih, ip_len);
			memcpy(packet + eth_len + ip_len, &th, tcp_len);

			// Send down the packet
			if (pcap_sendpacket(adhandle, packet, eth_len + ip_len + tcp_len) != 0)
			{
				throw Event::Error("Error sending the packet: " + string(pcap_geterr(adhandle)));
			}
		} catch (const Event::Error& err) {
			emit(err);
		}
	}
}