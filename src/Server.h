#pragma once

#include <pcap.h>
#include <iostream>
#include <iomanip>
#include <sstream>

#include "EventEmitter.h"
#include "Events.h"
#include "Packet.h"

namespace Transport {
	class Server : public EventEmitter<Server> {
		public:
			void listen(uint16_t port = NULL) {
				try {
					pcap_if_t *alldevs;
					char errbuf[PCAP_ERRBUF_SIZE];

					// Retrieve the device list
					if (pcap_findalldevs_ex(PCAP_SRC_IF_STRING, NULL, &alldevs, errbuf) == -1)
					{
						throw Event::Error("Error in pcap_findalldevs: " + string(errbuf));
					}

					// Print the list
					int i = 0;
					pcap_if_t *d;
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

					int inum;
					cout << "Enter the interface number (1-" << i << "):";
					cin >> inum;

					if (inum < 1 || inum > i)
					{
						pcap_freealldevs(alldevs);
						throw Event::Error("Interface number out of range.");
					}

					// Jump to the selected adapter
					for (d = alldevs, i = 0; i < inum - 1; d = d->next, i++);

					// Open the adapter
					pcap_t *adhandle;
					if ((adhandle = pcap_open(d->name,	// name of the device
						65536,							// portion of the packet to capture.
						PCAP_OPENFLAG_PROMISCUOUS,		// promiscuous mode
						1000,							// read timeout
						NULL,							// remote authentication
						errbuf							// error buffer
						)) == NULL)
					{
						pcap_freealldevs(alldevs);
						throw Event::Error("Unable to open the adapter. %s is not supported by WinPcap");
					}

					// Check the link layer. We support only Ethernet for simplicity.
					if (pcap_datalink(adhandle) != DLT_EN10MB)
					{
						pcap_freealldevs(alldevs);
						throw Event::Error("This program works only on Ethernet networks.");
					}

					u_int netmask;
					if (d->addresses != NULL)
						netmask = ((struct sockaddr_in *)(d->addresses->netmask))->sin_addr.S_un.S_addr;
					else
						netmask = 0xffffff;


					/*string filter = "tcp";
					if (port != NULL)
						filter += "dst port " + to_string(port);*/
					// Compile the filter
					struct bpf_program fcode;
					if (pcap_compile(adhandle, &fcode, "ip", 1, netmask) < 0)
					{
						pcap_freealldevs(alldevs);
						throw Event::Error("Unable to compile the packet filter. Check the syntax.");
					}

					// Set the filter
					if (pcap_setfilter(adhandle, &fcode) < 0)
					{
						pcap_freealldevs(alldevs);
						throw Event::Error("Error setting the filter.");
					}

					auto localIP = *(ip_address*)(d->addresses->addr->sa_data);
					cout << "Listening on " << localIP << ":" << port << "..." << endl; // d->description
					ip_address allIP{ 0, 0, 0, 0 };
					bool acceptAll = (localIP == allIP);

					// Free the device list
					pcap_freealldevs(alldevs);

					// Start the capture
					struct pcap_pkthdr* header;
					const uint8_t* pkt_data;
					int res;
					while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {
						if (res == 0)
							continue;

						// Retrieve the Ethernet header
						auto eh = (ethernet_header*)pkt_data;

						// Retrieve the IP header
						uint32_t eth_len = sizeof(ethernet_header);
						auto ih = (ip_header*)(pkt_data + eth_len);
						uint32_t ip_len = ih->hlen * 4;

						if (ih->daddr == localIP || acceptAll) {
							switch (ih->proto) {
								case 1: { //ICMP
									auto ich = (icmp_header*)(pkt_data + eth_len + ip_len);
									ntohstr(ich);
									cout << "ICMP: " << ich->code << endl;
									// Print data
									printHex((uint8_t*)ich, sizeof(icmp_header));
								}
								break;

								case 6:  {//TCP
									// Retrieve the TCP header
									auto th = (tcp_header*)(pkt_data + eth_len + ip_len);
									ntohstr(th);

									//if (port == NULL || th->dport == port) {
									if (true) {

										// Retrieve payload
										uint32_t tcp_len = th->offset * 4;
										uint32_t payload_len = (header->caplen - eth_len - ip_len - tcp_len);
										auto payload = (uint8_t*)(pkt_data + eth_len + ip_len + tcp_len);

										// Emit a connect event
										emit(Event::Connect(Request(*eh, *ih, *th, header->ts.tv_sec, header->caplen)));

										// Print payload
										printHex(payload, payload_len);
									}
								}
								break;
							}
						}
					}
				} catch (Event::Error err) {
					emit(err);
				}
			}
			protected:
				// Print payload data as hex
				void printHex(uint8_t* data, uint32_t length) {
					char line[17];
					for (int i = 0; i < length; i++)
					{
						uint8_t c = data[i];

						//Print the hex value for every character , with a space
						ostringstream asHex;
						asHex << setw(2) << setfill('0') << hex << (uint32_t)c;
						cout << " " << asHex.str();

						//Add the character to data line
						uint8_t a = (c >= 32 && c <= 128) ? (uint8_t)c : '.';

						line[i % 16] = a;

						//if last character of a line , then print the line - 16 characters in 1 line
						if ((i != 0 && (i + 1) % 16 == 0) || i == length - 1)
						{
							line[i % 16 + 1] = '\0';

							//print a big gap of 10 characters between hex and characters
							cout << "          ";

							//Print additional spaces for last lines which might be less than 16 characters in length
							for (int j = strlen(line); j < 16; j++)
							{
								cout << "   ";
							}

							cout << line << " " << endl;
						}
					}
				}

				// Convert network-endian struct to host-endian struct
				void ntohstr(tcp_header* th) {
					th->sport = ntohs(th->sport);
					th->dport = ntohs(th->dport);
					th->sequence = ntohf(th->sequence);
					th->acknowledge = ntohf(th->acknowledge);
					th->window = ntohs(th->window);
					th->checksum = ntohs(th->checksum);
					th->urgent_pointer = ntohs(th->urgent_pointer);
				}
				void ntohstr(icmp_header* ich) {
					ich->checksum = ntohs(ich->checksum);
					ich->id = ntohs(ich->id);
					ich->seq = ntohs(ich->seq);
				}
	};
}
