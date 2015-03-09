#pragma once

#include <stdint.h>
#include <string>

namespace Transport {
	// 6 byte MAC Address
	typedef struct mac_address {
		uint8_t byte1;
		uint8_t byte2;
		uint8_t byte3;
		uint8_t byte4;
		uint8_t byte5;
		uint8_t byte6;
	} mac_address;

	std::ostream& operator<<(std::ostream &strm, const mac_address &addr);

	// Ethernet header
	typedef struct ethernet_header{
		mac_address dhost;	// Destination host address
		mac_address shost;	// Source host address
		uint16_t type;		// Type (IP / ARP)
	} ethernet_header;

	// 4 bytes IP address
	typedef struct ip_address {
		uint8_t byte1;
		uint8_t byte2;
		uint8_t byte3;
		uint8_t byte4;
	} ip_address;

	std::ostream& operator<<(std::ostream &strm, const ip_address& addr);

	bool operator==(const ip_address& a, const ip_address& b);

	// IPv4 header
	typedef struct ip_header
	{
		uint8_t hlen : 4;			// Header length
		uint8_t version : 4;		// IPv4 version
		uint8_t tos;				// Type of service
		uint16_t tlen;				// Total length
		uint16_t id;				// Unique identifier
		uint8_t offset : 5;			// Fragment offset field
		uint8_t more : 1;
		uint8_t dont : 1;
		uint8_t res : 1;
		uint8_t fragoff;			// Fragment offset
		uint8_t ttl;				// Time to live
		uint8_t proto;				// Protocol
		uint16_t ichecksum;			// Checksum
		ip_address saddr;			// Source address
		ip_address daddr;			// Destination address
	} ip_header;

	// TCP header
	typedef struct tcp_header
	{
		uint16_t sport;				// Source port
		uint16_t dport;				// Destination port
		uint32_t sequence;			// Sequence number
		uint32_t acknowledge;		// Acknowledgement
		uint8_t ns : 1;				// Nonce Sum Flag
		uint8_t reserved : 3;		// Reserved
		uint8_t offset : 4;			// Data offset
		uint8_t fin : 1;			// Finish Flag
		uint8_t syn : 1;			// Synchronise Flag
		uint8_t rst : 1;			// Reset Flag
		uint8_t psh : 1;			// Push Flag
		uint8_t ack : 1;			// Acknowledgement Flag
		uint8_t urg : 1;			// Urgent Flag
		uint8_t ecn : 1;			// ECN-Echo Flag
		uint8_t cwr : 1;			// Congestion Window Reduced Flag
		uint16_t window;			// Window size
		uint16_t checksum;			// Checksum
		uint16_t urgent_pointer;	// Urgent pointer
	} tcp_header;

	// ICMP Header
	typedef struct icmp_header {
		uint8_t type;
		uint8_t code;
		uint16_t checksum;
		uint16_t id;
		uint16_t seq;
	} icmp_header;
}
