#include <stdlib.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <pcap/pcap.h>
#include "checksum.h"

#define USAGE 2
#define MACLEN 6
#define ETHER_OFFSET 14
#define IP 8
#define ICMP 1
#define TCP 6
#define UDP 17
#define ICMP_REQUEST 8
#define ICMP_REPLY 0
#define OP_REQUEST 1
#define OP_REPLY 2
#define ACK 16
#define SYN 2
#define RST 4
#define FIN 1
#define PSEUDO 12
#define HTTP 80
#define FTP 20
#define TELNET 23
#define POP 110
#define SMTP 161

struct ethernet_header {
	u_char dest[MACLEN];	
	u_char src[MACLEN];	
	uint16_t type;
} __attribute__((packed)); 

struct ip_header {
	uint8_t version_header_len;
	uint8_t TOS;
	uint16_t PDU_len;
	uint16_t id;
	uint16_t offset;
	uint8_t TTL;
	uint8_t protocol;
	uint16_t checksum;
	uint32_t sender_ip;
	uint32_t dest_ip;
} __attribute__((packed)); 

struct icmp_header {
	uint8_t type;
} __attribute__((packed));

struct arp_header {
	uint16_t hard_type;
	uint16_t proto_type;
	uint8_t hard_size;
	uint8_t proto_size;
	uint16_t opcode;
	u_char src[MACLEN];
	uint32_t sender_ip;
	u_char dest[MACLEN];
	uint32_t target_ip;
} __attribute__((packed));

struct tcp_header {
	uint16_t source_port;
	uint16_t dest_port;
	uint32_t sequence;
	uint32_t ack;
	uint16_t header_len_flags;
	uint16_t window_size;
	uint16_t checksum;
	uint16_t urgent;
} __attribute__((packed));

struct tcp_pseudo {
	uint32_t sender_ip;
	uint32_t dest_ip;
	uint8_t reserved;
	uint8_t protocol;
	uint16_t tcp_len;
} __attribute__((packed));

struct udp_header {
	uint16_t source_port;
	uint16_t dest_port;
	uint16_t length;
	uint16_t checksum;
} __attribute__((packed));

void usage();
uint16_t ethernet(const u_char *ether);
uint8_t ip(const u_char *ether);
void arp(const u_char *ether);
void icmp(const u_char *ether);
void tcp(const u_char *ether);
void udp(const u_char *ether);
void print_header(int packet_num, int frame_len);
void tcp_flags(uint16_t raw);
void port(uint16_t port);
