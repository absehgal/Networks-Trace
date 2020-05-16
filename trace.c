#include "trace.h"

int main(int argc, char *argv[]){
	uint16_t type;
	uint8_t protocol;
	int ret;
	int packet = 0;
	struct pcap_pkthdr *header;
	char errbuf[PCAP_ERRBUF_SIZE];
	const u_char *data;
	
	/* Check for proper number of arguments */
	if (argc != USAGE){
		usage();
	}

	/* Open pcap savefile for reading */
	pcap_t *save = pcap_open_offline(argv[1], errbuf);
	if (save == NULL){
		printf("pcap file could not be opened: %s\n", errbuf);
		exit(EXIT_FAILURE);
	}

	/* Loop through packets */
	while ((ret = pcap_next_ex(save, &header, &data)) >= 0){
		packet++;
		if (ret == 0){
			continue;
		}

		/* Print packet number and frame length */
		print_header(packet, header->len);

		/* Decode ethernet header, print ethernet information */ 
		type = ethernet(data);
		if (type == IP){
			protocol = ip(data);
			if (protocol == ICMP){
				icmp(data);
			} else if (protocol == UDP){
				udp(data);
			} else if (protocol == TCP){
				tcp(data);
			}
		} else {
			arp(data);
		}
	}

	/* Close savefile */
	pcap_close(save);
	return 0;
}

/* Usage message, exit */
void usage(){
	printf("Proper usage: ./trace TraceFile.pcap\n");
	exit(EXIT_FAILURE);
}

/* Obtain and print all Ethernet Header information */
uint16_t ethernet(const u_char *ether){
	struct ethernet_header *cur;
	struct ether_addr dest, src;

	/* Cast inputted header to ethernet_header struct */
	cur = (struct ethernet_header *) ether;

	/* Copy information to standard ether_addr struct 
	Needs to be this type for ether_ntoa function */
	memcpy(&dest, cur->dest, MACLEN);
	memcpy(&src, cur->src, MACLEN);

	/* Start printing ethernet header information */
	printf("\tEthernet Header\n");

	/* Convert destination address to standard hex and colon notation */
	printf("\t\tDest MAC: %s\n", ether_ntoa(&dest));

	/* Convert source address to standard hex and colon notation */
	printf("\t\tSource MAC: %s\n", ether_ntoa(&src));

	/* Determine next type, print information */
	if (ntohs(cur->type) == 0x0800){
		printf("\t\tType: IP\n");
	} else {
		printf("\t\tType: ARP\n");
	}

	/* Return type indicating IP or ARP */
	return cur->type;
}

/* Obtain and print all ARP Header information */
void arp(const u_char *ether){
	/* Use ethernet offset (14 bytes) to determine start of ARP header */
	struct arp_header *cur = (struct arp_header *)(ether + ETHER_OFFSET);
	struct in_addr send_ip, target_ip;
	struct ether_addr dest, src;

	/* Copy information to standard ether_addr struct 
	Needs to be this type for ether_ntoa function */
	memcpy(&dest, cur->dest, MACLEN);
	memcpy(&src, cur->src, MACLEN);

	printf("\n\tARP header\n");

	/* Determine and print opcode request or reply */
	if (ntohs(cur->opcode) == OP_REQUEST){
		printf("\t\tOpcode: Request\n");
	} else if (ntohs(cur->opcode) == OP_REPLY){
		printf("\t\tOpcode: Reply\n");
	}

	/* Obtain IP addresses */
	send_ip.s_addr = cur->sender_ip;
	target_ip.s_addr = cur->target_ip;

	printf("\t\tSender MAC: %s\n", ether_ntoa(&src));
	printf("\t\tSender IP: %s\n", inet_ntoa(send_ip));
	printf("\t\tTarget MAC: %s\n", ether_ntoa(&dest));
	printf("\t\tTarget IP: %s\n\n", inet_ntoa(target_ip));
}

/* Obtain and print all IP Header information */
uint8_t ip(const u_char *ether){
	struct ip_header *cur = (struct ip_header *)(ether + ETHER_OFFSET);
	struct in_addr send_addr, dest_addr;
	
	/* Store checksum value and set field equal to 0 */
	uint16_t checkstore = cur->checksum;
	cur->checksum = 0;

	/* Determine header length */
	int header_len = (cur->version_header_len & 0x0F) * 4;

	printf("\n\tIP Header\n");
	printf("\t\tHeader Len: %i (bytes)\n", header_len);
	printf("\t\tTOS: 0x%x\n", cur->TOS);
	printf("\t\tTTL: %i\n", cur->TTL);
	printf("\t\tIP PDU Len: %d (bytes)\n", ntohs(cur->PDU_len));

	/* Determine protocol */
	if (cur->protocol == ICMP){
		printf("\t\tProtocol: ICMP\n");
	} else if (cur->protocol == UDP){
		printf("\t\tProtocol: UDP\n");
	} else if (cur->protocol == TCP){
		printf("\t\tProtocol: TCP\n");
	} else {
		printf("\t\tProtocol: Unknown\n");
	}

	/* Checksum calculation and comparison */
	uint16_t actual_sum = (uint16_t)in_cksum((u_short *) (ether + ETHER_OFFSET), header_len);

	/* For display purposes, split checksum into two bytes
	uint8_t first[2];
	first[0] = *((uint8_t *)&(actual_sum) + 1);
	first[1] = *((uint8_t *)&(actual_sum)); */

	/* Went with a single uint16_t to match provided outputs */
	if (actual_sum == checkstore){
		//printf("\t\tChecksum: Correct (0x%x%x)\n", first[0], first[1]);
		printf("\t\tChecksum: Correct (0x%x)\n", actual_sum);
	} else {
		printf("\t\tChecksum: Incorrect (0x%x)\n", checkstore);
	}

	/* Obtain IP addresses */
	send_addr.s_addr = cur->sender_ip;
	dest_addr.s_addr = cur->dest_ip;
	printf("\t\tSender IP: %s\n", inet_ntoa(send_addr));
	printf("\t\tDest IP: %s\n", inet_ntoa(dest_addr));

	/* Return protocol for ICMP, TCP, or UDP */
	return cur->protocol;
}

/* Obtain and print ICMP type information */
void icmp(const u_char *ether){
	/* Determine IP header length for proper offset */
	struct ip_header *cur = (struct ip_header *)(ether + ETHER_OFFSET);
	int header_len = (cur->version_header_len & 0x0F) * 4;
	struct icmp_header *cur_icmp = (struct icmp_header *)(ether + 
						ETHER_OFFSET + header_len);

	/* Determine and print ICMP type */
	printf("\n\tICMP Header\n");
	if (cur_icmp->type == ICMP_REQUEST){
		printf("\t\tType: Request\n");
	} else if (cur_icmp->type == ICMP_REPLY) {
		printf("\t\tType: Reply\n");
	} else {
		printf("\t\tType: %d\n", cur_icmp->type);
	}
}

/* Obtain and print UDP type information */
void udp(const u_char *ether){
	/* Determine IP header length for proper offset */
	struct ip_header *ip = (struct ip_header *)(ether + ETHER_OFFSET);
	int header_len = (ip->version_header_len & 0x0F) * 4;
	struct udp_header *udp = (struct udp_header *)(ether + 
						ETHER_OFFSET + header_len);

	/* Print UDP header, call port function for proper print format */
	printf("\n\tUDP Header\n");
	printf("\t\tSource ");
	port(ntohs(udp->source_port));
	printf("\t\tDest ");
	port(ntohs(udp->dest_port));
}

/* Obtain and print TCP type information */
void tcp(const u_char *ether){
	struct ip_header *ip = (struct ip_header *)(ether + ETHER_OFFSET);
	int ipheader_len = (ip->version_header_len & 0x0F) * 4;
	struct tcp_header *tcp = (struct tcp_header *)(ether + 
						ETHER_OFFSET + ipheader_len);

	/* Create pseudo header struct */
	struct tcp_pseudo psdo;
	psdo.sender_ip = ip->sender_ip;
	psdo.dest_ip = ip->dest_ip;
	psdo.reserved = 0;
	psdo.protocol = ip->protocol;
	psdo.tcp_len = htons(ntohs(ip->PDU_len) - ipheader_len);

	/* Store checksum value and set field equal to 0 */
	uint16_t checkstore = tcp->checksum;
	tcp->checksum = 0;

	/* Create pseudo header and TCP segment buffer */
	u_char checkbuf[PSEUDO + ntohs(psdo.tcp_len)];

	/* Copy in pseudo header and TCP segment information */
	memcpy(checkbuf, &psdo, PSEUDO);
	memcpy(checkbuf + PSEUDO, tcp, ntohs(psdo.tcp_len));

	printf("\n\tTCP Header\n");

	/* Call port function for proper print format */
	printf("\t\tSource ");
	port(ntohs(tcp->source_port));
	printf("\t\tDest ");
	port(ntohs(tcp->dest_port));

	/* Print sequence number and acknowledgment using unsigned longs */
	printf("\t\tSequence Number: %lu\n", (long unsigned) ntohl(tcp->sequence));
	/* Bit mask to check if ack flag is set */
	if ((ntohs(tcp->header_len_flags) & 0x010) == 16){
		printf("\t\tACK Number: %lu\n", (long unsigned) ntohl(tcp->ack));
	} else {
		printf("\t\tACK Number: <not valid>\n");
	}

	/* Call flag function for bit masking and printing */
	tcp_flags(ntohs(tcp->header_len_flags));
	printf("\t\tWindow Size: %i\n", ntohs(tcp->window_size));

	uint16_t actual_sum = (uint16_t)in_cksum((u_short *) checkbuf, PSEUDO + ntohs(ip->PDU_len) - ipheader_len);
	/* For display purposes, split checksum into two bytes
	uint8_t first[2];
	first[0] = *((uint8_t *)&(actual_sum) + 1);
	first[1] = *((uint8_t *)&(actual_sum)); */

	/* Went with a single uint16_t to match provided outputs */
	if (actual_sum == checkstore){
		//printf("\t\tChecksum: Correct (0x%x%x)\n", first[1], first[0]);
		printf("\t\tChecksum: Correct (0x%x)\n", ntohs(actual_sum));
	} else {
		printf("\t\tChecksum: Incorrect (0x%x)\n", ntohs(checkstore));
	}
}

/* Determine and print port */
void port(uint16_t port){
	if (port == HTTP){
		printf("Port:  HTTP\n");
	} else if (port == FTP) {
		printf("Port: FTP\n");
	} else if (port == TELNET) {
		printf("Port: Telnet\n");
	} else if (port == POP) {
		printf("Port: POP3\n");
	} else if (port == SMTP) {
		printf("Port: SMTP\n");
	} else {
		printf("Port: : %d\n", port);
	}
}

/* Determine and print TCP flags using bit masking and comparisons */
void tcp_flags(uint16_t raw){
	if ((raw & 0x010) == ACK){
		printf("\t\tACK Flag: Yes\n");
	} else {
		printf("\t\tACK Flag: No\n");
	}
	if ((raw & 0x002) == SYN){
		printf("\t\tSYN Flag: Yes\n");
	} else {
		printf("\t\tSYN Flag: No\n");
	}
	if ((raw & 0x004) == RST){
		printf("\t\tRST Flag: Yes\n");
	} else {
		printf("\t\tRST Flag: No\n");
	}
	if ((raw & 0x001) == FIN){
		printf("\t\tFIN Flag: Yes\n");
	} else {
		printf("\t\tFIN Flag: No\n");
	}
}

/* Print packet number and frame length */
void print_header(int packet_num, int frame_len){
	printf("\n");
	printf("Packet number: %i  Frame Len: %d\n", packet_num, frame_len);
	printf("\n");
}
