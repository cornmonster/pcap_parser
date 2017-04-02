#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <pcap.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <string>

/*
check	- Packet type (TCP, UDP, other)
check	- Source and destination MAC address
check	- Source and destination IP address (if IP packet)
check	- Source and destination ports (if TCP or UDP)
check	- Checksum (if TCP) and whether the checksum is valid
check	- Payload size
*/

using namespace std;

int counter = 0;
// bool checkTcpCheckSum(const unsigned char *packet, ) {
	
// }

void parser(const unsigned char *packet, unsigned int capture_len) {
	string packetType;
	string sourceMAC;
	string destMAC;

	if (capture_len < sizeof(struct ether_header)) {
		fprintf(stderr, "Not a valid ethernet header.\n");
		return;
	}

	printf("Packet number: %d\n", counter);

	/* Get the source and destination MAC addresses */
	ether_header* eh = (struct ether_header*) packet;
	sourceMAC = string(reinterpret_cast<char*>((unsigned char*)packet->h_source));
	destMAC = string(reinterpret_cast<char*>((unsigned char*)packet->h_dest));
	printf("\tSource MAC address: %s\n", sourceMAC.c_str());
	printf("\tDestin MAC address: %s\n", destMAC.c_str());
	unsigned int etherType = packet->h_proto;

	/* Skip the ethernet header */
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);

	if (etherType == 8) { 
		/* This is an IPV4 packet */
		struct ip* iph = (struct ip*) packet;
		string sourceIP(inet_ntoa((in_addr)(iph->ip_src)));
		string destIP(inet_ntoa((in_addr)(iph->ip_dst)));
		printf("\tSource IP Address: %s\n", sourceIP.c_str());
		printf("\tDestin IP Address: %s\n", destIP.c_str());

		int ip_header_length = iph->ip_hl * 4;
		int ip_total_length = iph->ip_len;
		int proto = (int)iph->ip_p;
		/* Skip the ip header */
		packet += ip_header_length;
		capture_len -= ip_header_length;

		if(proto == 6) {
			/* This is a TCP packet */
			printf("\tPacket type: TCP\n");
			struct tcphdr* tcph = (struct tcphdr*) packet;
			printf("\tPayload size: %d\n", ip_total_length - ip_header_length - ntohs(tcph->th_off)*4);
			printf("\tSource Port: %s\n", ntohs(tcph->th_sport));
			printf("\tDestin Port: %s\n", ntohs(tcph->th_dport));
			// printf("\t");
		}
		else if(proto == 11) {
			/* This is a UDP packet */
			printf("\tPacket type: UDP\n");
			struct udphdr* udph = (struct udphdr*) packet;
			printf("\tPayload size: %d\n", ntohs(udph->uh_ulen)-8);
			printf("\tSource Port: %s\n", ntohs(udph->uh_sport));
			printf("\tDestin Port: %s\n", ntohs(udph->uh_dport));
		}
		else {
			/* Other protocol */
			printf("\tPacket type: Other\n");
		}
	}
	else {
		printf("\tThis is not an IP packet.\n");
	}
}

int main(int argc, char *argv[]) {
	pcap_t *pcap;
	const unsigned char *packet;
	char errbuf[PCAP_ERRBUF_SIZE];
	struct pcap_pkthdr header;

	/* Skip over the program name. */
	++argv; --argc;

	/* We expect exactly one argument, the name of the file to dump. */
	if ( argc != 1 ) {
		fprintf(stderr, "program requires one argument, the trace file to dump\n");
		exit(1);
	}

	pcap = pcap_open_offline(argv[0], errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "error reading pcap file: %s\n", errbuf);
		exit(1);
	}

	/* Now just loop through extracting packets as long as we have
	 * some to read.
	 */
	while ((packet = pcap_next(pcap, &header)) != NULL)
		parser(packet, header.caplen);

	// terminate
	return 0;
}
