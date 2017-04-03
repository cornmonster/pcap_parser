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
#include <arpa/inet.h>
#include <netinet/ether.h>

/*
check	- Packet type (TCP, UDP, other)
check	- Source and destination MAC address
check	- Source and destination IP address (if IP packet)
check	- Source and destination ports (if TCP or UDP)
check	- Checksum (if TCP) and whether the checksum is valid
check	- Payload size
*/

using namespace std;

int counter = 1;

struct tcp_pseudo {
	struct in_addr source;
	struct in_addr dest;
	u_char reserved;
	u_char protocol;
	u_short tcp_size;
};

uint16_t checksum(unsigned short *addr, unsigned int count, uint16_t check) {
    /* Compute Internet Checksum for "count" bytes
     *         beginning at location "addr".
     */
    register long sum = 0;

    while(count > 1) {
    /*  This is the inner loop */
        sum += * addr++;
        count -= 2;
    }

    /*  Add left-over byte, if any */
    if(count > 0)
        sum += * (unsigned char *) addr;

    /*  Fold 32-bit sum to 16 bits */
    while(sum>>16)
        sum = (sum & 0xffff) + (sum >> 16);

    return (uint16_t)~sum;
}

bool isValid_checksum(struct tcphdr* tcph, struct ip* iph) {
	int ip_total_length = ntohs(iph->ip_len);
	int tcpopt_len = (tcph->doff)*4 - 20;
	int tcpdata_len = ip_total_length - (iph->ip_hl)*4 - (tcph->doff)*4;

	struct tcp_pseudo tcpph;
	tcpph.source = (in_addr)(iph->ip_src);
	tcpph.dest = (in_addr)(iph->ip_dst);
	tcpph.reserved = 0;
	tcpph.protocol = htons(IPPROTO_TCP);
	tcpph.tcp_size = htons(sizeof(struct tcphdr) + tcpopt_len + tcpdata_len);

	int total_tcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr) + tcpopt_len + tcpdata_len;
	unsigned short* tcp_copy = (unsigned short*)malloc(total_tcp_len*sizeof(unsigned short));

    memcpy((unsigned char *)tcp_copy, &tcpph, sizeof(struct tcp_pseudo));
    memcpy((unsigned char *)tcp_copy+sizeof(struct tcp_pseudo), (struct tcphdr*)tcph, sizeof(struct tcphdr));
    memcpy((unsigned char *)tcp_copy+sizeof(struct tcp_pseudo)+sizeof(struct tcphdr), (struct ip*)iph + (iph->ip_hl)*4 + (sizeof(struct tcphdr)), tcpopt_len);
    memcpy((unsigned char *)tcp_copy+sizeof(struct tcp_pseudo)+sizeof(struct tcphdr)+tcpopt_len, (struct tcphdr*)tcph + (tcph->doff*4), tcpdata_len);

    uint16_t result = checksum(tcp_copy, total_tcp_len, tcph->check);
    printf("\tCalculated checksum: 0x%x\n", result);
    if(ntohs(result) == ntohs(tcph->check)) {
    	return true;
    }
    else {
    	return false;
    }
}

void parser(const unsigned char *packet, unsigned int capture_len) {
	if (capture_len < sizeof(struct ether_header)) {
		fprintf(stderr, "Not a valid ethernet header.\n");
		return;
	}

	printf("Packet number: %d\n", counter);

	/* Get the source and destination MAC addresses */
	struct ether_header* eh = (struct ether_header*) packet;
	printf("\tSource MAC address: %s\n", ether_ntoa((const ether_addr*)eh->ether_shost));
	printf("\tDestin MAC address: %s\n", ether_ntoa((const ether_addr*)eh->ether_dhost));
	unsigned int etherType = eh->ether_type;

	/* Skip the ethernet header */
	packet += sizeof(struct ether_header);
	capture_len -= sizeof(struct ether_header);

	if (etherType == 8) { 
		/* This is an IPV4 packet */
		struct ip* iph = (struct ip*) packet;
		printf("\tSource IP Address: %s\n", inet_ntoa((in_addr)(iph->ip_src)));
		printf("\tDestin IP Address: %s\n", inet_ntoa((in_addr)(iph->ip_dst)));

		int ip_header_length = iph->ip_hl;
		int ip_total_length = ntohs(iph->ip_len);
		// printf("\tIP total length: %d\n", ntohs(iph->ip_len));
		// printf("\tIP total length: %d\n", iph->ip_hl);
		int proto = (int)iph->ip_p;
		/* Skip the ip header */
		packet += ip_header_length*4;
		capture_len -= ip_header_length*4;

		if(proto == 6) {
			/* This is a TCP packet */
			printf("\tPacket type: TCP\n");
			struct tcphdr* tcph = (struct tcphdr*) packet;
			printf("\tPayload size: %d\n", ip_total_length - ip_header_length*4 - tcph->doff*4);
			printf("\tSource Port: %d\n", ntohs(tcph->source));
			printf("\tDestin Port: %d\n", ntohs(tcph->dest));
			printf("\tChecksum: 0x%x\n", ntohs(tcph->check));
			if(isValid_checksum(tcph, iph)) 
				printf("\tChecksum status: Valid\n");
			else 
				printf("\tChecksum status: Invalid\n");
		}
		else if(proto == 11) {
			/* This is a UDP packet */
			printf("\tPacket type: UDP\n");
			struct udphdr* udph = (struct udphdr*) packet;
			printf("\tPayload size: %d\n", ntohs(udph->len)-8);
			printf("\tSource Port: %d\n", ntohs(udph->source));
			printf("\tDestin Port: %d\n", ntohs(udph->dest));
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
	while ((packet = pcap_next(pcap, &header)) != NULL){
		parser(packet, header.caplen);
		counter++;
	}

	// terminate
	return 0;
}
