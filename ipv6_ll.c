/*
 * Send an IPv6 packet via raw socket at the link layer (ethernet frame).
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>		// close()
#include <string.h>		// strcpy, memset(), and memcpy()

#include <netdb.h>		// struct addrinfo
#include <sys/types.h>		// needed for socket(), uint8_t, uint16_t, uint32_t
#include <sys/socket.h>		// needed for socket()
#include <netinet/in.h>		// IPPROTO_TCP, INET6_ADDRSTRLEN
#include <netinet/ip.h>		// IP_MAXPACKET(which is 65535)
#include <netinet/ip6.h>	// struct ip6_hdr
#include <linux/tcp.h>	// struct tcphdr
#include <arpa/inet.h>		// inet_pton() and inet_ntop()
#include <sys/ioctl.h>		// macro ioctl is defined
#include <bits/ioctls.h>	// defines values for argument "request" of ioctl.
#include <net/if.h>		// struct ifreq
#include <linux/if_ether.h>	// ETH_P_IP = 0x0800, ETH_P_IPV6 = 0x86DD
#include <linux/if_packet.h>	// struct sockaddr_ll(see man 7 packet)
#include <net/ethernet.h>
#include <errno.h>		// errno, perror()

// Define some constants.
#define ETH_HDRLEN 14		// Ethernet header length
#define IP6_HDRLEN 40		// IPv6 header length
#define TCP_HDRLEN 20		// TCP header length, excludes options data
#define INTERFACE_NAME "wlp3s0" // Interface name

//Pseudo header needed for calculating the TCP header checksum
struct pseudoTCPPacket {
  uint32_t srcAddr;
  uint32_t dstAddr;
  uint8_t zero;
  uint8_t protocol;
  uint16_t TCP_len;
};

//Calculate the TCP header checksum of a string (as specified in rfc793)
//Function from http://www.binarytides.com/raw-sockets-c-code-on-linux/
unsigned short csum(unsigned short *ptr,int nbytes) {
  long sum;
  unsigned short oddbyte;
  short answer;

  //Debug info
  //hexdump((unsigned char *) ptr, nbytes);
  //printf("csum nbytes: %d\n", nbytes);
  //printf("csum ptr address: %p\n", ptr);

  sum=0;
  while(nbytes>1) {
    sum+=*ptr++;
    nbytes-=2;
  }
  if(nbytes==1) {
    oddbyte=0;
    *((u_char*)&oddbyte)=*(u_char*)ptr;
    sum+=oddbyte;
  }

  sum = (sum>>16)+(sum & 0xffff);
  sum = sum + (sum>>16);
  answer=(short)~sum;

  return(answer);
}


int main(int argc, char **argv)
{
	int i, status, frame_length, sd, bytes, tcp_flags[8];
	uint8_t src_mac[6], dst_mac[6], ether_frame[1518];
	char interface[40], target[INET6_ADDRSTRLEN], src_ip[INET6_ADDRSTRLEN], dst_ip[INET6_ADDRSTRLEN];
	struct ip6_hdr iphdr;
	struct tcphdr *tcpHdr;
	struct addrinfo hints, *res;
	struct sockaddr_in6 *ipv6;
	struct sockaddr_ll device;
	struct ifreq ifr;
	void *tmp;
	char *data;

	// Interface to send packet through.
	if (argc > 1)
		strcpy(interface, argv[1]);
	else
		strcpy(interface, INTERFACE_NAME);

	// Submit request for a socket descriptor to look up interface.
	if ((sd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
		perror("socket() failed to get socket descriptor for using ioctl() ");
		exit(EXIT_FAILURE);
	}

	// Use ioctl() to look up interface name and get its MAC address.
	memset(&ifr, 0, sizeof(ifr));
	snprintf(ifr.ifr_name, sizeof(ifr.ifr_name), "%s", interface);
	if (ioctl(sd, SIOCGIFHWADDR, &ifr) < 0) {
		perror("ioctl() failed to get source MAC address ");
		return(EXIT_FAILURE);
	}

	// Copy source MAC address.
	memcpy(src_mac, ifr.ifr_hwaddr.sa_data, 6 * sizeof(uint8_t));

	// Find interface index from interface name and store index in
	// struct sockaddr_ll device, which will be used as an argument of sendto().
	memset(&device, 0, sizeof(device));
	if ((device.sll_ifindex = if_nametoindex(interface)) == 0) {
		perror("if_nametoindex() failed to obtain interface index ");
		exit(EXIT_FAILURE);
	}

	// Set destination MAC address: you need to fill these out
	dst_mac[0] = 0xff;
	dst_mac[1] = 0xff;
	dst_mac[2] = 0xff;
	dst_mac[3] = 0xff;
	dst_mac[4] = 0xff;
	dst_mac[5] = 0xff;

	// Source IPv6 address: you need to fill this out
	strcpy(src_ip, "fe80::fab1:56ff:fefb:df9e");

	// Destination URL or IPv6 address: you need to fill this out
	strcpy(target, "fe80::5e26:aff:fe6e:aa88");
	// 2001:1bcd:123:1:1413:e4de:53f3:197
	
	// Fill out hints for getaddrinfo().
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_INET6;
	hints.ai_socktype = SOCK_RAW;
	hints.ai_flags = hints.ai_flags | AI_CANONNAME;

	// Resolve target using getaddrinfo().
	if ((status = getaddrinfo(target, NULL, &hints, &res)) != 0) {
		fprintf(stderr, "getaddrinfo() failed: %s\n", gai_strerror(status));
		exit(EXIT_FAILURE);
	}
	ipv6 =(struct sockaddr_in6 *) res->ai_addr;
	tmp = &(ipv6->sin6_addr);
	if (inet_ntop(AF_INET6, tmp, dst_ip, INET6_ADDRSTRLEN) == NULL) {
		status = errno;
		fprintf(stderr, "inet_ntop() failed.\nError message: %s", strerror(status));
		exit(EXIT_FAILURE);
	}
	freeaddrinfo(res);

	// Fill out sockaddr_ll.
	device.sll_family = AF_PACKET;
	memcpy(device.sll_addr, src_mac, 6 * sizeof(uint8_t));
	device.sll_halen = 6;

	// IPv6 header

	// IPv6 version (4 bits), Traffic class (8 bits), Flow label (20 bits)
	iphdr.ip6_flow = htonl((6 << 28) |(0 << 20) | 0);

	// Payload length (16 bits)
	iphdr.ip6_plen = 0;	// htons(TCP_HDRLEN);

	// Next header (8 bits): 6 for TCP
	iphdr.ip6_nxt = 255;	//IPPROTO_TCP;

	// Hop limit (8 bits): default to maximum value
	iphdr.ip6_hops = 255;

	// Source IPv6 address (128 bits)
	if ((status = inet_pton(AF_INET6, src_ip, &(iphdr.ip6_src))) != 1) {
		fprintf(stderr, "inet_pton() failed.\nError message: %s", strerror(status));
		exit(EXIT_FAILURE);
	}

	// Destination IPv6 address (128 bits)
	if ((status = inet_pton(AF_INET6, dst_ip, &(iphdr.ip6_dst))) != 1) {
		fprintf(stderr, "inet_pton() failed.\nError message: %s", strerror(status));
		exit(EXIT_FAILURE);
	}

	// TCP header
	//Setup
	char *srcIP = "fe80::fab1:56ff:fefb:df9e";
	char *dstIP = "fe80::5e26:aff:fe6e:aa88";
	int dstPort = 30000;
	int srcPort = 30001;

	//Pseudo TCP header to calculate the TCP header's checksum
	struct pseudoTCPPacket pTCPPacket;

	//Pseudo TCP Header + TCP Header + data
	char *pseudo_packet;


	//Populate tcpHdr
	tcpHdr->source = htons(srcPort); //16 bit in nbp format of source port
	tcpHdr->dest = htons(dstPort); //16 bit in nbp format of destination port
	tcpHdr->seq = 0x0; //32 bit sequence number, initially set to zero
	tcpHdr->ack_seq = 0x0; //32 bit ack sequence number, depends whether ACK is set or not
	tcpHdr->doff = 5; //4 bits: 5 x 32-bit words on tcp header
	tcpHdr->res1 = 0; //4 bits: Not used
	tcpHdr->cwr = 0; //Congestion control mechanism
	tcpHdr->ece = 0; //Congestion control mechanism
	tcpHdr->urg = 0; //Urgent flag
	tcpHdr->ack = 0; //Acknownledge
	tcpHdr->psh = 0; //Push data immediately
	tcpHdr->rst = 0; //RST flag
	tcpHdr->syn = 1; //SYN flag
	tcpHdr->fin = 0; //Terminates the connection
	tcpHdr->window = htons(155);//0xFFFF; //16 bit max number of databytes 
	tcpHdr->check = 0; //16 bit check sum. Can't calculate at this point
	tcpHdr->urg_ptr = 0; //16 bit indicate the urgent data. Only if URG flag is set

	//Now we can calculate the checksum for the TCP header
	pTCPPacket.srcAddr = inet_addr(srcIP); //32 bit format of source address
	pTCPPacket.dstAddr = inet_addr(dstIP); //32 bit format of source address
	pTCPPacket.zero = 0; //8 bit always zero
	pTCPPacket.protocol = IPPROTO_TCP; //8 bit TCP protocol
	pTCPPacket.TCP_len = htons(sizeof(struct tcphdr) + strlen(data)); // 16 bit length of TCP header

	//Populate the pseudo packet
	pseudo_packet = (char *) malloc((int) (sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(data)));
	memset(pseudo_packet, 0, sizeof(struct pseudoTCPPacket) + sizeof(struct tcphdr) + strlen(data));

	//Copy pseudo header
	memcpy(pseudo_packet, (char *) &pTCPPacket, sizeof(struct pseudoTCPPacket));

	tcpHdr->check = 0;

	//Copy tcp header + data to fake TCP header for checksum
	memcpy(pseudo_packet + sizeof(struct pseudoTCPPacket), tcpHdr, sizeof(struct tcphdr) + strlen(data));

	//Set the TCP header's check field
	tcpHdr->check = (csum((unsigned short *) pseudo_packet, (int) (sizeof(struct pseudoTCPPacket) + 
        sizeof(struct tcphdr) +  strlen(data))));

	printf("TCP Checksum: %d\n", (int) tcpHdr->check);


	// Fill out ethernet frame header.

	// Ethernet frame length = ethernet header (MAC + MAC + ethernet type) + ethernet data (IP header + TCP header)
	frame_length = 6 + 6 + 2 + IP6_HDRLEN;// + TCP_HDRLEN;

	// Destination and Source MAC addresses
	memcpy(ether_frame, dst_mac, 6 * sizeof(uint8_t));
	memcpy(ether_frame + 6, src_mac, 6 * sizeof(uint8_t));

	// Next is ethernet type code (ETH_P_IPV6 for IPv6).
	// http://www.iana.org/assignments/ethernet-numbers
	ether_frame[12] = ETH_P_IPV6 / 256;
	ether_frame[13] = ETH_P_IPV6 % 256;

	// Next is ethernet frame data (IPv6 header + TCP header).

	// IPv6 header
	memcpy(ether_frame + ETH_HDRLEN, &iphdr, IP6_HDRLEN * sizeof(uint8_t));

	// TCP header

	// Send ethernet frame to socket.
	if ((bytes = sendto(sd, ether_frame, frame_length, 0,(struct sockaddr *) &device, sizeof(device))) <= 0) {
		perror("sendto() failed");
		exit(EXIT_FAILURE);
	} else {
		printf("Success! Sent %d bytes.\n", bytes);
	}

	// Close socket descriptor.
	close(sd);

	return(EXIT_SUCCESS);
}
