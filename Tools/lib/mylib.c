/*

Lib sniff By Lionel PRAT & Truff & descript
cronos56@yahoo.com & truff@ifrance.com & descript@subakt.fr
http://www.nether.net/~lionel56

*/
#include "mylib.h"

int init_sniff(char *interface){
	int sock;
	struct ifreq ifr;
	 /*     htons(ETH_P_IP) ou  htons(0x800) */
	if((sock = socket(AF_INET, SOCK_PACKET, htons(0x800))) < 0) {
		perror("Probleme socket()");
		exit(0);
	}

	strncpy(ifr.ifr_name, interface,strlen(ifr.ifr_name));
	if((ioctl(sock, SIOCGIFFLAGS, &ifr) == -1)) {
		perror("Probleme ioctl()");
		exit(0);
	}
	ifr.ifr_flags |= IFF_PROMISC;
	if (ioctl (sock, SIOCSIFFLAGS, &ifr) == -1 ) {
		perror("Probleme ioctl()");
		exit(0);
	}
	return(sock);
}

int get_packet(int sock){

  	fd_set rset;
	char recvbuf[8192];
	int ok;

	while (1)
	{
		FD_ZERO(&rset);
		FD_SET(sock,&rset);
		FD_SET(STDIN_FILENO,&rset);
		select(sock+1,&rset,NULL,NULL,NULL);
		if (FD_ISSET(sock,&rset))
		{
			read(sock,recvbuf,8191);
			ok=gere_packet(recvbuf);
		}
	}

}

int gere_packet(char *packet){


    	struct ethhdr *eth;
    	struct iphdr *ip;
    	struct tcphdr *tcp;
    	struct udphdr *udp;
    	struct icmphdr *icmp;

	char *data;
     	int d_size, e_size, ip_size, t_size, u_size, ic_size;

	e_size = sizeof(struct ethhdr);
	ip_size = sizeof(struct iphdr);
	t_size = sizeof(struct tcphdr);
	u_size = sizeof(struct udphdr);
	ic_size = sizeof(struct icmphdr);

	eth = (struct ethhdr *) packet;
	ip = (struct iphdr *) (packet + e_size);

	if (ip->protocol == 6) {
		tcp = (struct tcphdr *) (packet + e_size + ip_size);
		data = (packet + e_size + ip_size + t_size);
		d_size  = (htons(ip->tot_len) - ip_size - t_size);
		eth_print(eth);
		ip_print(ip);
		tcp_print(tcp);
		data_print(data);
	}

	if (ip->protocol == 17) {
		udp = (struct udphdr *) (packet + e_size + ip_size);
		data = (packet + e_size + ip_size + u_size);
		d_size  = (htons(ip->tot_len) - ip_size - u_size);
		eth_print(eth);
		ip_print(ip);
		udp_print(udp);
	}

	if (ip->protocol == 1) {
		icmp = (struct icmphdr *) (packet + e_size + ip_size);
		data = (packet + e_size + ip_size + ic_size);
		d_size  = (htons(ip->tot_len) - ip_size - ic_size);
		eth_print(eth);
		ip_print(ip);
		icmp_print(icmp);
	}

	if (ip->protocol != 6) {
		if (ip->protocol != 17) {
			if (ip->protocol != 1) {
				eth_print(eth);
				ip_print(ip);
			}
		}
	}

}


int eth_print(struct ethhdr *eth){

	printf("+-----< Ethernet Header >\n|\n");
	printf("| Ethernet Destination (h_dest):\t%s\n", inet_ntoa(*(struct in_addr *) &eth->h_dest));
	printf("| Ethernet Source (h_source):\t\t%s\n", inet_ntoa(*(struct in_addr *) &eth->h_source));
	printf("| Ethernet Protocol (h_proto):\t\t%u\n|\n", eth->h_proto);

	return 1;

}

int ip_print(struct iphdr *ip){

	printf("+-----< IP Header >\n|\n");
	printf("| Version (version):\t\t\t%d\n", ip->version);
	printf("| IHL (ihl):\t\t\t\t%d\n", ip->ihl);
	printf("| Type of Service (tos):\t\t%d\n", ntohs(ip->tos));
	printf("| Total Length (tot_len):\t\t%d\n", ntohs(ip->tot_len));
	printf("| Identification (id):\t\t\t%d\n", ip->id);
	printf("| Fragment Offset (frag_off):\t\t%u\n", ip->frag_off);
	printf("| Time to Live (ttl):\t\t\t%d\n", ip->ttl);
	printf("| Protocol (protocol):\t\t\t%d\n", ip->protocol);
	printf("| Header Checksum (check):\t\t%d\n", ntohs(ip->check));
	printf("| Source Address (saddr):\t\t%s\n", inet_ntoa(*(struct in_addr *) &ip->saddr));  /*ip->saddr*/
	printf("| Destination Address (daddr):\t\t%s\n|\n", inet_ntoa(*(struct in_addr *) &ip->daddr));

	return 1;
}

int tcp_print(struct tcphdr *tcp){

	printf("+-----< TCP HEADER >\n|\n");
	printf("| Source Port (source):\t\t\t%d\n", ntohs(tcp->source));
	printf("| Destination Port (dest):\t\t%d\n", ntohs(tcp->dest));
	printf("| Sequence Number (seq):\t\t%x\n", tcp->seq);
	printf("| Acknowledgment Number (ack):\t\t%x\n", tcp->ack_seq);
	printf("| Data Offset (doff):\t\t\t%d\n", ntohs(tcp->doff));
	printf("| Reserverd 1 (res1):\t\t\t%d\n", ntohs(tcp->res1));
	printf("| Reserverd 2 (res2):\t\t\t%d\n", ntohs(tcp->res2));
	printf("| Flags (urg|ack|psh|rst|syn|fin):\t");

	if (tcp->urg == 1) { printf("URG "); }
	if (tcp->ack == 1) { printf("ACK "); }
	if (tcp->psh == 1) { printf("PSH "); }
	if (tcp->rst == 1) { printf("RST "); }
	if (tcp->syn == 1) { printf("SYN "); }
	if (tcp->fin == 1) { printf("FIN "); }

	printf("\n| Window (window):\t\t\t%d\n", ntohs(tcp->window));
	printf("| Header Checksum (check):\t\t%d\n", ntohs(tcp->check));
	printf("| Urgent Pointer (urg_ptr):\t\t%u\n", tcp->urg_ptr);

	return 1;
}

int udp_print(struct udphdr *udp){

	printf("+-----< UDP HEADER >\n|\n");
	printf("| Source Port (source):\t\t\t%d\n", ntohs(udp->source));
	printf("| Destination Port (dest):\t\t%d\n", ntohs(udp->dest));
	printf("| Header Checksum (check):\t\t%d\n", ntohs(udp->check));

	return 1;
}

int icmp_print(struct icmphdr *icmp){

  	printf("+-----< ICMP HEADER >\n|\n");
	printf("| Message Type:\t\t\t%d\n", icmp->type);
	printf("| Message Code:\t\t%d\n", icmp->code);
	printf("| Header Checksum (check):\t\t%d\n", ntohs(icmp->checksum));
	printf("| Identification (id):\t\t\t%d\n", ntohs(icmp->un.echo.id));
	printf("| Sequence Number (seq):\t\t%x\n", ntohs(icmp->un.echo.sequence));
	printf("| Gateway:\t\t\t%s\n", inet_ntoa(*(struct in_addr *) &icmp->un.gateway));
	printf("| Mtu:\t\t%u\n", icmp->un.frag.mtu);

	return 1;
}

int data_print(char *data){

	printf("| DATA:\t\t%s\n",data);

	return 1;
}

