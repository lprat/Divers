#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <linux/if.h>
#include <netinet/in.h>

int init_sniff(char *interface);
int get_packet(int sock);
int gere_packet(char *packet);
int eth_print(struct ethhdr *eth);
int ip_print(struct iphdr *ip);
int tcp_print(struct tcphdr *tcp);
int udp_print(struct udphdr *udp);
int icmp_print(struct icmphdr *icmp);
int data_print(struct icmphdr *icmp);