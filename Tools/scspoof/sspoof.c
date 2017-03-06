/* Lionel PRAT proof concept SCAN SPOOFING */
/* methode trouvé par ANTIREZ */
/* THX to Klemm for idea ! */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <time.h>
#include <ctype.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <netinet/if_ether.h>
#include <net/if.h>
#include <asm/ioctls.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/ip_icmp.h>
#include <sys/time.h>
#include <sys/ioctl.h>
#include <math.h>
#include <getopt.h>

#define MTU                     1500
#define IP_HEADER               20
#define TCP_HEADER              20
#define PSEUDO_HEADER           12
#define INITSOURCE              1026
#define INITSEQ                 24375400
#define ICMPHDRSIZE sizeof(struct icmphdr)
#define IPHDRSIZE sizeof(struct iphdr)

struct icmp_packet {
    struct iphdr ip;
    struct icmphdr icmp;
    char buffer[4096];
};
int push;
int win;
int sp_fd, IF_LEN, iflink;
char *IF_NAME;
unsigned long localip, remoteip, myip;
unsigned short port;

struct syn_pk {
    struct iphdr ip;
    struct tcphdr tcp;
};

struct pseudo_pk {
    unsigned long saddr;
    unsigned long daddr;
    unsigned char zero;
    unsigned char proto;
    unsigned short len;
};

u_long nameResolve(char *hostname)
{
    struct in_addr addr;
    struct hostent *hostEnt;

    if ((addr.s_addr = inet_addr(hostname)) == -1) {
	if (!(hostEnt = gethostbyname(hostname))) {
	    printf("Name Resolution Error:`%s`\n", hostname);
	    exit(0);
	}
	bcopy(hostEnt->h_addr, (char *) &addr.s_addr, hostEnt->h_length);
    }
    return addr.s_addr;
}

char *ntoa(unsigned long ip)
{
    static char buff[18];
    char *p;
    p = (char *) &ip;
    sprintf(buff, "%d.%d.%d.%d",
	    (p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));
    return (buff);
}


unsigned short un_cksum(u_short * addr, int len)
{
    register int nleft = len;
    register u_short *w = addr;
    register int sum = 0;
    u_short answer = 0;
    while (nleft > 1) {
	sum += *w++;
	nleft -= 2;
    }
    if (nleft == 1) {
	*(u_char *) (&answer) = *(u_char *) w;
	sum += answer;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;
    return (answer);
}

u_short in_cksum(u_short * ptr, int nbytes)
{
    register long sum;
    u_short oddbyte;
    register u_short answer;

    sum = 0;
    while (nbytes > 1) {
	sum += *ptr++;
	nbytes -= 2;
    }

    if (nbytes == 1) {
	oddbyte = 0;
	*((u_char *) & oddbyte) = *(u_char *) ptr;
	sum += oddbyte;
    }

    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    answer = ~sum;

    return ((u_short) answer);
}

void raw(void)
{
    int opt = 1;

    if ((sp_fd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
	perror("Erreur");
	exit(0);
    }
    if (setsockopt(sp_fd, IPPROTO_IP, IP_HDRINCL, &opt, sizeof(opt)) < 0) {
	perror("Erreur");
	exit(0);
    }
}

int tap(char *device, int mode)
{
    int fd;
    struct ifreq ifr;

    if ((fd = socket(AF_INET, SOCK_PACKET, htons(0x3))) < 0) {
	perror("Erreur");
	exit(0);
    }

    strcpy(ifr.ifr_name, device);
    if (ioctl(fd, SIOCGIFADDR, &ifr) < 0) {
	perror("Erreur");
	exit(1);
    }
    memcpy((void *) &myip, (void *) &ifr.ifr_addr.sa_data + 2, 4);

    if (!mode) {
	close(fd);
	return (0);
    } else
	return (fd);
}

/* ****************************ICMP************************************** */
/* packet_icmp( source_ip, destination_ip, source_port, destination_port, */
/*             ip->ID, frag_off, ttl, DATA, ICMP_CODE, ICMP_TYPE, GATEWAY */
/*             , ICMP_SEQUENCE, ICMP_ID, ICMP_MTU);                       */
/* ********************************************************************** */
int send_icmp(rdst_ip, data)
char *rdst_ip, *data;
{
    struct sockaddr_in sock;
    struct icmp_packet picmp;
    struct hostent *res;

    int lesock;
    int szbuff;			/* taille du buffer */
    int szpkt;			/* taille du packet */
    int ttlr;

/* configuration packet */

    ttlr = 1 + (int) (255.0 * rand() / (RAND_MAX + 64.0));

/* Ouvre socket */
    if (!(lesock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)))
	return (-1);

/* entre DATA  + entre taille du packet */
    if (strlen(data) < 4096) {
	strcpy(picmp.buffer, data);
    } else {
	printf("Buffer OverfloW ?!! :o)\n");
	exit(0);
    }
    szbuff = strlen(picmp.buffer);
    szpkt = sizeof(struct iphdr) + sizeof(struct icmphdr) + szbuff;
/* fabrique le packet */
    memset(&picmp, 0, szpkt);

    picmp.ip.version = 4;	/* IPV4 */
    picmp.ip.ihl = 5;
    picmp.ip.tot_len = htons(szpkt);	/* Taille du packet */
    picmp.ip.ttl = ttlr;	/* TTL */
    picmp.ip.id = 0;
    picmp.ip.protocol = 1;	/* Protocol 1 = ICMP */
    picmp.ip.saddr = myip;	/* source ip */
    picmp.ip.daddr = rdst_ip;	/* dst ip */
    picmp.ip.check = un_cksum((char *) &picmp, IPHDRSIZE);

    picmp.icmp.type = 8;	/* type=8 -- PING */
    picmp.icmp.code = 0;	/* code=0 */
    picmp.icmp.checksum =
	un_cksum((char *) &picmp, IPHDRSIZE + ICMPHDRSIZE + szbuff);
    sock.sin_family = AF_INET;
    sock.sin_addr.s_addr = picmp.ip.daddr;	/*  ip dest */

/* Envoie le packet!! */
    if (sendto(lesock, &picmp, szpkt, 0, (struct sockaddr *) &sock,
	       sizeof(struct sockaddr)) == -1) {
	perror("sendto");
	return (-1);
    }
    close(lesock);
}


void fire_syn(unsigned short source, unsigned long seq)
{
    struct sockaddr_in sin;
    int shoot;
    struct syn_pk syn;
    struct pseudo_pk *ppk_p;
    char checkbuff[MTU];
    int ttlr;

    ttlr = 1 + (int) (255.0 * rand() / (RAND_MAX + 64.0));

    memset(&syn, 0, sizeof(syn));
    memset(checkbuff, 0, MTU);
    ppk_p = (struct pseudo_pk *) checkbuff;

    syn.tcp.source = source;
    syn.tcp.dest = port;
    syn.tcp.seq = seq;
    syn.tcp.doff = 5;
    syn.tcp.syn = 1;
    if (push == 1) {
	syn.tcp.psh = 1;
    }
    syn.tcp.psh = 1;
    syn.tcp.window = htons(0x7000);

    ppk_p->saddr = localip;
    ppk_p->daddr = remoteip;
    ppk_p->zero = 0;
    ppk_p->proto = IPPROTO_TCP;
    ppk_p->len = htons(TCP_HEADER);

    memcpy(checkbuff + PSEUDO_HEADER, &syn.tcp,
	   TCP_HEADER + PSEUDO_HEADER);
    syn.tcp.check = in_cksum((unsigned short *) checkbuff,
			     PSEUDO_HEADER + TCP_HEADER);

    syn.ip.ihl = 5;
    syn.ip.version = 4;
    syn.ip.tos = 0;
    syn.ip.tot_len = htons(IP_HEADER + TCP_HEADER);
    syn.ip.frag_off = 0;
    syn.ip.ttl = ttlr;
    syn.ip.protocol = IPPROTO_TCP;
    syn.ip.saddr = localip;
    syn.ip.daddr = remoteip;
    syn.ip.check = in_cksum((unsigned short *) &syn.ip, IP_HEADER);

    memset(&sin, 0, sizeof(sin));
    sin.sin_family = AF_INET;
    sin.sin_port = port;
    sin.sin_addr.s_addr = remoteip;

    shoot = sendto(sp_fd, &syn, IP_HEADER + TCP_HEADER,
		   0, (struct sockaddr *) &sin, sizeof(sin));
    if (shoot < 0)
	printf("SP_ERROR\n");
}



int main(int argc, char **argv)
{
    int opt, i = 0;
    struct iphdr *ip;
    struct icmphdr *icmp;
    char packet[MTU];
    int regpb = 0, regpb2 = 0;
    int time = 0, portsrc = 0, wid = 0;
    int diff1 = 0, diff2 = 0, diff = 0, diff0 = 0;
    int mprobe = 0, mdiff = 0, mdiff0 = 0, mdiff1 = 0;
    win = 0;
    push = 0;
    if (geteuid() || getuid()) {
	printf("Root access pls\n");
	exit(0);
    }
    if (argc < 13) {
	printf("Scan spoofing By Lionel PRAT aka Anti-Social\n");
	printf
	    ("\nUse: %s -s ip -h host -p port -i interface -d diff_id -m nbr_syn [-f] [-l port_src] [-w] [-t time] [-W diviseBY]\n\n",
	     argv[0]);
	printf
	    ("Option:\n-f -> flag PSH\n-w -> mode win ID\n-t time -> time attente en + du default\n-W 256(default) -> for win id (ex:256)\n");
	exit(0);
    }
    while ((opt = getopt(argc, argv, "s:h:p:i:d:m:f:l:w:t:W:")) != EOF) {
	switch (opt) {
	case 's':
	    localip = nameResolve(optarg);
	    break;

	case 'h':
	    remoteip = nameResolve(optarg);
	    break;

	case 'p':
	    port = htons(atoi(optarg));
	    break;

	case 'i':
	    IF_NAME = optarg;
	    if (strstr(IF_NAME, "eth"))
		IF_LEN = 14;
	    else if (strstr(IF_NAME, "ppp"))
		IF_LEN = 0;
	    else {
		printf("seulement eth|ppp.\n");
		exit(0);
	    }
	    break;
	case 'd':
	    win = 1;
	    break;
	case 'm':
	    mprobe = atoi(optarg);
	    break;
	case 'f':
	    push = 1;
	    break;
	case 'w':
	    win = 1;
	    break;
	case 't':
	    time = atoi(optarg);
	    break;
	case 'l':
	    portsrc = atoi(optarg);
	    break;
	case 'W':
	    wid = atoi(optarg);
	    break;
	default:
	    printf("Unknown Option.\n");
	    exit(0);
	    break;
	}
    }
    if ((win == 1) && (wid == 0))
	wid = 256;
    raw();
    iflink = tap(IF_NAME, 1);
    // printf("Scan spoofing by Lionel PRAT\nProof Concept\ncronos56@yahoo.com\n");

    ip = (struct iphdr *) (((char *) packet) + IF_LEN);
    icmp = (struct icmphdr *) (((char *) packet) + (sizeof(struct iphdr) +
						    IF_LEN));
    memset(&packet, 0, sizeof(packet));
    //envoié 2 ping a interval de temps d'envoie de Xpacket
    // faire moyen cette mayen est ajouté a mdiff
    // total ping envoié 3packet

    send_icmp(localip, "1234567");
    regpb = 0;
    regpb2 = 0;
    while (recv(iflink, &packet, sizeof(packet), 0)) {
	int set = 0;
	if (regpb > 30) {
	    int set2 = 0;
	    if (regpb2 > 5) {
		printf("Pb de reception ping reply\n");
		exit(0);
	    }
	    send_icmp(localip, "1234567");
	    set2 = regpb2 + 1;
	    regpb2 = set2;
	}
	if (ip->protocol == IPPROTO_ICMP) {
	    if (ip->saddr == localip && ip->daddr == myip) {
		if (icmp->code == 0 && icmp->type == 0) {
		    diff0 = ntohs(ip->id);
		    break;
		}
	    }
	}
	set = regpb + 1;
	regpb = set;
    }

    //usleep(80000);
    usleep(mprobe * 10000);
    if (time > 0) {
	sleep(time);
    }
    send_icmp(localip, "1234567");

    regpb = 0;
    regpb2 = 0;
    while (recv(iflink, &packet, sizeof(packet), 0)) {
	int set = 0;
	if (regpb > 30) {
	    int set2 = 0;
	    if (regpb2 > 5) {
		printf("Pb de reception ping reply\n");
		exit(0);
	    }
	    send_icmp(localip, "1234567");
	    set2 = regpb2 + 1;
	    regpb2 = set2;
	}
	if (ip->protocol == IPPROTO_ICMP) {
	    if (ip->saddr == localip && ip->daddr == myip) {
		if (icmp->code == 0 && icmp->type == 0) {
		    diff1 = ntohs(ip->id);
		    break;
		}
	    }
	}
	set = regpb + 1;
	regpb = set;
    }

    for (; i != mprobe; i++) {
	usleep(1);
	if (portsrc > 0) {
	    fire_syn(htons(portsrc), htonl(INITSEQ + (i * i * 1000)));
	} else {
	    fire_syn(htons(INITSOURCE), htonl(INITSEQ + (i * i * 1000)));
	}

    }
    if (time > 0) {
	sleep(time);
    }

    send_icmp(localip, "1234567");

    regpb = 0;
    regpb2 = 0;
    while (recv(iflink, &packet, sizeof(packet), 0)) {
	int set = 0;
	if (regpb > 30) {
	    int set2 = 0;
	    if (regpb2 > 5) {
		printf("Pb de reception ping reply\n");
		exit(0);
	    }
	    send_icmp(localip, "1234567");
	    set2 = regpb2 + 1;
	    regpb2 = set2;
	}
	if (ip->protocol == IPPROTO_ICMP) {
	    if (ip->saddr == localip && ip->daddr == myip) {
		if (icmp->code == 0 && icmp->type == 0) {
		    diff2 = ntohs(ip->id);
		    break;
		}
	    }
	}
	set = regpb + 1;
	regpb = set;
    }
    if (win == 1) {
	int ret = 0;
	ret = diff0 / wid;
	diff0 = ret;
	ret = 0;
	ret = diff1 / wid;
	diff1 = ret;
	mdiff1 = diff1 - diff0;
	mdiff0 = mdiff + mdiff1;
	ret = 0;
	ret = diff2 / wid;
	diff2 = ret;
	diff = diff2 - diff1;
	// printf("%d\n",mdiff0);
	if (diff > mdiff0) {
	    printf("Le port %d est Ouvert !!!!!\n", ntohs(port));
	} else {
	    printf("Le port %d est Fermé\n", ntohs(port));
	}
    } else {
	if ((diff0 == 256) || (diff0 == 512) || (diff0 == 768)
	    || (diff0 == 1024) || (diff0 == 1280) || (diff0 == 1536)
	    || (diff0 == 1792) || (diff0 == 2048))
	    printf("Possible Win ID.... (option -w)\n");
	mdiff1 = diff1 - diff0;
	mdiff0 = mdiff + mdiff1;
	diff = diff2 - diff1;
	// printf("%d\n",mdiff0);
	if (diff > mdiff0) {
	    printf("Le port %d est Ouvert !!!!!\n", ntohs(port));
	} else {
	    printf("Le port %d est Fermé\n", ntohs(port));
	}
    }
    iflink = tap(IF_NAME, 0);
    exit(0);
}
