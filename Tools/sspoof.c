/* Lionel PRAT proof concept SCAN SPOOFING OF SOURCE PORT */
/* methode trouv� par ANTIREZ */
/* THX to Klemm for idea ! */
/*
Compile: cc -o ssport ssport.c -D_BSD_SOURCE
*/

/*  ...
A <-----> B

     SYN
C|A -----> B
    SYN | ACK
B  -----------> A
   RST
A -------> B

Sauf si nous utilisons le port src dans ce cas:

A <-----> B

     SYN
C|A -----> B
    ACK
B  -------> A

SI(if) port SRC OK ID == BAS (bottom)
Si(if) port SRC BAD ID == HAUT (top)
*/

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

#define ICMPHDRSIZE sizeof(struct icmphdr)
#define IPHDRSIZE sizeof(struct iphdr)
#define MTU                     1500
#define IP_HEADER               20
#define TCP_HEADER              20
#define PSEUDO_HEADER           12
#define INITSEQ                 24375400

struct icmp_packet
{
struct iphdr    ip;
struct icmphdr   icmp;
char buffer[4096];
};
struct syn_pk {
    struct iphdr ip;
    struct tcphdr tcp;
};

int sp_fd, IF_LEN, iflink;
char *IF_NAME;
unsigned long localip, remoteip, myip;
unsigned short port;
int win;
u_long nameResolve(char *hostname)
{
  struct in_addr addr;
  struct hostent *hostEnt;

  if((addr.s_addr=inet_addr(hostname)) == -1) {
    if(!(hostEnt=gethostbyname(hostname))) {
        printf("Name Resolution Error:`%s`\n",hostname);
        exit(0);
    }
    bcopy(hostEnt->h_addr,(char *)&addr.s_addr,hostEnt->h_length);
  }
  return addr.s_addr;
}

char *ntoa(unsigned long ip) {
        static char buff[18];
        char *p;
        p = (char *) &ip;
        sprintf(buff, "%d.%d.%d.%d",
                (p[0] & 255), (p[1] & 255), (p[2] & 255), (p[3] & 255));
        return(buff);
}


unsigned short un_cksum(u_short *addr, int len)
{
register int nleft = len;
register u_short *w = addr;
register int sum = 0;
u_short answer = 0;
while (nleft > 1)
{
sum += *w++;
nleft -= 2;
}
if (nleft == 1)
{
*(u_char *)(&answer) = *(u_char *)w ;
sum += answer;
}
sum = (sum >> 16) + (sum & 0xffff);
sum += (sum >> 16);
answer = ~sum;
return(answer);
}

u_short in_cksum(u_short *ptr, int nbytes)
{
  register long           sum;
  u_short                 oddbyte;
  register u_short        answer;

  sum = 0;
  while (nbytes > 1)
  {
    sum += *ptr++;
    nbytes -= 2;
  }

  if (nbytes == 1)
  {
    oddbyte = 0;
    *((u_char *) &oddbyte) = *(u_char *)ptr;
    sum += oddbyte;
  }

  sum  = (sum >> 16) + (sum & 0xffff);
  sum += (sum >> 16);
  answer = ~sum;

  return((u_short) answer);
}


int tap(char* device,int mode)
{
    int fd;
    struct ifreq ifr;

    if((fd=socket(AF_INET, SOCK_PACKET, htons(0x3))) <0){
        perror("Erreur");
        exit(0);
    }

    strcpy(ifr.ifr_name,device);
    if (ioctl (fd, SIOCGIFADDR, &ifr) < 0) {
        perror("Erreur");
        exit(1);
    }
    memcpy ((void *) &myip, (void *) &ifr.ifr_addr.sa_data + 2, 4);

    if(!mode){
        close(fd);
        return(0);
    }
    else return(fd);
}

/* ****************************ICMP************************************** */
/* packet_icmp( source_ip, destination_ip, source_port, destination_port, */
/*             ip->ID, frag_off, ttl, DATA, ICMP_CODE, ICMP_TYPE, GATEWAY */
/*             , ICMP_SEQUENCE, ICMP_ID, ICMP_MTU);                       */
/* ********************************************************************** */
int
send_icmp(rdst_ip,data)
char *rdst_ip,*data;
{
struct sockaddr_in sock;
struct icmp_packet   picmp;
struct hostent *res;

int lesock;
int szbuff; /* taille du buffer */
int szpkt; /* taille du packet */
int ttlr;

/* configuration packet */

ttlr=1+(int) (255.0*rand()/(RAND_MAX+64.0));

/* Ouvre socket */
if(!(lesock=socket(AF_INET, SOCK_RAW, IPPROTO_RAW)))return(-1);

/* entre DATA  + entre taille du packet */
if(strlen(data)<4096){
strcpy(picmp.buffer,data);
}
else{
printf("Buffer OverfloW ?!! :o)\n");
exit(0);
}
szbuff=strlen(picmp.buffer);
szpkt=sizeof(struct iphdr) + sizeof(struct icmphdr) + szbuff;
/* fabrique le packet */
memset(&picmp, 0, szpkt);

picmp.ip.version = 4; /* IPV4 */
picmp.ip.ihl = 5;
picmp.ip.tot_len = htons(szpkt); /* Taille du packet */
picmp.ip.ttl = ttlr; /* TTL */
picmp.ip.id = 0;
picmp.ip.protocol = 1; /* Protocol 1 = ICMP*/
picmp.ip.saddr = myip; /* source ip */
picmp.ip.daddr = rdst_ip; /* dst ip */
picmp.ip.check = un_cksum((char *)&picmp,IPHDRSIZE);

picmp.icmp.type = 8; /* type=8 -- PING */
picmp.icmp.code = 0; /* code=0 */
picmp.icmp.checksum = un_cksum((char *)&picmp,IPHDRSIZE + ICMPHDRSIZE+ szbuff);
sock.sin_family = AF_INET;
sock.sin_addr.s_addr = picmp.ip.daddr; /*  ip dest */

/* Envoie le packet!! */
if(sendto(lesock,&picmp, szpkt, 0, (struct sockaddr *) &sock,
sizeof(struct sockaddr)) == -1) { perror("sendto"); return(-1); }
close(lesock);
}


int send_tcp(int sfd,unsigned short src_p,char *buffer,int len)
{
 struct iphdr ip_head;
 struct tcphdr tcp_head;
 struct sockaddr_in target;
 char packet[2048];     /*the exploitation of this is left as an exercise..*/
 int i;

 struct tcp_pseudo        /*the tcp pseudo header*/
 {
    unsigned long src_addr;
    unsigned long dst_addr;
    unsigned char dummy;
    unsigned char proto;
    unsigned short length;
 } pseudohead;

 struct help_checksum   /*struct for checksum calculation*/
 {
  struct tcp_pseudo pshd;
  struct tcphdr tcphd;
  char tcpdata[1024];
 } tcp_chk_construct;


 /*Prepare IP header*/
 ip_head.ihl      = 5;     /*headerlength with no options*/
 ip_head.version  = 4;
 ip_head.tos      = 0;
 ip_head.tot_len  = htons(sizeof(struct iphdr)+sizeof(struct tcphdr)+len);
 ip_head.id       = htons(31337 + (rand()%100));
 ip_head.frag_off = 0;
 ip_head.ttl      = 255;
 ip_head.protocol = IPPROTO_TCP;
 ip_head.check    = 0;    /*Fill in later*/
 ip_head.saddr    = localip;
 ip_head.daddr    = remoteip;
 ip_head.check    = in_cksum((unsigned short *)&ip_head,sizeof(struct iphdr));

 /*Prepare TCP header*/
 tcp_head.th_sport = htons(src_p);
 tcp_head.th_dport = port;
 tcp_head.th_seq   = htonl(20985);
 tcp_head.th_ack   = htonl(0);
 tcp_head.th_x2    = 0;
 tcp_head.th_off   = 5;
 tcp_head.th_flags = 0x02;
 tcp_head.th_win   = htons(0x7c00);
 tcp_head.th_sum   = 0;  /*Fill in later*/
 tcp_head.th_urp   = 0;

 /*Assemble structure for checksum calculation and calculate checksum*/
 pseudohead.src_addr=ip_head.saddr;
 pseudohead.dst_addr=ip_head.daddr;
 pseudohead.dummy=0;
 pseudohead.proto=ip_head.protocol;
 pseudohead.length=htons(sizeof(struct tcphdr)+len);

 tcp_chk_construct.pshd=pseudohead;
 tcp_chk_construct.tcphd=tcp_head;
 memcpy(tcp_chk_construct.tcpdata,buffer,len);

 tcp_head.th_sum=in_cksum((unsigned short *)&tcp_chk_construct,
                         sizeof(struct tcp_pseudo)+sizeof(struct tcphdr)+len);

 /*Assemble packet*/
 memcpy(packet,(char *)&ip_head,sizeof(ip_head));
 memcpy(packet+sizeof(ip_head),(char *)&tcp_head,sizeof(tcp_head));
 memcpy(packet+sizeof(ip_head)+sizeof(tcp_head),buffer,len);

 /*Send packet*/
 target.sin_family     = AF_INET;
 target.sin_addr.s_addr= ip_head.daddr;
 target.sin_port       = tcp_head.th_dport;
 i=sendto(sfd,packet,sizeof(struct iphdr)+sizeof(struct tcphdr)+len,0,(struct sockaddr *)&target,sizeof(struct sockaddr_in));
 if(i<0)
   return(-1); /*Error*/
 else
   return(i); /*Return number of bytes sent*/
}

int main(int argc, char **argv)
{
        int sock=0,ok=0;
        int opt, i=0;
        struct iphdr *ip;
        struct icmphdr *icmp;
        char packet[MTU];
        int time = 0, wid = 0;
        int regpb=0,regpb2=0;
	int diff1=0,diff2=0,diff=0,diff0=0;
	int mprobe=0,mdiff=0,mdiff0=0,mdiff1=0;
	int portsrcd=0,j=0,portsrcf=0;
        win=0;
        if (geteuid() || getuid()) {
                printf("Root access pls\n");
                exit(0);
        }
        if (argc<13) {
            printf("\nUse: %s -s ip -h host -p port -i interface -d diff_id -m nbr_syn -l port_src_debut -L port_src_fin -t time -w -W diviseby\n\n", argv[0]);
            exit(0);
        }

        while ((opt = getopt(argc, argv, "s:h:p:i:d:m:l:L:t:w:W:")) != EOF) {
                switch(opt)
                {
	 case 's':
                                localip=nameResolve(optarg);
                                break;

                        case 'h':
                                remoteip=nameResolve(optarg);
                                break;

                        case 'p':
                                port=htons(atoi(optarg));
                                break;

                        case 'i':
                                IF_NAME=optarg;
                                if(strstr(IF_NAME, "eth")) IF_LEN=14;
                                else if(strstr(IF_NAME, "ppp")) IF_LEN=0;
                                else {
                                        printf("seulement eth|ppp.\n");
                                        exit(0);
                                }
                                break;
                        case 'd':
                                mdiff=atoi(optarg);
                                break;
                        case 'm':
                                mprobe=atoi(optarg);
                                break;
                        case 'l':
                                portsrcd=atoi(optarg);
                                break;
                        case 'L':
                                portsrcf=atoi(optarg);
                                break;
                        case 'W':
	    			wid = atoi(optarg);
	    			break;
	 		case 'w':
	  			win = 1;
	   			break;
			case 't':
	    			time = atoi(optarg);
	    			break;
                        default:
                                printf("Unknown Option.\n");
                                exit(0);
                                break;
                }
        }
  if((sock=socket(AF_INET,SOCK_RAW,IPPROTO_RAW))<0)  /*open sending socket*/
  {
   perror("socket");
   exit(1);
  }
        iflink=tap(IF_NAME, 1);
       // printf("Scan spoofing by Lionel PRAT\nProof Concept\ncronos56@yahoo.com\n");

        ip = (struct iphdr *)(((char *)packet)+IF_LEN);
        icmp = (struct icmphdr *)(((char *)packet)+(sizeof(struct iphdr)+
                                        IF_LEN));
        memset(&packet, 0, sizeof(packet));

        if(portsrcd == 0) portsrcd=1024;
        if(portsrcf == 0) portsrcf=3000;
        printf("Recherche port source:\n");
        for(j=portsrcd;j<=portsrcf;j++){
        send_icmp(localip, "1234567");
    regpb = 0;
    regpb2 = 0;
    while (recv(iflink, &packet, sizeof(packet), 0)) {
	int set = 0;
	if (regpb > 50) {
	    int set2 = 0;
	    if (regpb2 > 10) {
		printf("Pb de reception ping reply\n");
		break;
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
	if (regpb > 50) {
	    int set2 = 0;
	    if (regpb2 > 10) {
		printf("Pb de reception ping reply\n");
		break;
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
	   send_tcp(sock,j,0,0);
    }
    if (time > 0) {
	sleep(time);
    }
    send_icmp(localip, "1234567");
    regpb = 0;
    regpb2 = 0;
    while (recv(iflink, &packet, sizeof(packet), 0)) {
	int set = 0;
	if (regpb > 100) {
	    int set2 = 0;
	    if (regpb2 > 10) {
		printf("Pb de reception ping reply\n");
		break;
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
		if(ok==1){
			ok=0;
			printf("NON, desol�\nContinu:");
		}
	    printf(".", ntohs(port));
	} else {
	 int vrfy=0;
		if(ok==1){
			printf("Ok!!!!! port src == %d\n",j);
			exit(0);
		}
	    ok=1;
	    printf("\nLe port Source est peut etre: %d Verification...", j);
	    vrfy=j-1;
	    j=vrfy;
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
	if(ok==1){
			ok=0;
			printf("NON, desol�\nContinu:");
		}
	    printf(".", ntohs(port));
	} else {
		int vrfy=0;
		if(ok==1){
			printf("Ok!!!!! port src == %d\n",j);
			exit(0);
		}
	    ok=1;
	    printf("\nLe port Source est peut etre: %d Verification...", j);
	    vrfy=j-1;
	    j=vrfy;
	
	}
    }
        }
        iflink=tap(IF_NAME, 0);
        exit(0);
}
