

//code by lionel prat noel @2009
//DHCP nat secure v.3 2010
// sans liste chainée
#include <stdio.h>
#include <unistd.h>
#include <stdarg.h>
#include <sys/time.h>
#include <sys/types.h>
#include <string.h>
#include <regex.h>
#include <time.h>
#include <syslog.h>
 
char	*logprog="DHCP-NAT-SECURE";
 
struct element
{
    char ip[16];
    unsigned long int date;
    unsigned long int heure;
    int valid;
};
 
struct element elm[256];
 
/************init tableau***************/
void init_tab(){
	int i=0;
	for(i=0;i<256;i++){
		elm[i].date=0;
		elm[i].heure=0;
		elm[i].valid=0;
		sprintf(elm[i].ip,"192.168.72.%d\0",i);
	}
}
 
/*******************scan nmap IP ****************/
int scan_ip(char *ip){
	//verifier l'integrite de la machine
	//http://nmap.org/book/nse-scripts-list.html
	//virus conficker + promiscous
	printf("Entre dans scan ip\n");
	int r_p=0, r_v=0;
	char virus[512];
	char promis[512];
	snprintf(virus,sizeof(virus)-1,"/usr/bin/nmap -p 445 -d --script smb-check-vulns --script-args safe=1 %s | /bin/grep -i \"Likely INFECTED\"",ip);
	snprintf(promis,sizeof(promis)-1,"/usr/bin/nmap -sS -p1 -n --script=sniffer-detect.nse %s | /bin/grep -iE \"Likely|libpcap\"",ip);
	r_v=system(virus);
	r_p=system(promis);
	if(r_p==0){
		// send alert to admin
	}
	if(r_v==0){
		// send alert to admin
	}
	if(r_p !=0 && r_v !=0) return 1;
	if(r_v ==0) return 2;
	return 0; // r_p==0
}
 
/*****************add et DEL NAT **************************/
void add_nat(char *ip){
	//regarde si adresse existe
	char cmd[512];
	int ret=0;
	//ajoute iptables
	snprintf(cmd,sizeof(cmd)-1,"/sbin/iptables -t nat -I POSTROUTING 1 -o eth0 -s %s/255.255.255.255 -j MASQUERADE",ip);
	ret=system(cmd);
	if(ret!=0)syslog(LOG_ALERT,"PB CMD NAT -> %s ---- ret=%d",cmd,ret);
	printf("cmd=%s  ---- ret=%d (==0==good)\n",cmd,ret);
}
 
void del_nat(char *ip){
	//regarde si adresse existe
	char cmd[512];
	int ret=0;
	//enleve iptables
	snprintf(cmd,sizeof(cmd)-1,"/sbin/iptables -t nat -D POSTROUTING -o eth0 -s %s/255.255.255.255 -j MASQUERADE",ip);
	ret=system(cmd);
	if(ret!=0)syslog(LOG_ALERT,"PB CMD NAT -> %s ---- ret=%d",cmd,ret);
        printf("cmd=%s  ---- ret=%d (==0==good)\n",cmd,ret);
}
/******************* ip to ipfin ********************/
int iptofin(char *ip){
	int bip=0;
	int fin=0;
	int i=0;
	int j=0;
	char finip[3];
	fin=strlen(ip);
	printf("ip=%s...",ip);
	for(i=11;i<=fin;i++) {
		if(j<3)
			finip[j]=ip[i];
		j++;
	}
	printf("finip=%s...",finip);
	bip=atoi(finip);
	printf("bipip=%d\n",bip);
	return bip;
}
 
/******************** MAJ h.d/ Valid / supprime  ************************/
 
int lister(char *ip, int etat, char *mac)
{
	int bip=0,rslt=0;
    /*Quelle heure!*/
	time_t timestamp;
	struct tm * t;
	timestamp = time(NULL);
	t = localtime(&timestamp);
 
    /* char -> int verif >0) */
	bip=iptofin(ip);
	if(bip==0) return 0;
	printf("Entre dans add/maj/suppr: etat:%d - %s -> %d  ...",etat,ip,bip);
    /* quelle etat 0=valider, si deja valide scan-maj*/
	if(etat==0){
		if(elm[bip].valid==1){
			//scan + maj
			printf("Scan pour MAJ...");
			rslt=scan_ip(ip);
			if(rslt==1){
				//maj	
				printf("OK\n",ip);
				elm[bip].date=t->tm_mday+ ((t->tm_mon+1)*100)+ ((1900 + t->tm_year)*10000);
   				elm[bip].heure=(t->tm_hour*10000) + (t->tm_min*100) + t->tm_sec;
				return 1;
			} else {
				//suppr ->virus
				elm[bip].valid=0;
				elm[bip].date=0;
				elm[bip].heure=0;
				del_nat(ip);
				if(rslt==2){
					syslog(LOG_ALERT, "Utilisateur %s/%s...VIRUS CONFICKER ALERTE", ip, mac);
					printf("%d/%d/%d %dh%d:Utilisateur %s/%s...VIRUS CONFICKER ALERTE\n",t->tm_mday, ((t->tm_mon+1)), ((1900 + t->tm_year)), (t->tm_hour), (t->tm_min),ip,mac);
				} else {
					syslog(LOG_ALERT, "Utilisateur %s/%s...PROMISCOUS/SNIFF ALERTE", ip, mac);
					printf("%d/%d/%d %dh%d:Utilisateur %s/%s...PROMISCOUS/SNIFF ALERTE\n",t->tm_mday, ((t->tm_mon+1)), ((1900 + t->tm_year)), (t->tm_hour), (t->tm_min),ip,mac);
				}
				return 0;
			}
		}
		else {
			//scan + valid
			printf("Scan pour ADD...");
			rslt=scan_ip(ip);
			if(rslt==1){
				//add
				printf("Ok\n");
				elm[bip].date=t->tm_mday+ ((t->tm_mon+1)*100)+ ((1900 + t->tm_year)*10000);
   				elm[bip].heure=(t->tm_hour*10000) + (t->tm_min*100) + t->tm_sec;
				elm[bip].valid=1;
				add_nat(ip);
				return 1;
			} else {
				//virus
				if(rslt==2){
					syslog(LOG_ALERT, "Utilisateur %s/%s...VIRUS CONFICKER ALERTE", ip, mac);
					printf("%d/%d/%d %dh%d:Utilisateur %s/%s...VIRUS CONFICKER ALERTE\n",t->tm_mday, ((t->tm_mon+1)), ((1900 + t->tm_year)), (t->tm_hour), (t->tm_min),ip,mac);
				} else {
					syslog(LOG_ALERT, "Utilisateur %s/%s...PROMISCOUS/SNIFF ALERTE", ip, mac);
					printf("%d/%d/%d %dh%d:Utilisateur %s/%s...PROMISCOUS/SNIFF ALERTE\n",t->tm_mday, (t->tm_mon+1), ((1900 + t->tm_year)), (t->tm_hour), (t->tm_min),ip,mac);
				}
				return 0;
			}
		}
	}	
    /* quelle etat 0=supprime, si deja non valide rien*/
 	else {
		if(elm[bip].valid==1){
			printf("Supression.\n");
			elm[bip].valid=0;
			elm[bip].date=0;
			elm[bip].heure=0;
			del_nat(ip);
			return 1;
		} else {printf("Deja non valide.\n"); return 0;}
	}
}
 
/***********supression ip date************/
void dateverif()
{	
	int i=0;
    /* quelle heure */
	time_t timestamp;
	struct tm * t;
	int rego=0;
	unsigned long int date;
	unsigned long int heure;
	timestamp = time(NULL);
	t = localtime(&timestamp);
	date=t->tm_mday+ ((t->tm_mon+1)*100)+ ((1900 + t->tm_year)*10000);
	if(t->tm_hour!=0){
		heure=((t->tm_hour-1)*10000) + ((t->tm_min)*100) + t->tm_sec;
	} else heure=((t->tm_hour)*10000) + (t->tm_min*100) + t->tm_sec;
 
 	for(i=1;i<256;i++)
    	{
		if(elm[i].valid==1){
			if(date > elm[i].date || heure > elm[i].heure)
			{
				printf("Supression du au temps de %s\n",elm[i].ip);
				del_nat(elm[i].ip);
				elm[i].date=0;
				elm[i].heure=0;
				elm[i].valid=0;
			}
		}
	}
}
/*****************main*************************************/
int main(int argc, char **argv)
{
    int n;
    FILE *f_in;
    char ligne[64];
    char recvbuf[1024];
    fd_set rset;
    init_tab();
    printf("Lancement securite DHCP-NAT\n");
    openlog(logprog, LOG_CONS|LOG_PID, LOG_AUTHPRIV);
    /************************INIT***************************/
    printf("Init lease...");
    system("/bin/grep -E \"^lease|binding state active|}\" /var/lib/dhcpd/dhcpd.leases | /bin/awk '{printf \"%s\", $0; if ( $0 ~ \"}\" ) printf \"\\n\"}' | /bin/grep active | /bin/awk '{print $2}' > /tmp/hash_lease");
	//scan
	//add iptables & registre
	if ((f_in = fopen("/tmp/hash_lease","r")) == NULL)
   	{
		syslog(LOG_ALERT, "Impossible de lire le fichier /tmp/hash_lease...STOP proc");
      		fprintf(stderr, "\nErreur: Impossible de lire le fichier\n");
      		exit (-1);
	}
	while (fgets(ligne,sizeof(ligne)-1,f_in) != NULL){
		ligne[strlen(ligne)-1]='\0';
		//printf("%s\n",ligne);
		printf("INIT IP dhcpack: %s\n",ligne);
		lister(ligne,0,"00:00:00:00:00:00");
	}
	fclose(f_in);
	system("/bin/rm -f /tmp/hash_lease");
 
    /*************************** Scrut LOG **********************/
    while (1)
	{
	  FD_ZERO(&rset);
	  FD_SET(STDIN_FILENO,&rset);
	  //select(STDIN_FILENO,&rset,NULL,NULL,NULL);
	  if (FD_ISSET(STDIN_FILENO,&rset))
	  {
		n=read(STDIN_FILENO,recvbuf,1024);
		if (n>0)
		{
			recvbuf[n]=0;
			if(strstr(recvbuf,"DHCPACK")!=0){ //type == 1
				dateverif();
				printf("DHCPACK= %s\n",recvbuf);
				int err,err2;
				regex_t preg;
				regex_t preg2;
				//const char *str_regex = "([0-9]{1,3}\\.){3}[0-9]{1,3}";
					const char *str_regex = "(192\\.168\\.72\\.)[0-9]{1,3}";
					const char *str_regex2 = "((([0-9a-f]){2,2}(:)){5,5})([0-9a-f]){2,2}";
				/* (1) */
				err = regcomp (&preg, str_regex, REG_EXTENDED);
				err2 = regcomp (&preg2, str_regex2, REG_EXTENDED);
				if (err == 0)
				{
					int match;
					size_t nmatch = 0;
					regmatch_t *pmatch = NULL;
 
					nmatch = preg.re_nsub;
					pmatch = malloc (sizeof (*pmatch) * nmatch);
					if (pmatch)
					{
					/* (2) */
						match = regexec (&preg, recvbuf, nmatch, pmatch, 0);
					/* (3) */
						regfree (&preg);
					/* (4) */
						if (match == 0)
						{
							char *site2 = NULL;
							char *site = NULL;
							int macok=0;
							int start = pmatch[0].rm_so;
							int end = pmatch[0].rm_eo;
							if (err2 == 0)
							{
								int match2;
								size_t nmatch2 = 0;
								regmatch_t *pmatch2 = NULL;
 
								nmatch2 = preg2.re_nsub;
								pmatch2 = malloc (sizeof (*pmatch2) * nmatch2);
								if (pmatch2)
								{
								/* (2) */
									match2 = regexec (&preg2, recvbuf, nmatch2, pmatch2, 0);
								/* (3) */
									regfree (&preg);
								/* (4) */
									if (match2 == 0)
									{
										int start2 = pmatch2[0].rm_so;
										int end2 = pmatch2[0].rm_eo;
										size_t size2 = end2 - start2;
										site2 = malloc (sizeof (*site2) * (size2 + 1));
										if (site2){
											strncpy (site2, &recvbuf[start2], size2);
											site2[size2] = '\0';
											macok=1;
										}
									}
								}
							}
							size_t size = end - start;
							site = malloc (sizeof (*site) * (size + 1));
							if (site)
							{
								strncpy (site, &recvbuf[start], size);
								site[size] = '\0';
								printf ("Adresse ip trouvé: %s recherche...", site);
								lister(site,0,site2);
								free(site);
								if(macok==1)free(site2);
							}
						}
					/* (5) */
						else if (match == REG_NOMATCH)
						{
							printf ("%s n\'est pas une adresse IP valide\n", recvbuf);
						}
					/* (6) */
						else
						{
							char *text;
							size_t size;
 
						/* (7) */
							size = regerror (err, &preg, NULL, 0);
							text = malloc (sizeof (*text) * size);
							if (text)
							{
						/* (8) */
								regerror (err, &preg, text, size);
								fprintf (stderr, "%s\n", text);
								free (text);
							}
							else
							{
								syslog(LOG_ALERT, "Memoire insuffisante...STOP proc");
								fprintf (stderr, "Memoire insuffisante\n");
								return(0);
							}
						}
					}
					else
					{
						syslog(LOG_ALERT, "Memoire insuffisante...STOP proc");
						fprintf (stderr, "Memoire insuffisante\n");
						return(0);
					}
				}
			}
			if(strstr(recvbuf,"DHCPRELEASE")!=0){ //type == 2
				printf("DHCPRELEASE= %s\n",recvbuf);
				int err;
				regex_t preg;
				//const char *str_regex = "([0-9]{1,3}\\.){3}[0-9]{1,3}";
				const char *str_regex = "(192\\.168\\.72\\.)[0-9]{1,3}";
				/* (1) */
				err = regcomp (&preg, str_regex, REG_EXTENDED);
				if (err == 0)
				{
					int match;
					size_t nmatch = 0;
					regmatch_t *pmatch = NULL;
 
					nmatch = preg.re_nsub;
					pmatch = malloc (sizeof (*pmatch) * nmatch);
					if (pmatch)
					{
						/* (2) */
						match = regexec (&preg, recvbuf, nmatch, pmatch, 0);
						/* (3) */
						regfree (&preg);
						/* (4) */
						if (match == 0)
						{
							char *site = NULL;
							int start = pmatch[0].rm_so;
							int end = pmatch[0].rm_eo;
							size_t size = end - start;
							site = malloc (sizeof (*site) * (size + 1));
							if (site)
							{
								strncpy (site, &recvbuf[start], size);
								site[size] = '\0';
								printf ("Adresse ip trouvé: %s recherche...", site);
								lister(site,1,"00:00:00:00:00:00");
								free (site);
							}
						}
						/* (5) */
						else if (match == REG_NOMATCH)
						{
							printf ("%s n\'est pas une adresse IP valide\n", recvbuf);
						}
						/* (6) */
						else
						{
							char *text;
							size_t size;
 
							/* (7) */
							size = regerror (err, &preg, NULL, 0);
							text = malloc (sizeof (*text) * size);
							if (text)
							{
								/* (8) */
								regerror (err, &preg, text, size);
								fprintf (stderr, "%s\n", text);
								free (text);
							}
							else
							{
								syslog(LOG_ALERT, "Memoire insuffisante...STOP proc");
								fprintf (stderr, "Memoire insuffisante\n");
								return(0);
							}
						}
					}
					else
					{
						syslog(LOG_ALERT, "Memoire insuffisante...STOP proc");
						fprintf (stderr, "Memoire insuffisante\n");
						return(0);
					}
				}
			}
			if(strstr(recvbuf,"DHCPNAK")!=0){ //type == 2
				printf("DHCPNAK= %s\n",recvbuf);
				int err;
				regex_t preg;
				//const char *str_regex = "([0-9]{1,3}\\.){3}[0-9]{1,3}";
				const char *str_regex = "(192\\.168\\.72\\.)[0-9]{1,3}";
				/* (1) */
				err = regcomp (&preg, str_regex, REG_EXTENDED);
				if (err == 0)
				{
					int match;
					size_t nmatch = 0;
					regmatch_t *pmatch = NULL;
 
					nmatch = preg.re_nsub;
					pmatch = malloc (sizeof (*pmatch) * nmatch);
					if (pmatch)
					{
						/* (2) */
						match = regexec (&preg, recvbuf, nmatch, pmatch, 0);
						/* (3) */
						regfree (&preg);
						/* (4) */
						if (match == 0)
						{
							char *site = NULL;
							int start = pmatch[0].rm_so;
							int end = pmatch[0].rm_eo;
							size_t size = end - start;
							site = malloc (sizeof (*site) * (size + 1));
							if (site)
							{
								strncpy (site, &recvbuf[start], size);
								site[size] = '\0';
								printf ("Adresse ip trouvé: %s recherche...", site);
								lister(site,1,"00:00:00:00:00:00");
								free (site);
							}
						}
						/* (5) */
						else if (match == REG_NOMATCH)
						{
							printf ("%s n\'est pas une adresse IP valide\n", recvbuf);
						}
						/* (6) */
						else
						{
							char *text;
							size_t size;
 
							/* (7) */
							size = regerror (err, &preg, NULL, 0);
							text = malloc (sizeof (*text) * size);
							if (text)
							{
								/* (8) */
								regerror (err, &preg, text, size);
								fprintf (stderr, "%s\n", text);
								free (text);
							}
							else
							{
								syslog(LOG_ALERT, "Memoire insuffisante...STOP proc");
								fprintf (stderr, "Memoire insuffisante\n");
								return(0);
							}
						}
					}
					else
					{
						syslog(LOG_ALERT, "Memoire insuffisante...STOP proc");
						fprintf (stderr, "Memoire insuffisante\n");
						return(0);
					}
				}
			}
 
		}
	  }
	}
	closelog();
    return 0;
}


