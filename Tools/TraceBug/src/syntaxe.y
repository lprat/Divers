%{
	#include "main.h"
	int i;
%}

%token OPTION FICHIERLOG PROG PV EGAL TEXTE CHAP DP FP DPA FPA EGAL2 VCHIFFRE
%token OVERFLOW FMT ESCAPE OTHER GM REMOTE LOCAL CONNECTION ENVOIE LANCE CHAR
%token CLOSE CIP IP CPORT PORT PROTOCOL OPT TCP EGAL RECONNECT UDP AUTOTRACE CONNECTOK

%start loop
%%

loop:
		| loop debut
		;
debut: 		 REMOTE DP remotemode FP
		{
                                        printf("FIN!!!\n");
                                }
		|  LOCAL DP localmode FP
                                {
                                        printf("FIN!!!\n");
                                }
                                ;
remotemode:
		| remotemode remote
		;
remote:             PROG EGAL GM valeur GM PV
                                {
                                        strncpy(progv,nvaleur,sizeof(progv)-1);
                                        bzero(temp,sizeof(temp));
                                        bzero(nvaleur,sizeof(nvaleur));
                                }
                                | FICHIERLOG EGAL GM valeur GM PV
                                {
                                        strncpy(fichierl,nvaleur,sizeof(fichierl)-1);
                                        bzero(temp,sizeof(temp));
                                        bzero(nvaleur,sizeof(nvaleur));
                                }
                                | OPTION EGAL possib PV
                                { // OK, TRAVAUX
                                }
                                | CONNECTION DP connect FP
                                { // OK
                                }
                                | ENVOIE DP modeenvoie FP
                                { //OK
                                }
                                ;
localmode:
		| localmode local
		;
local:                  PROG EGAL GM valeur GM PV
                                {
                                        strncpy(progv,nvaleur,sizeof(progv)-1);
                                        bzero(temp,sizeof(temp));
                                        bzero(nvaleur,sizeof(nvaleur));
                                }
                                | FICHIERLOG EGAL GM valeur GM PV
                                {
                                        strncpy(fichierl,nvaleur,sizeof(fichierl)-1);
                                        bzero(temp,sizeof(temp));
                                        bzero(nvaleur,sizeof(nvaleur));
                                }
                                | OPTION EGAL possib PV
                                { // OK, TRAVAUX
                                }
                                | LANCE DP lanceok FP
                                { // OK
                                }
                                ;
lanceok:     lanceok planceok
                |
                ;
planceok:                     OPT EGAL GM chaine GM PV
                                {
                                        trace();  // trace prog
                                        snprintf(nlance,sizeof(nlance)-1,"%s %s",progv,nlance);
                                        system(nlance); //changer par un execve!!!
                                        bzero(nchaine,sizeof(nchaine));
                                        findbug(); // recherche d'un segfault... ou autre
                                }
                                ;
valeur:         valeur vvaleur
                |
                ;
vvaleur:                TEXTE
                        {
                                i=0;
                                i=strlen(nvaleur);
                               strncat(nvaleur,temp,sizeof(nvaleur)-i-1);
                        }
                        ;
valeur2:         valeur2 vvaleur2
                |
                ;
vvaleur2:                TEXTE
                        {
                                i=0;
                                i=strlen(nvaleur2);
                               strncat(nvaleur2,temp,sizeof(nvaleur2)-i-1);
                        }
                        ;
connect:
                        | connect pconnect
                        ;
pconnect:             IP EGAL GM valeur GM PV
                        {
                                strncpy(ip,nvaleur,sizeof(ip)-1);
                                hosttoip(ip,&ipdest); // gesthostbyname
                                ipdac=1;
                                bzero(temp,sizeof(temp));
                                bzero(nvaleur,sizeof(nvaleur));
                        }
                        | PORT EGAL GM valeur GM PV
                        {
                                strncpy(port,nvaleur,sizeof(port)-1);
                                aport=atoi(port);
                                portdac=1;
                                bzero(temp,sizeof(temp));
                                bzero(nvaleur,sizeof(nvaleur));
                        }
                        | PROTOCOL EGAL protocol PV
                        { //ok
                        }
                        | CONNECTOK PV
                        {
                                if((ipdac==1) && (portdac==1) && ((ptcp==1) || (pudp==1))) {
                                        trace(); // lancement du tracage du prog!
                                        statut=1;
                                        sock=connectx(ipdest,aport);
                                        connectionok=1;
                                        /* pour plus tard si ptcp == 1 alors connecttcp ou si pudp ==1 alors connectudp a la palce de connectx */
                                        printf("Connection sur %s:%d OK!\n",ip,aport);
                                }
                                else{
                                        printf("Votre fichier est mal codé...\nUne demande de connection est faite alors qu'il n'y a pas tous les parametres(ip,port,protocol)\n");
                                        exit(0);
                                }
                        }
                        | CLOSE PV
                        {
                               if(connectionok==1) {
                                        close(sock);
                               }
                               else{
                                        printf("Votre fichier est mal codé...\nUne demande de deconnection est faite alors qu'il n'y a pas eu de connection\n");
                                        exit(0);
                               }
                        }
                        | RECONNECT PV
                        {
                                if(connectionok==1) {
                                        close(sock);
                                        sock=connectx(ipdest,aport);
                                        printf("Reconnection sur %s:%d OK!\n",ip,aport);
                                }
                                else{
                                        printf("Votre fichier est mal codé...\nUne demande de reconnection est faite alors qu'il n'y a pas eu de connection!\n");
                                        exit(0);
                                }
                        }
                        ;
protocol:            TCP
                        {
                                ptcp=1;
                                pudp=0;
                                printf("Mode TCP activé!\n");
                        }
                        | UDP
                        {
                                pudp=1;
                                ptcp=0;
                                printf("Mode encore en travaux!!\n");
                        }
                        ;
possib:              AUTOTRACE
                        {
                                optionv=1;
                        }
                        ;
modeenvoie:
                        | modeenvoie pmodeenvoie
                        ;
pmodeenvoie:     CHAR EGAL GM chaine GM PV
                        {
                                if(connectionok==1){
                                        fdwrite(sock,"%s",nchaine);
                                        bzero(nchaine,sizeof(nchaine));
                                        findbug(); // recherche d'un segfault... ou autre
                                }
                                else{
                                        printf("Votre fichier est mal codé...\nUne demande d'envoie est faite alors qu'il n'y a pas eu de connection\n");
                                }
                        }
                        ;

chaine:         chaine chainev
                |
                ;
chainev:             TEXTE
                        {
                                i=0;
                                i=strlen(nchaine);
                               strncat(nchaine,temp,sizeof(nchaine)-i-1);
                        }
                        | CHAP buge CHAP
                        {
                                i=0;
                                i=strlen(nchaine);
                                strncat(nchaine,bugc,sizeof(nchaine)-i-1);
                                bzero(bugc,sizeof(bugc));
                        }
                        ;
buge:                 OVERFLOW EGAL2 valeur DPA valeur2 FPA
                        {
                                overflow(nvaleur,nvaleur2);
                                bzero(nvaleur,sizeof(nvaleur));
                                bzero(nvaleur2,sizeof(nvaleur2));
                        }
                        | FMT EGAL2 valeur DPA valeur2 FPA
                        {
                                fmt(nvaleur,nvaleur2);
                                bzero(nvaleur,sizeof(nvaleur));
                                bzero(nvaleur2,sizeof(nvaleur2));
                        }
                        | ESCAPE EGAL2 valeur DPA valeur2 FPA
                        {
                                escape(nvaleur,nvaleur2);
                                bzero(nvaleur,sizeof(nvaleur));
                                bzero(nvaleur2,sizeof(nvaleur2));
                        }
                        | OTHER EGAL2 valeur DPA valeur2 FPA
                        {
                                autre(nvaleur,nvaleur2);
                                bzero(nvaleur,sizeof(nvaleur));
                                bzero(nvaleur2,sizeof(nvaleur2));
                        }
                        ;

%%

int yyerror(char *s) {
	printf("%s\n",s);
}

int analyse(char *file) {
	bzero(temp,sizeof(temp));
                bzero(nchaine,sizeof(nchaine));
                lignes=0;
                connectionok=0;
                ipdac=0, portdac=0;
	yyparse();
}
