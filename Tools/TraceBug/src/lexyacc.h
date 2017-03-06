/* Traceur de Bug by Lionel PRAT & Gangstuck */
/* lexyacc.h */


char temp[256];
char nvaleur[8192];
char nvaleur2[8192];
char nchaine[100000];
char nlance[100000];
char bugc[10000];
char progv[1024];
char fichierl[1024];
int ipdac,portdac;
int aport;
int sock;
int ptcp, pudp;
int connectionok;
int lignes;
int optionv;
int statut;

/*
optionv:
        - AUTOTRACE == 1
        - XXX == 2
        - XXX == 4
        - XXX == 8
        - ...
        SI on veus option 2 et 1 alors optionv==3 ...
*/

