/* main.h  | Trace Bug by Lionel PRAT & Gangstuck */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <sys/time.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netdb.h>
#include "lexyacc.h"

int trace();
int findbug();
int fdwrite(int dafd,char *fmt,...);
int hosttoip(char *hostname,struct in_addr *addr);
int connectx(struct in_addr addr,unsigned short port);
int overflow(char *arg1, char *arg2);
int fmt(char *arg1, char *arg2);
int escape(char *arg1, char *arg2);
int autre(char *arg1, char *arg2);
char ip[256];
char port[80];
struct in_addr ipdest;
