#include "main.h"

int trace(){
        char cmd[512];
        snprintf(cmd,sizeof(cmd)-1,"ltrace -f -i -o %s %s\n",fichierl,progv);
        fork();
        system(cmd);
}

int findbug(){
        // GANG a toi de la codé en shell ou autre... :)
        char cmd[512];
        snprintf(cmd,sizeof(cmd)-1,"findbug.sh %s\n",fichierl);
        system(cmd);
}

int fdwrite(int dafd,char *fmt,...)
{
  char mybuffer[100000];
  va_list va;

  va_start(va,fmt);
  vsnprintf(mybuffer,100000,fmt,va);
  write(dafd,mybuffer,strlen(mybuffer));
  va_end(va);
  return(1);
}

int hosttoip(char *hostname,struct in_addr *addr)
{
  struct hostent *res;

  res=gethostbyname(hostname);
  if (res==NULL)
    return(0);
  memcpy((char *)addr,res->h_addr,res->h_length);
  return(1);
}

int connectx(struct in_addr addr,unsigned short port)
{
  struct sockaddr_in serv;
  int thesock,flags;

  thesock=socket(AF_INET,SOCK_STREAM,IPPROTO_TCP);
  bzero(&serv,sizeof(serv));
  memcpy(&serv.sin_addr,&addr,sizeof(struct in_addr));
  serv.sin_port=htons(port);
  serv.sin_family=AF_INET;
  if (connect(thesock,(struct sockaddr *)&serv,sizeof(serv)) < 0)
    return(-1);
  else
    return(thesock);
}

int overflow(char *arg1, char *arg2){
        int loop=0,ok=0;
        int stop;
        stop=atoi(arg1);
        strncpy(bugc,arg2,sizeof(bugc)-1);
        for(loop=0;loop<stop;loop++) {
                ok=0;
                ok=strlen(bugc);
                strncat(bugc,arg2,(sizeof(bugc)-ok)-1);
        }
}

int fmt(char *arg1, char *arg2){
        int loop=0,ok=0;
        int stop;
        stop=atoi(arg1);
        strncpy(bugc,arg2,sizeof(bugc)-1);
        for(loop=0;loop<stop;loop++) {
                ok=0;
                ok=strlen(bugc);
                strncat(bugc,arg2,(sizeof(bugc)-ok)-1);
        }
}

int escape(char *arg1, char *arg2){
        int loop=0,ok=0;
        int stop;
        stop=atoi(arg1);
        strncpy(bugc,arg2,sizeof(bugc)-1);
        for(loop=0;loop<stop;loop++) {
                ok=0;
                ok=strlen(bugc);
                strncat(bugc,arg2,(sizeof(bugc)-ok)-1);
        }
}

int autre(char *arg1, char *arg2){
        int loop=0,ok=0;
        int stop;
        stop=atoi(arg1);
        strncpy(bugc,arg2,sizeof(bugc)-1);
        for(loop=0;loop<stop;loop++) {
                ok=0;
                ok=strlen(bugc);
                strncat(bugc,arg2,(sizeof(bugc)-ok)-1);
        }
}



