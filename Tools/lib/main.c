#include "mylib.h"

int main(){
int sock;
printf("Sniff ETH0\n Truff & Lionel PRAT & Descript\n");
sock=init_sniff("eth0");
get_packet(sock);
}
