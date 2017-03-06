#include "main.h"

int main(int argc, char **argv){
        char cmd[256];
        printf("Trace Bug par Lionel PRAT & Gangstuck\n");
        if(argc=! 2){
                printf("Usage: %s <fichier.tb>\n",argv[0]);
                exit(0) ;
        }
        statut=0;
        analyse(argv[2]) ;
        printf("Fin de l'annalyse!! Verifier quand meme les sources de votre codes on ne c'est jamais!\n");
        exit(0);
        system("killall -9 trace");
        snprintf(cmd,sizeof(cmd)-1,"killall -9 %s\n",argv[0]);
        system(cmd);
}
