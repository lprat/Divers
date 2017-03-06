%{

#include "main.h"
#include "syntaxe.tab.h"

%}

%s COMMENTAIRE COMMENTAIRES STRING BUG BUG2 BUG3

ESPACE ([ \t\v\f])
ESPACES ([ \t\v\f]+)

%%

                                int condition;
<COMMENTAIRE>[^*\n]*       /* absorbe tout sauf '*' et '\n' */
<COMMENTAIRE>"*"+[^*/\n]*  /* absorbe les '*' non suivies de '/'s */
<COMMENTAIRE>\n	{
				lignes++;
    			}
<COMMENTAIRE>"*"+"/"       { BEGIN condition; }

<COMMENTAIRES>\n	{
				BEGIN condition;
				lignes++;
    			}
<COMMENTAIRES>.		{}

<BUG>"^"                {
                                        BEGIN(STRING);
                                        return(CHAP);
                                }
<BUG3>"/*"           {
                                        condition = BUG3;
                                        BEGIN(COMMENTAIRE);
                                 }
<BUG3>"//"           {
                                        condition = BUG3;
                                        BEGIN(COMMENTAIRES);
                                 }
<BUG3>")"              {
                                        BEGIN(BUG);
                                        return(FPA);
                                }
<BUG3>.                {
                                        bzero(temp,sizeof(temp));
                                        strncpy(temp,yytext,sizeof(temp)-1);
                                        return(TEXTE);
                                }
<BUG2>"/*"           {
                                        condition = BUG2;
                                        BEGIN(COMMENTAIRE);
                                 }
<BUG2>"//"           {
                                        condition = BUG2;
                                        BEGIN(COMMENTAIRES);
                                 }
<BUG2>"("               {
                                        BEGIN(BUG3);
                                        return(DPA);
                                }
<BUG2>.                 {
                                         bzero(temp,sizeof(temp));
                                        strncpy(temp,yytext,sizeof(temp)-1);
                                        return(TEXTE);
                                }
<BUG>"/*"           {
                                        condition = BUG;
                                        BEGIN(COMMENTAIRE);
                                 }
<BUG>"//"           {
                                        condition = BUG;
                                        BEGIN(COMMENTAIRES);
                                 }
<BUG>"=="              {
                                        BEGIN(BUG2);
                                        return(EGAL2);
                                }
<BUG>"overflow"    {
                                        return(OVERFLOW);
                                }
<BUG>"fmt"            {
                                        return(FMT);
                                }
<BUG>"escape"       {
                                        return(ESCAPE);
                                }
<BUG>"other"         {
                                        return(OTHER); /* ??? :) */
                                }
<STRING>"/*"           {
                                        condition = STRING;
                                        BEGIN(COMMENTAIRE);
                                 }
<STRING>"//"           {
                                        condition = STRING;
                                        BEGIN(COMMENTAIRES);
                                 }
<STRING>"\""           {
                                        BEGIN(INITIAL);
                                        return(GM);
                                 }
<STRING>"^"           {
                                        BEGIN(BUG);
                                        return(CHAP);
                                 }
<STRING>.               {
                                        bzero(temp,sizeof(temp));
                                        strncpy(temp,yytext,sizeof(temp)-1);
                                        return(TEXTE);
                                 }
<STRING>\n             { lignes++; }

"/*"			{
                                                        condition = INITIAL;
                                                        BEGIN(COMMENTAIRE);
    			}


"//"			{
                                                                condition = INITIAL;
                                                                BEGIN(COMMENTAIRES);
    			}
"+"+(""|{ESPACES})+"OPTION"	{
				        return(OPTION);
			                }
"+"+(""|{ESPACES})+"FICHIERLOG"	{
                                                                        return(FICHIERLOG);
			                }
"+"+(""|{ESPACES})+"PROG"	                {
                                                                        return(PROG);
			                }

"\""                            { //SAUTE mode string
                                        BEGIN(STRING);
                                        return(GM);
                                 }
[\n\r]			{ lignes++; }
{ESPACE}                 {}

"REMOTE"	                {
                                                        printf("REMOTE MODE ok\n");
                                                        return(REMOTE);
                                                 }
"LOCAL"	                                 {
                                                        printf("REMOTE MODE ok\n");
                                                        return(LOCAL);
                                                 }
"CONNECTION"	                {
                                                        return(CONNECTION);
                                                 }
"CONNECTOK"	                {
                                                        return(CONNECTOK);
                                                 }
"ENVOIE"	                {
                                                        return(ENVOIE);
                                                 }
"LANCE"	                                {
                                                        return(LANCE);
                                                }
"autotrace"               {
                                        /*OPTION....*/
                                        return(AUTOTRACE);
                                }
"char"                      { return(CHAR); }
"RECONNECT"                 { return(RECONNECT); }
"CLOSE"                 { return(CLOSE); }
"IP"                          {
                                        return(IP);
                                }
"PORT"                    {
                                        return(PORT);
                                }
"PROTOCOL"          { return(PROTOCOL); }
"OPT"                       { return(OPT); }
"TCP"                       { return(TCP); }
"UDP"                       { return(UDP); }
"="                            { return(EGAL); }
"{"                             { return(DP); }
"}"                             { return(FP); }
";"                             { return(PV); }
.                                               {
                                                                bzero(temp,sizeof(temp));
                                                                strncpy(temp,yytext,sizeof(temp)-1);
                                                                printf(":%s",temp);
                                                                return(TEXTE);
                                                }

%%
/*
int noreconnu(){
        printf("Warning: caractere non reconnu %s (%s:%d)\n", yytext,yytext[0], lignes);
}

*/
/* VErifier que les parametre indispensable sont bien la!!! ex: fichie.log... */
