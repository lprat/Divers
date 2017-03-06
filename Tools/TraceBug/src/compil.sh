bison -d syntaxe.y
flex lex.l
cc -c lex.yy.c -o lex.o
cc -c syntaxe.tab.c -o syntaxe.o
cc -c fonction.c -o fonction.o
cc -c main.c -o main.o
cc -o trace main.o fonction.o lex.o syntaxe.o -lm -ll