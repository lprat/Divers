rm -f *.o 
rm sniff
cc -c mylib.c
cc -c main.c 
cc -o sniff main.o mylib.o
echo "Compilage OK"
