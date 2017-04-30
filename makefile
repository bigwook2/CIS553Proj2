CFLAGS = -Wall -g -lpcap
all: packetparse.o
	gcc $(CFLAGS) packetparse.o -o packetparse 

packetparse.o: packetparse.h packetparse.c
	gcc -c packetparse.c
mail: mail_inhale.c
	cc $(CFLAGS) mail_inhale.c -o mail
	
clean:
	rm *.o 
