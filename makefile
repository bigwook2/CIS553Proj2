CFLAGS = -Wall -g -lpcap
all: packetparse.o
	cc $(CFLAGS) -o packetparse packetparse.o

packetparse.o: packetparse.h packetparse.c
	cc -c -g  packetparse.c
mail: mail_inhale.c
	cc $(CFLAGS) mail_inhale.c -o mail
	
clean:
	rm packetparse *.o mail
