CC=gcc
CFLAGS=-c -Wall 
LDFLAGS=-L/lib -liw -lpcap
PROGS=chswi

all:  chswio
	gcc -g -o chswi chswi.o $(LDFLAGS)

chswio: 
	$(CC) $(CFLAGS) $(LDFLAGS) chswi.c
	
clean:
	rm -rf *.o $(PROGS)
