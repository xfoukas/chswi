CC=gcc
CFLAGS=-c -Wall 
LDFLAGS=-L/lib -liw -lpcap
PROGS=chswi
XCFLAGS = $(A_SUPPORT_FLAG)

#BUILD_PROTOA_SUPPORT = y

ifdef BUILD_PROTOA_SUPPORT
  A_SUPPORT_FLAG = -DSUPPORT_802_11_A
endif 

all:  chswio
	gcc -g -o chswi  chswi.o $(LDFLAGS)

chswio: 
	$(CC) $(CFLAGS) $(XCFLAGS) $(LDFLAGS) chswi.c
	
clean:
	rm -rf *.o $(PROGS)
