EXECUTABLE=chswi
SOURCES=chswi.c
CFLAGS = -c -Wall 
LDFLAGS = -s  -liw -lpcap
LIBS = -liw -lpcap
XCFLAGS = $(A_SUPPORT_FLAG)

OBJECTS=chswi.o

#BUILD_PROTOA_SUPPORT = y

ifdef BUILD_PROTOA_SUPPORT
  A_SUPPORT_FLAG = -DSUPPORT_802_11_A
endif 

all:  $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE) :  chswi.h chswi.o
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

.c.o:
	$(CC) $(XCFLAGS) $(CFLAGS) $< -o $@

clean:
	rm -rf *.o $(EXECUTABLE)
