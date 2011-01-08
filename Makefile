EXECUTABLE=chswi
SOURCES=chswi.c
#CFLAGS = -c -Wall 
LDFLAGS += -s 
LIBS = -liw -lpcap
XCFLAGS = $(A_SUPPORT_FLAG)

OBJECTS=chswi.o

#BUILD_PROTOA_SUPPORT = y

ifdef BUILD_PROTOA_SUPPORT
  A_SUPPORT_FLAG = -DSUPPORT_802_11_A
endif 

all:  $(SOURCES) $(EXECUTABLE)

$(EXECUTABLE) :  $(OBJECTS)
	$(CC) $(LDFLAGS) $(OBJECTS) $(LIBS) -o $@

.c.o:
	$(CC) $(XCFLAGS) $(CFLAGS) -c $< -o $@

clean:
	rm -rf *.o $(EXECUTABLE)
