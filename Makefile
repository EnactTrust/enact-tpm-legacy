CC=gcc
CFLAGS = -Wall -I/usr/local/include
LDFLAGS = -L/usr/local/lib
LDLIBS = -lwolftpm -lwolfssl -lm -pthread -lcurl

#Debug Level 1
#CFLAGS += -g -O0 -DDEBUG_PRINTS
#Debug Level 2
#CFLAGS += -g -O0 -DDEBUG_VERBOSE
#Debug Level 3
#CFLAGS += -g -O0 -DDEBUG_PRINTS -DDEBUG_VERBOSE

.PHONY: all
all:
	$(CC) $(CFLAGS) -o agent agent.c tpm.c $(LDFLAGS) $(LDLIBS)

.PHONY: clean
clean:
	rm agent
