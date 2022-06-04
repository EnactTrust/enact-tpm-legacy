CC=gcc
CFLAGS = -Wall
LDLIBS = -lwolftpm -lwolfssl -lm -pthread -lcurl

#Debug Level 1
#CFLAGS += -g -O0 -DDEBUG_PRINTS
#Debug Level 2
#CFLAGS += -g -O0 -DDEBUG_VERBOSE
#Debug Level 3
#CFLAGS += -g -O0 -DDEBUG_PRINTS -DDEBUG_VERBOSE

.PHONY: all
all:
	$(CC) $(CFLAGS) -o enact agent.c tpm.c misc.c $(LDFLAGS) $(LDLIBS)

.PHONY: clean
clean:
	rm enact
