BLAB := $(shell command -v blab 2> /dev/null)
RADAMSA := $(shell command -v radamsa 2> /dev/null)
CFLAGS = -W -g -O3
LIBS = -lpcre -lssl -lcrypto -lpthread

FUZZOTRON = fuzzotron
REPLAY = replay
FUZZOTRON_SRC = fuzzotron.c callback.c generator.c monitor.c sender.c trace.c
REPLAY_SRC = replay.c callback.c sender.c

FUZZOTRON_OBJ = $(FUZZOTRON_SRC:.c=.o)
REPLAY_OBJ = $(REPLAY_SRC:.c=.o)

.PHONY: all
all: fuzzotron replay
ifndef RADAMSA
	$(error radamsa is not available. Download from https://gitlab.com/akihe/radamsa)
endif

ifndef BLAB
	$(info Blab is not available, attempting to use blab mode will fail. Download from https://gitlab.com/akihe/blab)
endif

$(FUZZOTRON): $(FUZZOTRON_OBJ)
	$(CC) ${LDFLAGS} -o $@ $^ ${LIBS}

$(REPLAY): $(REPLAY_OBJ)
	$(CC) ${LDFLAGS} -o $@ $^ ${LIBS}

$(SRCS:.c):%.c
	$(CC) $(CFLAGS) -MM $<

.PHONY: clean
clean:
	rm -f $(REPLAY_OBJ) $(FUZZOTRON_OBJ) ${FUZZOTRON} ${REPLAY}
