BLAB := $(shell command -v blab 2> /dev/null)
RADAMSA := $(shell command -v radamsa 2> /dev/null)

CFLAGS = -Wall -g

all:
ifndef RADAMSA
    $(error radamsa is not available. Download from https://github.com/aoh/radamsa)
endif

ifndef BLAB
	$(info Blab is not available, attempting to use blab mode will fail.)
endif

	$(CC) $(CFLAGS) fuzzotron.c generator.c monitor.c sender.c trace.c -o fuzzotron -lpcre -lcrypto -lssl -lpthread