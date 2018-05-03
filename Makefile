BLAB := $(shell command -v blab 2> /dev/null)
RADAMSA := $(shell command -v radamsa 2> /dev/null)
CFLAGS = -W -g -O3
LIBS = -lpcre -lcrypto -lssl -lpthread
TARGET = fuzzotron

SRCS = callback.c fuzzotron.c generator.c monitor.c sender.c trace.c
OBJS = $(SRCS:.c=.o)

.PHONY: all
all: $(TARGET)
ifndef RADAMSA
	$(error radamsa is not available. Download from https://github.com/aoh/radamsa)
endif

ifndef BLAB
	$(info Blab is not available, attempting to use blab mode will fail.)
endif

$(TARGET): $(OBJS)
	$(CC) ${LDFLAGS} -o $@ $^ ${LIBS}

$(SRCS:.c):%.c
	$(CC) $(CFLAGS) -MM $<

.PHONY: clean
clean:
	rm -f ${OBJS} ${TARGET}
