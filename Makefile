
PREFIX ?= /usr/local

WARN_FLAGS = -Wall -Wextra -Wpedantic
OPT_FLAGS = -O3 -flto
ALLFLAGS = -pthread # passed to both compiling/linking stages
CFLAGS += -MD -MP -std=c11 $(WARN_FLAGS) $(OPT_FLAGS) $(ALLFLAGS)
LDFLAGS += $(OPT_FLAGS) $(ALLFLAGS)

SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.o)

all: tundra-nat64
.PHONY: all clean install

tundra-nat64: $(OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

%.o: %.c
	$(CC) $(CFLAGS) -o $@ -c $<

HELP2MAN_FLAGS = \
 --no-info --no-discard-stderr \
 --name='a multithreaded IPv6 to IPv4 packet translator' \
 --section=8

tundra-nat64.8: tundra-nat64
	PATH=$$PWD:$$PATH help2man $(HELP2MAN_FLAGS) $< >$@ || rm $@

clean:
	-rm src/*.o
	-rm src/*.d
	-rm *.8

install: tundra-nat64.8
	install -D -m755 tundra-nat64 -t $(DESTDIR)$(PREFIX)/sbin/
	install -D -m644 tundra-nat64.8 -t $(DESTDIR)$(PREFIX)/share/man/man8/

.SUFFIXES:

-include $(OBJS:.o=.d)
