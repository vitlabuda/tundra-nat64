
PREFIX ?= /usr/local

WARN_FLAGS = -Wall -Wextra -Wpedantic $(WARN_FLAGS_gcc) $(WARN_FLAGS_clang)
OPT_FLAGS = -O3 -flto
ALLFLAGS = -pthread $(ALLFLAGS_gcc)
CFLAGS += -MD -MP -std=c11 $(WARN_FLAGS) $(OPT_FLAGS) $(ALLFLAGS) $(CFLAGS_gcc)
LDFLAGS += $(OPT_FLAGS) $(LDFLAGS_gcc) $(ALLFLAGS)

SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:.c=.o)

CC_IS_CLANG := $(findstring clang,$(shell LC_ALL=C $(CC) --version 2>/dev/null | head -n 1))

ifndef CC_IS_CLANG
WARN_FLAGS_gcc += -fanalyzer

# Compiler flags taken from https://airbus-seclab.github.io/c-compiler-security/
WARN_FLAGS_gcc += -Wformat=2 -Wformat-overflow=2 -Wformat-truncation=2 -Wformat-security -Wnull-dereference -Wstack-protector -Wtrampolines -Walloca -Wvla -Warray-bounds=2 -Wimplicit-fallthrough=3 -Wtraditional-conversion -Wshift-overflow=2 -Wcast-qual -Wstringop-overflow=4 -Wconversion -Warith-conversion -Wlogical-op -Wduplicated-cond -Wduplicated-branches -Wformat-signedness -Wshadow -Wstrict-overflow=4 -Wundef -Wstrict-prototypes -Wswitch-default -Wswitch-enum -Wstack-usage=1000000 -Wcast-align=strict
CFLAGS_gcc += -D_FORTIFY_SOURCE=3
ALLFLAGS_gcc += -fstack-protector-strong -fstack-clash-protection -fPIE -fsanitize=bounds -fsanitize-undefined-trap-on-error
LDFLAGS_gcc += -Wl,-z,relro -Wl,-z,now -Wl,-z,noexecstack -Wl,-z,separate-code
else
WARN_FLAGS_clang = -Weverything
endif

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
