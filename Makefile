# Makefile for the modernized IRC bot
# Compiler: prefer gcc, fall back to clang, then cc, if gcc is not installed.
# An explicit `make CC=<compiler>` (command line / env) always wins.
ifeq ($(origin CC),default)
  CC := $(shell command -v gcc >/dev/null 2>&1 && echo gcc || \
                { command -v clang >/dev/null 2>&1 && echo clang; } || echo cc)
endif
$(info [build] using CC=$(CC))

# Set to 0 to disable curl support (update feature will be unavailable)
USE_CURL ?= 1

# Detect OS so feature-test macros and library paths stay correct per-platform.
UNAME_S := $(shell uname -s)

#FOR DEV
#CFLAGS = -Wall -Wextra -std=c11 -g
#FOR RELEASE
CFLAGS = -Wall -Wextra -Wpedantic -Wshadow -std=c11 -O2

ifeq ($(UNAME_S),Linux)
# glibc + -std=c11 defines __STRICT_ANSI__ and hides POSIX symbols unless we
# explicitly request a POSIX/XSI environment.
CFLAGS += -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700
else
# FreeBSD / other BSD: do NOT define _POSIX_C_SOURCE/_XOPEN_SOURCE — doing so
# disables __BSD_VISIBLE and hides BSD extensions this code relies on
# (flock/LOCK_*, MSG_NOSIGNAL). The default (no feature macros) exposes
# POSIX+BSD. Ports also install third-party headers/libs under /usr/local.
CFLAGS += -I/usr/local/include
LDFLAGS += -L/usr/local/lib
endif

# Add HAVE_CURL flag if curl support is enabled
ifeq ($(USE_CURL),1)
CFLAGS += -DHAVE_CURL
LDFLAGS += -lssl -lcrypto -lcurl
else
LDFLAGS += -lssl -lcrypto
endif

# Source files
SRCS = main.c bot.c config.c channel.c hub_client.c irc_client.c irc_parser.c commands.c utils.c logging.c auth.c bot_comms.c crypto.c

# Object files
OBJS = $(SRCS:.c=.o)

# Executable name
TARGET = ircbot

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)
	@chmod 700 $(TARGET)

%.o: %.c bot.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

install:
	rm -rf $(OBJS) *.c *.h README.md LICENSE Makefile .gitignore .git releases
