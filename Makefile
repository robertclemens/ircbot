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
CFLAGS = -std=c11 -O2

# Warnings.  A production build (plain `make`, and what the release tooling
# runs) gets the standard set, WARN_STD.  `make dev` (= `make WARN=full`) adds
# the full development set on top, so no warning stays hidden while testing;
# the tree must stay warning-free under both.  Switching sets needs a
# `make clean` first (objects do not depend on the flags).
# Left out of the full set on purpose: -Wjump-misses-init (C++ compatibility
# only) and -Wformat-truncation=2 (flags bounded snprintf whose result is
# checked).
WARN ?= std
WARN_STD    = -Wall -Wextra -Wpedantic -Wshadow
WARN_COMMON = $(WARN_STD) -Wformat=2 -Wstrict-prototypes \
              -Wmissing-prototypes -Wmissing-declarations -Wold-style-definition \
              -Wnested-externs -Wbad-function-cast -Wcast-qual -Wcast-align \
              -Wpointer-arith -Wwrite-strings -Wundef -Wnull-dereference \
              -Wredundant-decls -Wvla -Wfloat-equal -Wdouble-promotion -Winit-self \
              -Wconversion -Wsign-conversion
# Checks only one compiler has (an unknown -W flag is itself a warning).
WARN_GCC    = -Wformat-overflow=2 -Wformat-signedness -Wlogical-op -Wduplicated-cond \
              -Wduplicated-branches -Wstringop-overflow=4 -Warray-bounds=2 \
              -Walloc-zero -Wtrampolines
WARN_CLANG  = -Wunreachable-code-aggressive -Wconditional-uninitialized \
              -Wmissing-variable-declarations -Wcomma -Wloop-analysis -Wassign-enum \
              -Wextra-semi
ifeq ($(WARN),full)
CC_IS_CLANG := $(shell $(CC) --version 2>/dev/null | grep -qi clang && echo 1)
ifeq ($(CC_IS_CLANG),1)
WARNFLAGS = $(WARN_COMMON) $(WARN_CLANG)
else
WARNFLAGS = $(WARN_COMMON) $(WARN_GCC)
endif
else
WARNFLAGS = $(WARN_STD)
endif
# WARNFLAGS go on the compile steps only: the link line carries CFLAGS, and a
# static link LTO-compiles code from the system's static libraries (Alpine's
# nghttp2, libpsl) under whatever warning flags it is given.

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
SRCS = main.c bot.c config.c channel.c hub_client.c irc_client.c irc_parser.c commands.c utils.c logging.c auth.c bot_comms.c crypto.c dcc.c sendq.c chanlive.c chancfg.c glob_overlap.c chanenf.c chanflood.c botflood.c chancmd.c access.c

# Object files
OBJS = $(SRCS:.c=.o)

# Executable name
TARGET = ircbot

.PHONY: all clean keygen dev

all: $(TARGET)

# Development / test build: the daemon and keygen under the full warning set.
dev:
	@$(MAKE) --no-print-directory WARN=full all keygen

# utils/keygen.c + bcrypt_pbkdf.[ch] are byte-identical to their irchub
# copies (self-contained, OpenSSL only).  Not part of `all`: build it where
# users make their keys.
keygen: utils/keygen

utils/keygen: utils/keygen.c utils/bcrypt_pbkdf.c utils/bcrypt_pbkdf.h
	$(CC) $(CFLAGS) $(WARNFLAGS) -o $@ utils/keygen.c utils/bcrypt_pbkdf.c -lcrypto

$(TARGET): $(OBJS)
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS) $(LDFLAGS)
	@chmod 700 $(TARGET)

%.o: %.c bot.h
	$(CC) $(CFLAGS) $(WARNFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET) utils/keygen

install:
	rm -rf $(OBJS) *.c *.h README.md LICENSE Makefile .gitignore .git releases
