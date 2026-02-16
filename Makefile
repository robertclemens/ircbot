# Makefile for the modernized IRC bot
CC = gcc

# Set to 0 to disable curl support (update feature will be unavailable)
USE_CURL ?= 1

#FOR DEV
#CFLAGS = -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -Wall -Wextra -std=c11 -g
#FOR RELEASE
CFLAGS = -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -Wall -Wextra -std=c11 -O2

# Add HAVE_CURL flag if curl support is enabled
ifeq ($(USE_CURL),1)
CFLAGS += -DHAVE_CURL
LDFLAGS = -lssl -lcrypto -lcurl
else
LDFLAGS = -lssl -lcrypto
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

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) $(TARGET)

install:
	rm -rf $(OBJS) *.c *.h README.md LICENSE Makefile .gitignore .git releases
