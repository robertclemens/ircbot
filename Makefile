# Makefile for the modernized IRC bot
CC = gcc

#FOR DEV
#CFLAGS = -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -Wall -Wextra -std=c11 -g
#FOR RELEASE
CFLAGS = -D_POSIX_C_SOURCE=200809L -D_XOPEN_SOURCE=700 -Wall -Wextra -std=c11 -O2

LDFLAGS = -lssl -lcrypto -lcurl

# Source files
SRCS = main.c bot.c config.c channel.c irc_client.c irc_parser.c commands.c utils.c logging.c auth.c bot_comms.c crypto.c

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
