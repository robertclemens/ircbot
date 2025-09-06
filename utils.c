#include <arpa/inet.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "bot.h"

void handle_fatal_error(const char *message) {
  perror(message);
  exit(EXIT_FAILURE);
}
void get_local_ip(bot_state_t *state) {
  char hostname[256];
  if (gethostname(hostname, sizeof(hostname)) != 0) return;
  struct addrinfo hints, *info;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  if (getaddrinfo(hostname, NULL, &hints, &info) != 0) return;
  struct sockaddr_in *sa = (struct sockaddr_in *)info->ai_addr;
  state->local_ip_long = ntohl(sa->sin_addr.s_addr);
  freeaddrinfo(info);
}
