/* dcc.c — outbound-only DCC CHAT for admins (irchub/docs/passwordless.md §4.6).
 *
 * The bot never listens for a connection.  An admin sends the sealed command
 * `dcc`; the bot answers with a passive ("reverse") offer
 *     PRIVMSG <nick> :\1DCC CHAT chat <our ip> 0 <token>\1
 * The admin's client listens on a port from its own DCC range and replies,
 * from the same nick!user@host, with
 *     PRIVMSG <bot> :\1DCC CHAT chat <its ip> <port> <token>\1
 * (a client without passive DCC may instead make a plain offer, with no
 * token, while ours is open).  The bot then connects out to that address.
 *
 * The chat is only a transport: every line must be a sealed ~A2 frame from
 * the admin who asked (commands_handle_dcc_line), so whoever holds the TCP
 * connection gains nothing without that admin's key.  Anything else closes
 * the chat.  Replies to a command that came down the chat go back down it
 * (dcc_divert_reply); replies to commands sent by PRIVMSG stay on IRC. */

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#include "bot.h"

#define DCC_OUTBUF_START 4096

void dcc_init(bot_state_t *state) {
  memset(state->dcc, 0, sizeof(state->dcc));
  for (int i = 0; i < DCC_MAX_SESSIONS; i++)
    state->dcc[i].fd = -1;
  state->dcc_reply = NULL;
}

/* Release a slot: close the socket and wipe everything it held. */
static void dcc_free(bot_state_t *state, dcc_session_t *s) {
  if (s->fd >= 0)
    close(s->fd);
  if (s->outbuf) {
    secure_wipe(s->outbuf, s->outcap);
    free(s->outbuf);
  }
  if (state->dcc_reply == s)
    state->dcc_reply = NULL;
  secure_wipe(s, sizeof(*s));
  s->fd = -1; /* phase is DCC_FREE (0) */
}

/* Send what is queued without blocking; false on a hard error. */
static bool dcc_flush(dcc_session_t *s) {
  while (s->outlen > 0) {
    ssize_t n = send(s->fd, s->outbuf, s->outlen, MSG_NOSIGNAL);
    if (n > 0) {
      memmove(s->outbuf, s->outbuf + n, s->outlen - (size_t)n);
      s->outlen -= (size_t)n;
    } else if (n < 0 && errno == EINTR) {
      continue;
    } else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) {
      return true;
    } else {
      return false;
    }
  }
  return true;
}

/* Queue one line (text + "\n") and try to send it.  A client that stops
 * reading must not grow this without bound: past DCC_OUTBUF_MAX the chat is
 * marked failed and closed at the next check. */
static void dcc_queue(dcc_session_t *s, const char *text, size_t len) {
  if (s->phase != DCC_OPEN || s->failed)
    return;
  size_t need = s->outlen + len + 1;
  if (need > DCC_OUTBUF_MAX) {
    s->failed = true;
    return;
  }
  if (need > s->outcap) {
    size_t cap = s->outcap ? s->outcap : DCC_OUTBUF_START;
    while (cap < need)
      cap *= 2;
    if (cap > DCC_OUTBUF_MAX)
      cap = DCC_OUTBUF_MAX;
    /* Grow by copy so the old buffer can be wiped (realloc may not). */
    char *nb = malloc(cap);
    if (!nb) {
      s->failed = true;
      return;
    }
    if (s->outbuf) {
      memcpy(nb, s->outbuf, s->outlen);
      secure_wipe(s->outbuf, s->outcap);
      free(s->outbuf);
    }
    s->outbuf = nb;
    s->outcap = cap;
  }
  memcpy(s->outbuf + s->outlen, text, len);
  s->outbuf[s->outlen + len] = '\n';
  s->outlen += len + 1;
  if (!dcc_flush(s))
    s->failed = true;
}

static void dcc_queue_str(dcc_session_t *s, const char *text) {
  dcc_queue(s, text, strlen(text));
}

/* Close a chat.  An open one is told why first (one send attempt). */
static void dcc_close(bot_state_t *state, dcc_session_t *s,
                      const char *reason) {
  if (reason)
    dcc_queue_str(s, reason);
  log_message(L_INFO, state, "[DCC] Closed chat with %s (%s)%s%s\n", s->name,
              s->user_host, reason ? ": " : "", reason ? reason : "");
  dcc_free(state, s);
}

/* The one reply channel a chat that never opened has: PRIVMSG on IRC. */
static void dcc_give_up(bot_state_t *state, dcc_session_t *s,
                        const char *why) {
  log_message(L_INFO, state, "[DCC] Chat for %s (%s) abandoned: %s\n", s->name,
              s->user_host, why);
  irc_printf(state, "PRIVMSG %s :DCC chat not opened: %s\r\n", s->nick, why);
  dcc_free(state, s);
}

void dcc_close_all(bot_state_t *state, const char *reason) {
  for (int i = 0; i < DCC_MAX_SESSIONS; i++) {
    dcc_session_t *s = &state->dcc[i];
    if (s->phase == DCC_OPEN)
      dcc_close(state, s, reason);
    else if (s->phase != DCC_FREE)
      dcc_free(state, s);
  }
}

void dcc_offer(bot_state_t *state, const char *nick, const char *user_host,
               const user_record_t *who) {
  if (strlen(nick) >= A2_NICK_MAX || strlen(user_host) >= MAX_MASK_LEN) {
    irc_printf(state, "PRIVMSG %s :Error: your nick or mask is too long for a "
                      "DCC chat.\r\n", nick);
    return;
  }

  /* The offer carries our address only because clients reject a zero one;
   * the receiver of a passive offer never connects to it. */
  char ip[INET6_ADDRSTRLEN] = "";
  struct sockaddr_storage self;
  socklen_t self_len = sizeof(self);
  if (state->server_fd >= 0 &&
      getsockname(state->server_fd, (struct sockaddr *)&self, &self_len) == 0) {
    uint32_t v4 = 0;
    bool is_v4 = false;
    if (self.ss_family == AF_INET) {
      v4 = ((struct sockaddr_in *)&self)->sin_addr.s_addr;
      is_v4 = true;
    } else if (self.ss_family == AF_INET6) {
      const struct in6_addr *a6 = &((struct sockaddr_in6 *)&self)->sin6_addr;
      if (IN6_IS_ADDR_V4MAPPED(a6)) {
        memcpy(&v4, a6->s6_addr + 12, 4);
        is_v4 = true;
      } else if (!inet_ntop(AF_INET6, a6, ip, sizeof(ip))) {
        ip[0] = '\0';
      }
    }
    if (is_v4)
      snprintf(ip, sizeof(ip), "%lu", (unsigned long)ntohl(v4));
  }
  if (!ip[0]) {
    irc_printf(state, "PRIVMSG %s :Error: cannot offer a DCC chat right now "
                      "(no IRC connection).\r\n", nick);
    return;
  }

  unsigned char rnd[4];
  if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
    irc_printf(state, "PRIVMSG %s :Error: RNG failure.\r\n", nick);
    return;
  }
  /* Clients read the passive id as a positive int; 0 means "none". */
  uint32_t token = (((uint32_t)rnd[0] << 24) | ((uint32_t)rnd[1] << 16) |
                    ((uint32_t)rnd[2] << 8) | rnd[3]) & 0x7fffffffu;
  if (token == 0)
    token = 1;

  /* One chat per user: a new request replaces any earlier one. */
  for (int i = 0; i < DCC_MAX_SESSIONS; i++) {
    dcc_session_t *o = &state->dcc[i];
    if (o->phase != DCC_FREE && strcmp(o->uuid, who->uuid) == 0) {
      if (o->phase == DCC_OPEN)
        dcc_close(state, o, "Replaced by a new DCC request.");
      else
        dcc_free(state, o);
    }
  }
  dcc_session_t *s = NULL;
  for (int i = 0; i < DCC_MAX_SESSIONS && !s; i++)
    if (state->dcc[i].phase == DCC_FREE)
      s = &state->dcc[i];
  if (!s) {
    irc_printf(state, "PRIVMSG %s :Error: all %d DCC chat slots are in use; "
                      "try again later.\r\n", nick, DCC_MAX_SESSIONS);
    return;
  }

  s->phase = DCC_OFFERED;
  s->fd = -1;
  s->token = token;
  s->phase_since = time(NULL);
  snprintf(s->nick, sizeof(s->nick), "%s", nick);
  snprintf(s->botnick, sizeof(s->botnick), "%s", state->current_nick);
  snprintf(s->user_host, sizeof(s->user_host), "%s", user_host);
  snprintf(s->uuid, sizeof(s->uuid), "%s", who->uuid);
  snprintf(s->name, sizeof(s->name), "%s", who->name);

  irc_printf(state, "PRIVMSG %s :\001DCC CHAT chat %s 0 %lu\001\r\n", nick, ip,
             (unsigned long)token);
  irc_printf(state,
             "PRIVMSG %s :DCC chat offered; accept it within %d s (irssi: "
             "/dcc chat %s). I connect out to your client, so open its DCC "
             "port range in your firewall and set its DCC address to your "
             "public IP. A client without passive DCC can /dcc chat %s "
             "instead while this offer is open.\r\n",
             nick, DCC_OFFER_TIMEOUT, state->current_nick, state->current_nick);
  log_message(L_INFO, state, "[DCC] Offered a chat to %s (%s)\n", s->name,
              user_host);
}

/* Parse the address field of a DCC offer: the classic decimal IPv4, or a
 * literal IPv6 or dotted IPv4 address.  Never a hostname: no lookups.  An
 * IPv4-mapped IPv6 address becomes plain IPv4 so one set of rules applies. */
static bool dcc_parse_addr(const char *a, unsigned port,
                           struct sockaddr_storage *ss, socklen_t *len) {
  memset(ss, 0, sizeof(*ss));
  struct sockaddr_in *v4 = (struct sockaddr_in *)ss;
  struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)ss;
  size_t n = strlen(a);
  if (n == 0 || n >= INET6_ADDRSTRLEN)
    return false;

  if (strspn(a, "0123456789") == n) {
    if (n > 10)
      return false;
    unsigned long long v = strtoull(a, NULL, 10);
    if (v > 0xffffffffULL)
      return false;
    v4->sin_addr.s_addr = htonl((uint32_t)v);
  } else if (strchr(a, ':')) {
    struct in6_addr a6;
    if (inet_pton(AF_INET6, a, &a6) != 1)
      return false;
    if (IN6_IS_ADDR_V4MAPPED(&a6)) {
      memcpy(&v4->sin_addr.s_addr, a6.s6_addr + 12, 4);
    } else {
      v6->sin6_family = AF_INET6;
      v6->sin6_port = htons((uint16_t)port);
      v6->sin6_addr = a6;
      *len = sizeof(*v6);
      return true;
    }
  } else if (inet_pton(AF_INET, a, &v4->sin_addr) != 1) {
    return false;
  }
  v4->sin_family = AF_INET;
  v4->sin_port = htons((uint16_t)port);
  *len = sizeof(*v4);
  return true;
}

/* Addresses a chat may never be pointed at: unspecified, link-local
 * (169.254/16 is where cloud metadata services answer), multicast, broadcast
 * and reserved.  Loopback and private ranges stay allowed: the client may be
 * on the bot's own host or LAN, and every command still needs the admin's key. */
static bool dcc_addr_allowed(const struct sockaddr_storage *ss) {
  if (ss->ss_family == AF_INET) {
    uint32_t a = ntohl(((const struct sockaddr_in *)ss)->sin_addr.s_addr);
    if ((a >> 24) == 0)          /* 0.0.0.0/8 */
      return false;
    if ((a >> 16) == 0xA9FE)     /* 169.254.0.0/16 */
      return false;
    if ((a >> 28) >= 0xE)        /* 224/4 multicast, 240/4 reserved, broadcast */
      return false;
    return true;
  }
  if (ss->ss_family == AF_INET6) {
    const struct in6_addr *a = &((const struct sockaddr_in6 *)ss)->sin6_addr;
    return !(IN6_IS_ADDR_UNSPECIFIED(a) || IN6_IS_ADDR_LINKLOCAL(a) ||
             IN6_IS_ADDR_MULTICAST(a) || IN6_IS_ADDR_V4MAPPED(a));
  }
  return false;
}

/* Source the chat from the configured VHOST, as irc_connect does, when it is
 * the same address family (otherwise the kernel picks). */
static void dcc_bind_vhost(bot_state_t *state, int fd, int family) {
  if (state->vhost[0] == '\0' || strcasecmp(state->vhost, "NULL") == 0)
    return;
  struct sockaddr_storage va;
  memset(&va, 0, sizeof(va));
  socklen_t vl = 0;
  if (family == AF_INET &&
      inet_pton(AF_INET, state->vhost,
                &((struct sockaddr_in *)&va)->sin_addr) == 1) {
    va.ss_family = AF_INET;
    vl = sizeof(struct sockaddr_in);
  } else if (family == AF_INET6 &&
             inet_pton(AF_INET6, state->vhost,
                       &((struct sockaddr_in6 *)&va)->sin6_addr) == 1) {
    va.ss_family = AF_INET6;
    vl = sizeof(struct sockaddr_in6);
  }
  if (vl && bind(fd, (struct sockaddr *)&va, vl) != 0)
    log_message(L_INFO, state, "[DCC] Could not bind VHOST %s: %s\n",
                state->vhost, strerror(errno));
}

/* Start a non-blocking connect; the fd, or -1 with *err set. */
static int dcc_connect(bot_state_t *state, const struct sockaddr_storage *ss,
                       socklen_t len, int *err) {
  int fd = socket(ss->ss_family, SOCK_STREAM, 0);
  if (fd < 0) {
    *err = errno;
    return -1;
  }
  int fl = fcntl(fd, F_GETFL, 0);
  if (fd >= FD_SETSIZE || fl < 0 || fcntl(fd, F_SETFL, fl | O_NONBLOCK) < 0 ||
      fcntl(fd, F_SETFD, FD_CLOEXEC) < 0) {
    *err = (fd >= FD_SETSIZE) ? EMFILE : errno;
    close(fd);
    return -1;
  }
  dcc_bind_vhost(state, fd, ss->ss_family);
  if (connect(fd, (const struct sockaddr *)ss, len) != 0 &&
      errno != EINPROGRESS) {
    *err = errno;
    close(fd);
    return -1;
  }
  return fd;
}

/* All digits, at most maxlen of them. */
static bool all_digits(const char *s, size_t maxlen) {
  size_t n = strlen(s);
  return n > 0 && n <= maxlen && strspn(s, "0123456789") == n;
}

void dcc_handle_ctcp(bot_state_t *state, const char *user_host,
                     const char *ctcp) {
  /* "DCC CHAT chat <addr> <port> [<token>]" */
  char buf[256];
  char *f[6];
  int nf = 0;
  bool shape_ok = strlen(ctcp) < sizeof(buf);
  if (shape_ok) {
    snprintf(buf, sizeof(buf), "%s", ctcp);
    char *sp;
    for (char *t = strtok_r(buf, " ", &sp); t; t = strtok_r(NULL, " ", &sp)) {
      if (nf == 6) {
        shape_ok = false;
        break;
      }
      f[nf++] = t;
    }
  }
  shape_ok = shape_ok && nf >= 5 && strcasecmp(f[0], "DCC") == 0 &&
             strcasecmp(f[1], "CHAT") == 0 && strcasecmp(f[2], "chat") == 0;

  dcc_session_t *s = NULL;
  for (int i = 0; i < DCC_MAX_SESSIONS && !s; i++)
    if (state->dcc[i].phase == DCC_OFFERED &&
        strcasecmp(state->dcc[i].user_host, user_host) == 0)
      s = &state->dcc[i];
  if (!shape_ok || !s) {
    /* Never a connection the bot did not offer: no listening, no chats or
     * sends started by someone else. */
    log_message(L_CTCP, state, "[DCC] Ignored DCC request from %s: the bot "
                               "only connects out, after its own offer\n",
                user_host);
    return;
  }

  if (nf == 6) {
    if (!all_digits(f[5], 10) ||
        strtoull(f[5], NULL, 10) != (unsigned long long)s->token) {
      log_message(L_CTCP, state, "[DCC] Reply from %s carries another "
                                 "offer's token; ignored\n", user_host);
      return;
    }
  }
  /* From here the reply belongs to this offer: a bad value ends it. */
  bool port_digits = all_digits(f[4], 5);
  unsigned long port = port_digits ? strtoul(f[4], NULL, 10) : 0;
  if (port_digits && port == 0) {
    dcc_give_up(state, s, "your client answered with a passive offer of its "
                          "own; it has to listen on a port for me to connect "
                          "to.");
    return;
  }
  if (!port_digits || port < DCC_MIN_PORT || port > 65535) {
    char why[128];
    if (port_digits)
      snprintf(why, sizeof(why), "port %lu is not allowed (use %d-65535).",
               port, DCC_MIN_PORT);
    else
      snprintf(why, sizeof(why), "your client's reply has no valid port.");
    dcc_give_up(state, s, why);
    return;
  }
  struct sockaddr_storage ss;
  socklen_t ss_len = 0;
  if (!dcc_parse_addr(f[3], (unsigned)port, &ss, &ss_len) ||
      !dcc_addr_allowed(&ss)) {
    dcc_give_up(state, s, "your client sent an address I will not connect "
                          "to; set its DCC address to your public IP.");
    return;
  }

  char host[INET6_ADDRSTRLEN] = "?";
  const void *ap = (ss.ss_family == AF_INET)
                       ? (const void *)&((struct sockaddr_in *)&ss)->sin_addr
                       : (const void *)&((struct sockaddr_in6 *)&ss)->sin6_addr;
  inet_ntop(ss.ss_family, ap, host, sizeof(host));
  snprintf(s->peer, sizeof(s->peer), "%s port %lu", host, port);

  int err = 0;
  int fd = dcc_connect(state, &ss, ss_len, &err);
  if (fd < 0) {
    char why[160];
    snprintf(why, sizeof(why), "connecting to %s failed: %s.", s->peer,
             strerror(err));
    dcc_give_up(state, s, why);
    return;
  }
  s->fd = fd;
  s->phase = DCC_CONNECTING;
  s->phase_since = time(NULL);
  log_message(L_INFO, state, "[DCC] Connecting to %s for %s (%s)\n", s->peer,
              s->name, user_host);
}

/* A connecting socket turned writable: open, or report why not. */
static void dcc_on_connect(bot_state_t *state, dcc_session_t *s) {
  int soerr = 0;
  socklen_t sl = sizeof(soerr);
  if (getsockopt(s->fd, SOL_SOCKET, SO_ERROR, &soerr, &sl) != 0)
    soerr = errno;
  if (soerr == 0) {
    struct sockaddr_storage pa;
    socklen_t pl = sizeof(pa);
    if (getpeername(s->fd, (struct sockaddr *)&pa, &pl) != 0) {
      if (errno == ENOTCONN)
        return; /* not finished yet */
      soerr = errno;
    }
  }
  if (soerr != 0) {
    char why[200];
    snprintf(why, sizeof(why), "connecting to %s failed: %s. Check that your "
                               "firewall lets that port in.", s->peer,
             strerror(soerr));
    dcc_give_up(state, s, why);
    return;
  }
  s->phase = DCC_OPEN;
  s->phase_since = s->last_active = time(NULL);
  log_message(L_INFO, state, "[DCC] Chat open with %s (%s) at %s\n", s->name,
              s->user_host, s->peer);
  char line[400];
  snprintf(line, sizeof(line),
           "%s: DCC chat open for %s. Send commands with /botcmd %s "
           "<command>; the replies come back here. Anything that is not a "
           "sealed command closes this chat. Idle limit: %d min.",
           s->botnick, s->name, s->botnick, DCC_IDLE_TIMEOUT / 60);
  dcc_queue_str(s, line);
}

/* Read what arrived and run each complete line. */
static void dcc_read(bot_state_t *state, dcc_session_t *s) {
  char buf[2048];
  ssize_t n = recv(s->fd, buf, sizeof(buf), 0);
  if (n == 0 || (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK &&
                 errno != EINTR)) {
    log_message(L_INFO, state, "[DCC] %s (%s) closed the chat\n", s->name,
                s->user_host);
    dcc_free(state, s);
    return;
  }
  for (ssize_t i = 0; i < n; i++) {
    unsigned char c = (unsigned char)buf[i];
    if (c == '\n') {
      size_t len = s->inlen;
      if (len > 0 && s->inbuf[len - 1] == '\r')
        len--;
      s->inbuf[len] = '\0';
      s->inlen = 0;
      if (len == 0)
        continue; /* blank line: nothing to run */
      log_message(L_RAW, state, "[DCC_RECV] (%s) %s\n", s->user_host,
                  s->inbuf);
      bool ok = commands_handle_dcc_line(state, s, s->inbuf);
      secure_wipe(s->inbuf, sizeof(s->inbuf));
      if (!ok) {
        dcc_close(state, s, "That was not a valid sealed command from your "
                            "key; closing.");
        return;
      }
      if (s->phase != DCC_OPEN)
        return;
      continue;
    }
    /* A frame is base64: a control byte (other than the CR before LF) or an
     * over-long line is not one, and nothing after it is trusted either. */
    bool bad = (c < 0x20 && c != '\r') || c == 0x7f ||
               (s->inlen > 0 && s->inbuf[s->inlen - 1] == '\r');
    if (bad || s->inlen >= A2_LINE_MAX + 1) {
      dcc_close(state, s, bad ? "Unexpected control byte; closing."
                              : "Line too long; closing.");
      return;
    }
    s->inbuf[s->inlen++] = (char)c;
  }
}

void dcc_fill_fds(bot_state_t *state, fd_set *rfds, fd_set *wfds,
                  int *max_fd) {
  for (int i = 0; i < DCC_MAX_SESSIONS; i++) {
    dcc_session_t *s = &state->dcc[i];
    if (s->fd < 0)
      continue;
    if (s->phase == DCC_CONNECTING) {
      FD_SET(s->fd, wfds);
    } else if (s->phase == DCC_OPEN) {
      FD_SET(s->fd, rfds);
      if (s->outlen > 0)
        FD_SET(s->fd, wfds);
    }
    if (s->fd > *max_fd)
      *max_fd = s->fd;
  }
}

void dcc_process(bot_state_t *state, const fd_set *rfds, const fd_set *wfds) {
  for (int i = 0; i < DCC_MAX_SESSIONS; i++) {
    dcc_session_t *s = &state->dcc[i];
    if (s->fd < 0)
      continue;
    if (s->phase == DCC_CONNECTING) {
      /* A slot connected after select() may reuse a closed fd's number;
       * dcc_on_connect's getpeername() tells a finished connect apart. */
      if (FD_ISSET(s->fd, wfds))
        dcc_on_connect(state, s);
      continue;
    }
    if (s->phase != DCC_OPEN)
      continue;
    if (FD_ISSET(s->fd, wfds) && !dcc_flush(s))
      s->failed = true;
    if (!s->failed && FD_ISSET(s->fd, rfds))
      dcc_read(state, s);
    if (s->phase == DCC_OPEN && s->failed)
      dcc_close(state, s, NULL);
  }
}

void dcc_check_timeouts(bot_state_t *state) {
  time_t now = time(NULL);
  for (int i = 0; i < DCC_MAX_SESSIONS; i++) {
    dcc_session_t *s = &state->dcc[i];
    if (s->phase == DCC_OPEN && s->failed) {
      dcc_close(state, s, NULL);
    } else if (s->phase == DCC_OFFERED &&
               now - s->phase_since > DCC_OFFER_TIMEOUT) {
      dcc_give_up(state, s, "your client did not answer the offer in time.");
    } else if (s->phase == DCC_CONNECTING &&
               now - s->phase_since > DCC_CONNECT_TIMEOUT) {
      char why[200];
      snprintf(why, sizeof(why), "connecting to %s timed out. Check that "
                                 "your firewall lets that port in.", s->peer);
      dcc_give_up(state, s, why);
    } else if (s->phase == DCC_OPEN &&
               now - s->last_active > DCC_IDLE_TIMEOUT) {
      dcc_close(state, s, "Idle limit reached; closing.");
    }
  }
}

/* irc_printf hook: while a command from a chat runs (state->dcc_reply), its
 * replies -- "PRIVMSG <that nick> :<text>" -- go down the chat instead of to
 * the server.  Lines to anyone else (MODE, INVITE, ~B2 to other bots) do not
 * match and still go to IRC. */
bool dcc_divert_reply(bot_state_t *state, const char *line, int len) {
  dcc_session_t *s = state->dcc_reply;
  if (!s || len < 0)
    return false;
  size_t nl = strlen(s->nick);
  size_t head = 8 + nl + 2; /* "PRIVMSG " nick " :" */
  if ((size_t)len < head + 2 || strncmp(line, "PRIVMSG ", 8) != 0 ||
      memcmp(line + 8, s->nick, nl) != 0 || memcmp(line + 8 + nl, " :", 2) != 0)
    return false;
  size_t tlen = (size_t)len - head - 2; /* without the "\r\n" */
  log_message(L_RAW, state, "[DCC_SEND] (%s) %.*s\n", s->user_host, (int)tlen,
              line + head);
  dcc_queue(s, line + head, tlen);
  return true;
}
