#include <arpa/inet.h>
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <netdb.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/select.h>
#include <unistd.h>

#include "bot.h"

/* ---- Server refusals (bans / throttles) ----------------------------------
 *
 * A server that refuses the bot says why in a 465 (ERR_YOUREBANNEDCREEP) or
 * 463 (ERR_NOPERMFORHOST) numeric and/or the ERROR line it sends before
 * closing the link.  The parser hands that text to irc_note_refusal(); when
 * the link drops, irc_disconnect() classifies it once and puts a hold on that
 * server_list[] slot, which irc_connect() then skips.
 *
 *   ban wording + stated length  ("Temporary K-line 60 min.", "expires in 2h")
 *        -> held for that long (+IRC_BAN_GRACE), never less than the
 *           throttle backoff for the strike count
 *   ban wording + "permanent"    -> never retried automatically
 *   ban wording alone            -> IRC_BAN_BACKOFF doubling to _MAX: an
 *           unlabelled temporary ban clears by itself, and an unlabelled
 *           permanent one costs one connection attempt a day
 *   "throttled", "too fast", "too many [connections]"
 *        -> IRC_THROTTLE_BACKOFF doubling to _MAX
 *
 * Ban wording is a 465/463, or K-/G-/Z-/D-lined, AKILL, "banned", "not
 * welcome".  Anything else -- ping timeout, KILL, the echo of our own QUIT --
 * is an ordinary disconnect.  The text is server-controlled: it is sanitized
 * (a lone CR/LF would inject IRC commands when 'status' echoes it), bounded,
 * and parsed without overflow.  Holds are runtime-only; 'jump <server>',
 * +server/-server and a restart clear them. */

/* Server text, control bytes (including a lone CR or LF) replaced by '?'. */
static void refusal_sanitize(char *dst, size_t cap, const char *src) {
  size_t n = 0;
  for (const unsigned char *p = (const unsigned char *)src; *p && n + 1 < cap;
       p++)
    dst[n++] = (*p < 0x20 || *p == 0x7f) ? '?' : (char)*p;
  dst[n] = '\0';
}

/* Lower-cased, '-' dropped: "K-Lined", "k-line" and "KLINE" all read "kline". */
static void refusal_fold(char *dst, size_t cap, const char *src) {
  size_t n = 0;
  for (; *src && n + 1 < cap; src++)
    if (*src != '-') dst[n++] = (char)tolower((unsigned char)*src);
  dst[n] = '\0';
}

/* needle at a word start (not preceded by a letter), so "unbanned" and
 * "deadline" do not read as "banned" and "dline".  Returns the position just
 * past the match, or NULL. */
static const char *refusal_find(const char *hay, const char *needle) {
  size_t nl = strlen(needle);
  for (const char *p = strstr(hay, needle); p; p = strstr(p + 1, needle))
    if (p == hay || !isalpha((unsigned char)p[-1])) return p + nl;
  return NULL;
}

/* A length such as "60 min", "2 hours", "1h30m" starting at the first digit
 * within 48 chars of s.  Only a known unit word counts, so a date ("2026/09")
 * or "3 strikes" yields 0 (= unknown).  Digits are clamped while parsing, so
 * hostile input cannot overflow; the result is capped at IRC_BAN_STATED_MAX. */
static long long refusal_parse_duration(const char *s) {
  static const struct { const char *word; long long secs; } units[] = {
    {"s", 1}, {"sec", 1}, {"secs", 1}, {"second", 1}, {"seconds", 1},
    {"m", 60}, {"min", 60}, {"mins", 60}, {"minute", 60}, {"minutes", 60},
    {"h", 3600}, {"hr", 3600}, {"hrs", 3600}, {"hour", 3600}, {"hours", 3600},
    {"d", 86400}, {"day", 86400}, {"days", 86400},
    {"w", 604800}, {"wk", 604800}, {"week", 604800}, {"weeks", 604800},
    {"mo", 2592000}, {"month", 2592000}, {"months", 2592000},
    {"y", 31536000}, {"yr", 31536000}, {"year", 31536000}, {"years", 31536000},
  };
  const char *p = s;
  for (int skipped = 0; *p && !isdigit((unsigned char)*p); p++)
    if (++skipped > 48) return 0;

  long long total = 0;
  for (int pairs = 0; pairs < 4 && isdigit((unsigned char)*p); pairs++) {
    long long n = 0;
    for (; isdigit((unsigned char)*p); p++)
      if (n < 1000000000LL) n = n * 10 + (*p - '0');
    while (*p == ' ') p++;
    char word[12];
    size_t wl = 0;
    for (; isalpha((unsigned char)*p); p++)
      if (wl + 1 < sizeof(word)) word[wl++] = *p;
    word[wl] = '\0';
    long long unit = 0;
    for (size_t i = 0; i < sizeof(units) / sizeof(units[0]); i++)
      if (strcmp(word, units[i].word) == 0) { unit = units[i].secs; break; }
    if (unit == 0) break;
    total += n * unit; /* n < 1e10, unit < 3.2e7: no overflow */
    if (total >= IRC_BAN_STATED_MAX) return IRC_BAN_STATED_MAX;
    while (*p == ' ' || *p == ',') p++;
  }
  return total;
}

static server_block_kind_t refusal_classify(const char *text, bool ban_numeric,
                                            long long *stated_secs) {
  static const char *const ban_words[] = {"kline", "gline",    "zline",
                                          "dline", "akill",    "autokill",
                                          "banned", "not welcome"};
  static const char *const throttle_words[] = {"throttl", "too fast",
                                               "too many"};
  char t[IRC_REFUSAL_LEN];
  refusal_fold(t, sizeof(t), text);
  *stated_secs = 0;

  /* An oper KILL or the echo of our own QUIT carries free text that may say
   * anything; neither is a ban. */
  if (!ban_numeric && (strstr(t, "killed (") || strstr(t, "(quit:")))
    return SB_NONE;

  bool ban = ban_numeric;
  for (size_t i = 0; !ban && i < sizeof(ban_words) / sizeof(ban_words[0]); i++)
    if (refusal_find(t, ban_words[i])) ban = true;
  if (ban) {
    const char *after = refusal_find(t, "temporar");
    if (!after) after = refusal_find(t, "expire");
    if (after) {
      *stated_secs = refusal_parse_duration(after);
      return *stated_secs > 0 ? SB_BANNED_TEMP : SB_BANNED;
    }
    return refusal_find(t, "permanent") ? SB_BANNED_PERM : SB_BANNED;
  }
  for (size_t i = 0; i < sizeof(throttle_words) / sizeof(throttle_words[0]);
       i++)
    if (refusal_find(t, throttle_words[i])) return SB_THROTTLED;
  return SB_NONE;
}

static long long refusal_backoff(long long base, int strikes, long long cap) {
  long long s = base;
  for (int i = 1; i < strikes && s < cap; i++) s *= 2;
  return s < cap ? s : cap;
}

static void refusal_fmt_secs(char *buf, size_t len, long long s) {
  if (s >= 86400)
    snprintf(buf, len, "%lldd%lldh", s / 86400, (s % 86400) / 3600);
  else if (s >= 3600)
    snprintf(buf, len, "%lldh%02lldm", s / 3600, (s % 3600) / 60);
  else if (s >= 60 && s % 60)
    snprintf(buf, len, "%lldm%02llds", s / 60, s % 60);
  else if (s >= 60)
    snprintf(buf, len, "%lldm", s / 60);
  else
    snprintf(buf, len, "%llds", s);
}

void irc_note_refusal(bot_state_t *state, const char *text, bool ban_numeric) {
  char clean[IRC_REFUSAL_LEN];
  refusal_sanitize(clean, sizeof(clean), text ? text : "");
  if (ban_numeric) state->irc_refusal_ban = true;
  log_message(L_INFO, state, "[IRC] Server %s: %s\n",
              ban_numeric ? "refused registration" : "ERROR", clean);

  /* A 465 is usually followed by an ERROR; keep both for the classifier.
   * Truncation is harmless: bounded, and the telling words come early.
   * Appended by hand -- an snprintf here trips gcc 8's -Wformat-truncation. */
  const size_t cap = sizeof(state->irc_refusal);
  size_t off = strlen(state->irc_refusal);
  if (off > 0 && off + 3 + 1 < cap) { /* " | " plus >= 1 byte of text */
    memcpy(state->irc_refusal + off, " | ", 3);
    off += 3;
  }
  size_t n = strlen(clean);
  if (n > cap - 1 - off) n = cap - 1 - off;
  memcpy(state->irc_refusal + off, clean, n);
  state->irc_refusal[off + n] = '\0';
}

/* Classify what this link was told, once, as it goes down (irc_disconnect). */
static void irc_apply_refusal(bot_state_t *state) {
  if (state->irc_refusal[0] == '\0' && !state->irc_refusal_ban) return;

  long long stated = 0;
  server_block_kind_t kind =
      refusal_classify(state->irc_refusal, state->irc_refusal_ban, &stated);
  int idx = state->irc_server_idx;
  if (kind != SB_NONE && idx >= 0 && idx < state->server_count) {
    server_block_t *b = &state->server_blocks[idx];
    time_t now = time(NULL);
    if (b->strikes < 32) b->strikes++;

    long long hold = 0;
    if (kind == SB_THROTTLED) {
      hold = refusal_backoff(IRC_THROTTLE_BACKOFF, b->strikes,
                             IRC_THROTTLE_BACKOFF_MAX);
    } else if (kind == SB_BANNED) {
      hold = refusal_backoff(IRC_BAN_BACKOFF, b->strikes, IRC_BAN_BACKOFF_MAX);
    } else if (kind == SB_BANNED_TEMP) {
      /* Honour the stated length, but never redial faster than a throttle
       * would -- a short or misread length must not become a tight loop. */
      long long floor = refusal_backoff(IRC_THROTTLE_BACKOFF, b->strikes,
                                        IRC_BAN_BACKOFF_MAX);
      hold = stated + IRC_BAN_GRACE;
      if (hold < floor) hold = floor;
    }
    b->kind = kind;
    b->until = (kind == SB_BANNED_PERM) ? 0 : now + (time_t)hold;
    snprintf(b->reason, sizeof(b->reason), "%s", state->irc_refusal);

    char hold_s[32] = "", stated_s[32] = "";
    refusal_fmt_secs(hold_s, sizeof(hold_s), hold);
    refusal_fmt_secs(stated_s, sizeof(stated_s), stated);
    if (kind == SB_BANNED_PERM)
      log_message(L_INFO, state,
                  "[BAN] %s: PERMANENT ban - will not reconnect to it until "
                  "restart, 'jump %s', or re-adding it.\n",
                  state->server_list[idx], state->server_list[idx]);
    else if (kind == SB_BANNED_TEMP)
      log_message(L_INFO, state,
                  "[BAN] %s: temporary ban, server says %s - holding %s "
                  "(strike %d).\n",
                  state->server_list[idx], stated_s, hold_s, b->strikes);
    else
      log_message(L_INFO, state, "[BAN] %s: %s - holding %s (strike %d).\n",
                  state->server_list[idx],
                  kind == SB_THROTTLED ? "throttled" : "banned, no length given",
                  hold_s, b->strikes);
  }
  state->irc_refusal[0] = '\0';
  state->irc_refusal_ban = false;
}

/* 001: this server took us; forget any hold and strike count it had. */
void irc_note_registered(bot_state_t *state) {
  int idx = state->irc_server_idx;
  if (idx < 0 || idx >= state->server_count) return;
  if (state->server_blocks[idx].strikes > 0)
    log_message(L_INFO, state, "[BAN] %s accepted us; hold cleared.\n",
                state->server_list[idx]);
  memset(&state->server_blocks[idx], 0, sizeof(server_block_t));
}

void irc_server_block_clear(bot_state_t *state, int idx) {
  if (idx < 0 || idx >= MAX_SERVERS) return;
  memset(&state->server_blocks[idx], 0, sizeof(server_block_t));
  state->irc_blocked_logged = false;
}

/* -server: call BEFORE server_list[] is compacted (server_count unchanged). */
void irc_server_block_remove(bot_state_t *state, int idx) {
  int n = state->server_count;
  if (idx < 0 || idx >= n) return;
  memmove(&state->server_blocks[idx], &state->server_blocks[idx + 1],
          (size_t)(n - 1 - idx) * sizeof(server_block_t));
  memset(&state->server_blocks[n - 1], 0, sizeof(server_block_t));
  if (state->irc_server_idx == idx)
    state->irc_server_idx = -1; /* a refusal on this link now has no slot */
  else if (state->irc_server_idx > idx)
    state->irc_server_idx--;
}

/* "banned 42m", "throttled 55s", "banned, permanent", or "" if eligible. */
void irc_server_block_desc(const bot_state_t *state, int idx, char *buf,
                           size_t len) {
  if (len == 0) return;
  buf[0] = '\0';
  if (idx < 0 || idx >= MAX_SERVERS) return;
  const server_block_t *b = &state->server_blocks[idx];
  if (b->kind == SB_BANNED_PERM) {
    snprintf(buf, len, "banned, permanent");
    return;
  }
  time_t now = time(NULL);
  if (b->kind == SB_NONE || b->until <= now) return;
  char left[32];
  refusal_fmt_secs(left, sizeof(left), (long long)(b->until - now));
  snprintf(buf, len, "%s %s", b->kind == SB_THROTTLED ? "throttled" : "banned",
           left);
}

/* First slot at or after current_server_index (wrapping) that is not held;
 * -1 when every configured server is refusing us (logged once per episode). */
static int irc_pick_server(bot_state_t *state, time_t now) {
  int n = state->server_count;
  if (n <= 0) return -1;
  int start = state->current_server_index;
  if (start < 0 || start >= n) start = 0;

  time_t soonest = 0;
  for (int k = 0; k < n; k++) {
    int i = (start + k) % n;
    const server_block_t *b = &state->server_blocks[i];
    if (b->kind == SB_BANNED_PERM) continue;
    if (b->kind != SB_NONE && b->until > now) {
      if (soonest == 0 || b->until < soonest) soonest = b->until;
      continue;
    }
    state->irc_blocked_logged = false;
    return i;
  }
  if (!state->irc_blocked_logged) {
    state->irc_blocked_logged = true;
    if (soonest) {
      char wait_s[32];
      refusal_fmt_secs(wait_s, sizeof(wait_s), (long long)(soonest - now));
      log_message(L_INFO, state,
                  "[BAN] Every configured server is refusing this bot; next "
                  "attempt in %s.\n", wait_s);
    } else {
      log_message(L_INFO, state,
                  "[BAN] Every configured server has permanently banned this "
                  "bot; not reconnecting to IRC until restarted.\n");
    }
  }
  return -1;
}

void irc_disconnect(bot_state_t *state) {
  irc_apply_refusal(state);
  // Send QUIT first so the server removes the nick immediately.
  // Without this, NAT holds the TCP state and the nick ghosts until ping-timeout.
  if ((state->status & S_CONNECTED) && state->server_fd != -1) {
    const char *quit_msg = "QUIT :bye\r\n";
    if (state->is_ssl && state->ssl) {
      SSL_write(state->ssl, quit_msg, strlen(quit_msg));
    } else {
      send(state->server_fd, quit_msg, strlen(quit_msg), MSG_NOSIGNAL);
    }
  }
  if (state->is_ssl && state->ssl) {
    SSL_shutdown(state->ssl);
    SSL_free(state->ssl);
    state->ssl = NULL;
  }
  if (state->ssl_ctx) {
    SSL_CTX_free(state->ssl_ctx);
    state->ssl_ctx = NULL;
  }
  if (state->server_fd != -1) {
    close(state->server_fd);
    state->server_fd = -1;
  }
  state->status = S_NONE;
  state->is_ssl = false;
  channel_list_reset_status(state);
}

int irc_printf(bot_state_t *state, const char *format, ...) {
  if (!(state->status & S_CONNECTED)) return -1;
  char buffer[MAX_BUFFER];
  va_list args;
  va_start(args, format);
  int len = vsnprintf(buffer, sizeof(buffer), format, args);
  va_end(args);
  if (len < 0) return -1;
  if (len >= (int)sizeof(buffer)) len = (int)sizeof(buffer) - 1;
  log_message(L_RAW, state, "[RAW_SEND] %s", buffer);
  if (state->is_ssl) {
    int sent = SSL_write(state->ssl, buffer, len);
    if (sent <= 0) {
      ERR_print_errors_fp(stderr);
      log_message(L_INFO, state,
                  "[INFO] Lost connection to server (SSL write error).\n");
      irc_disconnect(state);
      return -1;
    }
    return sent;
  } else {
    int total_sent = 0;
    while (total_sent < len) {
      ssize_t sent = write(state->server_fd, buffer + total_sent,
                           len - total_sent);
      if (sent <= 0) {
        if (errno == EINTR) continue;
        log_message(L_INFO, state,
                    "[INFO] Lost connection to server (write error).\n");
        irc_disconnect(state);
        return -1;
      }
      total_sent += (int)sent;
    }
    return total_sent;
  }
}

void irc_connect(bot_state_t *state) {
  if (state->server_fd != -1) return;
  time_t attempt_now = time(NULL);
  int pick = irc_pick_server(state, attempt_now);
  if (pick < 0) return; /* everything held; irc_pick_server logged why */
  state->current_server_index = pick;
  state->irc_server_idx = pick;
  state->last_irc_attempt = attempt_now;
  state->irc_refusal[0] = '\0';
  state->irc_refusal_ban = false;

  char server_str[256];
  snprintf(server_str, sizeof(server_str), "%s",
           state->server_list[state->current_server_index]);

  char *port_from_config = strrchr(server_str, ':');
  char *host = server_str;
  if (port_from_config) {
    *port_from_config = '\0';
    port_from_config++;
  }

  // If port specified: only try that port. Otherwise try 6667, then 6697
  const char *ports_to_try[3] = {NULL, NULL, NULL};
  if (port_from_config) {
    ports_to_try[0] = port_from_config;
  } else {
    ports_to_try[0] = "6667";
    ports_to_try[1] = "6697";
  }

  struct sockaddr_storage vhost_addr;
  int vhost_family = AF_UNSPEC;

  if (state->vhost[0] != '\0' && strcasecmp(state->vhost, "NULL") != 0) {
      struct sockaddr_in *v4 = (struct sockaddr_in *)&vhost_addr;
      struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&vhost_addr;

      if (inet_pton(AF_INET, state->vhost, &v4->sin_addr) == 1) {
          vhost_family = AF_INET;
          v4->sin_family = AF_INET;
          v4->sin_port = 0;
      } else if (inet_pton(AF_INET6, state->vhost, &v6->sin6_addr) == 1) {
          vhost_family = AF_INET6;
          v6->sin6_family = AF_INET6;
          v6->sin6_port = 0;
      } else {
          log_message(L_INFO, state, "[WARN] Invalid VHOST IP '%s'. Ignoring.\n", state->vhost);
      }
  }

  int sockfd = -1;
  for (int i = 0; ports_to_try[i] != NULL && sockfd == -1; i++) {
    log_message(L_INFO, state, "[INFO] Attempting to connect to %s:%s...\n",
                host, ports_to_try[i]);

    struct addrinfo hints, *res;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host, ports_to_try[i], &hints, &res) != 0) continue;

    for (struct addrinfo *p = res; p != NULL; p = p->ai_next) {

      if (vhost_family != AF_UNSPEC && p->ai_family != vhost_family) {
          continue;
      }

      if ((sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) < 0)
        continue;

      if (vhost_family != AF_UNSPEC) {
            socklen_t addr_len = (vhost_family == AF_INET) ? sizeof(struct sockaddr_in)
                                                           : sizeof(struct sockaddr_in6);

            if (bind(sockfd, (struct sockaddr*)&vhost_addr, addr_len) < 0) {
                log_message(L_INFO, state, "[WARN] Failed to bind VHOST %s: %s\n",
                            state->vhost, strerror(errno));
                close(sockfd);
                sockfd = -1;
                continue;
            }
      }

      // Set socket to non-blocking for connect timeout
      int flags = fcntl(sockfd, F_GETFL, 0);
      fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

      int conn_result = connect(sockfd, p->ai_addr, p->ai_addrlen);
      bool connected = false;

      if (conn_result == 0) {
        // Connected immediately (rare)
        connected = true;
      } else if (errno == EINPROGRESS) {
        // Connection in progress, wait with timeout
        fd_set writefds;
        struct timeval timeout;
        FD_ZERO(&writefds);
        FD_SET(sockfd, &writefds);
        timeout.tv_sec = 10;  // 10 second timeout
        timeout.tv_usec = 0;

        int select_result = select(sockfd + 1, NULL, &writefds, NULL, &timeout);
        if (select_result > 0) {
          // Check if connection succeeded
          int so_error;
          socklen_t len = sizeof(so_error);
          getsockopt(sockfd, SOL_SOCKET, SO_ERROR, &so_error, &len);
          if (so_error == 0) {
            connected = true;
          }
        } else if (select_result == 0) {
          log_message(L_INFO, state,
                      "[INFO] Connection timeout after 10 seconds.\n");
        }
      }

      if (connected) {
        // Set back to blocking mode
        fcntl(sockfd, F_SETFL, flags);

        // Try TLS if connecting to port 6697
        if (strcmp(ports_to_try[i], "6697") == 0) {
          state->ssl_ctx = SSL_CTX_new(TLS_client_method());
          if (!state->ssl_ctx) {
            close(sockfd);
            sockfd = -1;
            continue;
          }
          state->ssl = SSL_new(state->ssl_ctx);
          SSL_set_fd(state->ssl, sockfd);
          if (SSL_connect(state->ssl) == 1) {
            state->is_ssl = true;
            log_message(L_INFO, state,
                        "[INFO] Secure TLS connection established.\n");
          } else {
            log_message(L_INFO, state,
                        "[INFO] SSL handshake failed. Trying insecure.\n");
            SSL_free(state->ssl);
            state->ssl = NULL;
            SSL_CTX_free(state->ssl_ctx);
            state->ssl_ctx = NULL;
            close(sockfd);
            sockfd = -1;
          }
        } else {
          state->is_ssl = false;
          log_message(L_INFO, state,
                      "[INFO] Insecure connection established.\n");
        }
        break;
      }
      close(sockfd);
      sockfd = -1;
    }
    freeaddrinfo(res);
  }

  if (sockfd != -1) {
    state->server_fd = sockfd;
    state->status = S_CONNECTED;
    state->last_pong_time = time(NULL);
    state->connection_time = time(NULL);
    snprintf(state->current_nick, sizeof(state->current_nick), "%s",
             state->target_nick);
    irc_printf(state, "NICK %s\r\n", state->current_nick);
    irc_printf(state, "USER %s 0 * :%s\r\n", state->user, state->gecos);
  }
  state->current_server_index++;
}

void irc_handle_read(bot_state_t *state) {
  static char read_buffer[MAX_BUFFER * 2];
  static int buffer_len = 0;

  if (buffer_len >= (int)(sizeof(read_buffer) - 1)) {
      log_message(L_INFO, state, "[WARN] Receive buffer full (line too long). Flushing buffer.\n");
      buffer_len = 0;
  }

  ssize_t bytes_read;
  if (state->is_ssl) {
    bytes_read = SSL_read(state->ssl, read_buffer + buffer_len,
                          sizeof(read_buffer) - (size_t)buffer_len - 1);
    if (bytes_read <= 0) {
      int ssl_err = SSL_get_error(state->ssl, (int)bytes_read);
      if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) {
        if (ssl_err != SSL_ERROR_ZERO_RETURN) ERR_print_errors_fp(stderr);
        irc_disconnect(state);
        buffer_len = 0;
      }
      return;
    }
  } else {
    bytes_read = read(state->server_fd, read_buffer + buffer_len,
                      sizeof(read_buffer) - (size_t)buffer_len - 1);
    if (bytes_read <= 0) {
      if (bytes_read == 0 || (errno != EWOULDBLOCK && errno != EAGAIN &&
                               errno != EINTR)) {
        irc_disconnect(state);
        buffer_len = 0;
      }
      return;
    }
  }

  buffer_len += (int)bytes_read;
  read_buffer[buffer_len] = '\0';
  state->last_pong_time = time(NULL);

  char *line_start = read_buffer;
  char *line_end;

  while ((line_end = strstr(line_start, "\r\n")) != NULL) {
    *line_end = '\0';
    log_message(L_RAW, state, "[RAW_RECV] %s\n", line_start);
    parser_handle_line(state, line_start);
    line_start = line_end + 2;
  }

  int remaining = buffer_len - (int)(line_start - read_buffer);
  if (remaining < 0) remaining = 0;
  if (remaining > 0 && line_start != read_buffer) {
      memmove(read_buffer, line_start, remaining);
  }
  buffer_len = remaining;
  read_buffer[buffer_len] = '\0';
}

void irc_check_status(bot_state_t *state) {
  time_t now = time(NULL);

  // --- HUB WATCHDOG ---
  // Only monitor the hub connection if we aren't in standalone mode
  if (state->hub_count > 0 && state->hub_fd != -1 && state->hub_authenticated) {
    // If we haven't received a PONG or any encrypted data for 120 seconds,
    // the hub connection has likely "zombied" or the network path is dead.
    if (now - state->last_hub_activity > 120) {
      log_message(L_INFO, state, "[HUB] Connection timed out (Watchdog). Reconnecting...\n");
      
      close(state->hub_fd);
      state->hub_fd = -1;
      state->hub_connected = false;
      state->hub_authenticated = false;
      state->hub_connecting = false;
      // Note: the main loop's hub_client_connect() will handle the retry logic
    }
  }

  // --- IRC SERVER STATUS ---
  if (!(state->status & S_CONNECTED)) {
    /* Floor between attempts.  Without it a server that drops us before
     * registration is redialled every main-loop tick (~1 s) -- the pattern
     * that gets a host throttled and then Z-lined.  Per-server ban/throttle
     * holds are applied inside irc_connect(). */
    if (now - state->last_irc_attempt >= IRC_RECONNECT_MIN_INTERVAL)
      irc_connect(state);
    return;
  }

  if (now - state->last_pong_time > DEAD_SERVER_TIMEOUT) {
    log_message(L_INFO, state, "[INFO] Server timed out. Disconnecting.\n");
    irc_disconnect(state);
    return;
  }

  if (!state->pong_pending &&
      (now - state->last_pong_time > CHECK_LAG_TIMEOUT)) {
    irc_printf(state, "PING :%lld\r\n", (long long)now);
    state->pong_pending = true;
  }

  // --- NICK & CHANNEL MANAGEMENT ---
  if (state->status & S_AUTHED) {
    channel_manager_check_joins(state);
    
    if (!state->nick_change_pending) {
      if (strcasecmp(state->current_nick, state->target_nick) != 0) {
        if (now - state->nick_release_time > NICK_TAKE_TIME) {
          if (now - state->last_nick_attempt > NICK_RETRY_TIME) {
            log_message(L_INFO, state,
                        "[INFO] Attempting to reclaim primary nick '%s'.\n",
                        state->target_nick);
            irc_attempt_nick_change(state, state->target_nick);
          }
        } else {
          log_message(L_INFO, state,
                      "[INFO] Nick reclaim on hold. %lld seconds remaining.\n",
                      (long long)(NICK_TAKE_TIME - (now - state->nick_release_time)));
        }
      }
    } else {
      log_message(L_INFO, state,
                  "[INFO] Nick reclaim skipped: nick change pending.\n");
    }
  }
}

void irc_attempt_nick_change(bot_state_t *state, const char *new_nick) {
  log_message(L_DEBUG, state, "[DEBUG] Attemping NICK to %s\n", new_nick);
  irc_printf(state, "NICK %s\r\n", new_nick);
  state->last_nick_attempt = time(NULL);
}

void irc_generate_new_nick(bot_state_t *state) {
  const char nick_append_chars[] = "_`^";
  const int num_special_chars = sizeof(nick_append_chars) - 1;
  char new_nick[MAX_NICK];
  int attempt = state->nick_generation_attempt;

  char base_nick[9];
  size_t base_len = strlen(state->target_nick);
  if (base_len >= sizeof(base_nick)) base_len = sizeof(base_nick) - 1;
  memcpy(base_nick, state->target_nick, base_len);
  base_nick[base_len] = '\0';

  if (attempt < num_special_chars) {
    snprintf(new_nick, MAX_NICK, "%s%c", base_nick, nick_append_chars[attempt]);
  } else {
    int numeric_attempt = attempt - num_special_chars;
    if (numeric_attempt < 10) {
      snprintf(new_nick, MAX_NICK, "%s%d", base_nick, numeric_attempt);
    } else {
      state->nick_generation_attempt = 0;
      return;
    }
  }
  snprintf(state->current_nick, sizeof(state->current_nick), "%s", new_nick);
  state->nick_generation_attempt++;
  irc_attempt_nick_change(state, new_nick);
}
