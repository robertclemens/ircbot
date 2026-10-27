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

#include <openssl/x509v3.h>

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

/* Bytes of an incomplete line, kept between reads of one connection.  File
 * scope so irc_disconnect can drop them: kept across a reconnect (a ping
 * timeout), a fragment was glued onto the next server's first line. */
static char read_buffer[MAX_BUFFER * 2];
static int buffer_len = 0;

void irc_disconnect(bot_state_t *state) {
  irc_dial_abort(state); /* a dial in flight goes with it */
  buffer_len = 0;
  read_buffer[0] = '\0';
  state->overlong_nick[0] = '\0';
  state->overlong_since = 0;
  /* Last chance for queued lines (a parting PRIVMSG, a restart notice) to go
   * out on whatever credit is left; a write error here already disconnected. */
  if ((state->status & S_CONNECTED) && state->server_fd != -1) {
    sendq_drain(state);
    if (!(state->status & S_CONNECTED) && state->server_fd == -1)
      return;
  }
  irc_apply_refusal(state);
  // Send QUIT first so the server removes the nick immediately.
  // Without this, NAT holds the TCP state and the nick ghosts until ping-timeout.
  if ((state->status & S_CONNECTED) && state->server_fd != -1) {
    const char *quit_msg = "QUIT :bye\r\n";
    if (state->is_ssl && state->ssl) {
      SSL_write(state->ssl, quit_msg, (int)strlen(quit_msg));
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
  sendq_clear(state);
  isupport_reset(state);
  channel_list_reset_status(state);
}

/* True if buf[0..len) is exactly one IRC line: it ends in the "\r\n" every
 * irc_printf format carries, with no CR, LF or NUL anywhere before that. */
static bool irc_is_single_line(const char *buf, int len) {
  if (len < 2 || buf[len - 2] != '\r' || buf[len - 1] != '\n')
    return false;
  for (int i = 0; i < len - 2; i++)
    if (buf[i] == '\r' || buf[i] == '\n' || buf[i] == '\0')
      return false;
  return true;
}

#define A2R_NOT_A_REPLY (-2)
static int a2r_seal_reply(bot_state_t *state, const char *line, int len);
static int irc_send_line(bot_state_t *state, const char *buffer, int len);

int irc_printf(bot_state_t *state, const char *format, ...) {
  if (!(state->status & S_CONNECTED) && !state->dcc_reply) return -1;
  char buffer[MAX_BUFFER];
  va_list args;
  va_start(args, format);
  int len = vsnprintf(buffer, sizeof(buffer), format, args);
  va_end(args);
  if (len < 0) return -1;
  /* One command per call, always.  Commands are filtered where they arrive;
   * this is the backstop for every other value that reaches a format (hub
   * data, config, getlog replays).  A line vsnprintf had to truncate has lost
   * its terminator, so it is refused too rather than sent half-formed. */
  if (len >= (int)sizeof(buffer) || !irc_is_single_line(buffer, len)) {
    int verb = (int)strcspn(buffer, " \r\n");
    log_message(L_INFO, state,
                "[IRC] Refused to send %.*s line: embedded line break or no "
                "terminator\n", verb > 16 ? 16 : verb, buffer);
    return -1;
  }
  if (state->a2r.active) {
    int r = a2r_seal_reply(state, buffer, len);
    if (r != A2R_NOT_A_REPLY) {
      /* the reply went out sealed: its plaintext is not left on the stack
       * (review 2026-10-25 L1) */
      secure_wipe(buffer, (size_t)len);
      return r;
    }
  }
  return irc_send_line(state, buffer, len);
}

/* While a ~A2S command runs (state->a2r), its replies -- "PRIVMSG <asker>
 * :<text>" or NOTICE -- leave as ~A2R frames: "<seq>:<more>:<text>" sealed
 * under the command's reply key, the text cut into A2R_TEXT_MAX-byte pieces
 * (not inside a UTF-8 sequence) with more = 1 on all but the last.  CTCP
 * stays plain: the DCC offer has to reach the client's own DCC code.  If a
 * piece cannot be sealed the rest of the reply is dropped, never sent plain.
 * Returns A2R_NOT_A_REPLY for any other line, else the last send's result. */
static int a2r_seal_reply(bot_state_t *state, const char *line, int len) {
  const char *verb = strncmp(line, "PRIVMSG ", 8) == 0  ? "PRIVMSG"
                     : strncmp(line, "NOTICE ", 7) == 0 ? "NOTICE"
                                                         : NULL;
  if (!verb) return A2R_NOT_A_REPLY;
  size_t vl = strlen(verb) + 1, nl = strlen(state->a2r.nick);
  size_t head = vl + nl + 2; /* "VERB " nick " :" */
  if ((size_t)len < head + 2 || memcmp(line + vl, state->a2r.nick, nl) != 0 ||
      memcmp(line + vl + nl, " :", 2) != 0)
    return A2R_NOT_A_REPLY;
  const char *text = line + head;
  size_t tlen = (size_t)len - head - 2; /* without the "\r\n" */
  if (tlen > 0 && text[0] == '\001') return A2R_NOT_A_REPLY;

  int ret = -1;
  size_t off = 0;
  do {
    size_t cut = tlen - off;
    if (cut > A2R_TEXT_MAX) {
      cut = A2R_TEXT_MAX;
      while (cut > 1 && ((unsigned char)text[off + cut] & 0xC0) == 0x80)
        cut--;
    }
    unsigned char pt[A2R_PT_MAX], frame[A2R_PT_MAX + A2R_OVERHEAD];
    int hl = snprintf((char *)pt, sizeof(pt), "%lu:%d:", state->a2r.seq,
                      off + cut < tlen ? 1 : 0);
    int fl = -1;
    if (hl > 0 && (size_t)hl + cut <= sizeof(pt)) {
      memcpy(pt + hl, text + off, cut);
      fl = crypto_reply_seal(state->a2r.key, state->a2r.aad, state->a2r.aad_len,
                             pt, (size_t)hl + cut, frame, sizeof(frame));
    }
    secure_wipe(pt, sizeof(pt));
    char *b64 = fl > 0 ? base64_encode(frame, fl) : NULL;
    if (!b64) {
      log_message(L_INFO, state, "[CMD] Could not seal a reply to %s; the rest "
                                 "of it is dropped\n", state->a2r.nick);
      return -1;
    }
    char out[640];
    int ol = snprintf(out, sizeof(out), "%s %s :~A2R %s\r\n", verb,
                      state->a2r.nick, b64);
    free(b64);
    if (ol <= 0 || ol >= (int)sizeof(out)) return -1;
    ret = irc_send_line(state, out, ol);
    if (ret < 0) return ret; /* link gone: the rest could not be sent either */
    state->a2r.seq++;
    off += cut;
  } while (off < tlen);
  return ret;
}

/* True when a finished IRC line's command is PING or PONG -- the keepalive
 * chatter HIDEPINGPONG keeps out of the RAW log.  Handles both directions:
 * our own "PING :<token>" and a server's prefixed ":irc.example.net PONG ...".
 * A CTCP PING rides inside PRIVMSG, so it is never matched here. */
static bool irc_line_is_keepalive(const char *line) {
  if (!line) return false;
  while (*line == ' ') line++;
  if (*line == ':') { /* skip a ":prefix " source */
    while (*line && *line != ' ') line++;
    while (*line == ' ') line++;
  }
  if (strncasecmp(line, "PING", 4) != 0 && strncasecmp(line, "PONG", 4) != 0)
    return false;
  /* Exact verb only, so a command merely starting with those letters stays
   * logged. */
  return line[4] == ' ' || line[4] == ':' || line[4] == '\r' ||
         line[4] == '\0';
}

/* One finished line to the server -- or down a DCC chat, for a reply to a
 * command that came from one (dcc_divert_reply), even while the IRC link is
 * down. */
static int irc_send_line(bot_state_t *state, const char *buffer, int len) {
  if (dcc_divert_reply(state, buffer, len)) return len;
  if (!(state->status & S_CONNECTED)) return -1;
  return sendq_enqueue(state, buffer, len);
}

/* The write itself, for a line the send queue has decided may go now.  A
 * write error drops the link (which also empties the queue). */
int irc_write_raw(bot_state_t *state, const char *buffer, int len) {
  if (!(state->status & S_CONNECTED)) return -1;
  if (!HIDEPINGPONG || !irc_line_is_keepalive(buffer))
    log_raw(state, "[RAW_SEND] ", buffer);
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
                           (size_t)(len - total_sent));
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

/* Review 16: the IRC dial in flight.  irc_connect picks the server and
 * starts it: each address of each port (the configured one, else 6667 then
 * 6697 with TLS) gets a non-blocking connect, and a TLS port then a
 * non-blocking handshake, both driven from the main loop (irc_dial_fill_fds,
 * irc_dial_process) and bounded per step (irc_dial_tick: 10 s a connect, 15 s TLS).
 * The blocking connect froze the bot up to 10 s per dead address, and the
 * blocking SSL_connect had no bound at all.  server_fd stays -1 until the
 * link is up, so nothing else sees a half-open one.  (Name resolution is
 * still getaddrinfo, which blocks.) */
#define IRC_DIAL_TIMEOUT 10 /* the connect, per address */
#define IRC_TLS_TIMEOUT 15  /* the TLS handshake (the Rust bot's bound too) */
static struct {
  int fd;                    /* -1: no dial in flight */
  bool tls;                  /* in the TLS handshake (else the connect) */
  bool want_read;            /* the handshake waits for input, else output */
  bool have_cas;             /* CA certificates were loaded for the check */
  time_t started;            /* of the current step */
  int flags;                 /* fcntl flags before O_NONBLOCK */
  char host[256];
  char port_cfg[16];
  const char *ports[3];
  int port_idx;
  struct addrinfo *res, *ai; /* the port's addresses, the next to try */
  struct sockaddr_storage vhost;
  int vhost_family;
} g_dial = {.fd = -1};

static void dial_connected(bot_state_t *state);
static void dial_tls_step(bot_state_t *state);
static void dial_up(bot_state_t *state, bool tls);

/* Close the address in flight (and its half-done TLS session). */
static void dial_drop(bot_state_t *state) {
  if (g_dial.tls) {
    SSL_free(state->ssl);
    state->ssl = NULL;
    SSL_CTX_free(state->ssl_ctx);
    state->ssl_ctx = NULL;
  }
  if (g_dial.fd >= 0) close(g_dial.fd);
  g_dial.fd = -1;
  g_dial.tls = false;
}

/* Start a connect to the next address that takes one, resolving the next
 * port when this one's run out; nothing left: the attempt is over. */
static void dial_next(bot_state_t *state) {
  for (;;) {
    while (g_dial.ai) {
      struct addrinfo *p = g_dial.ai;
      g_dial.ai = p->ai_next;
      if (g_dial.vhost_family != AF_UNSPEC && p->ai_family != g_dial.vhost_family)
        continue;
      int sockfd = socket(p->ai_family, p->ai_socktype, p->ai_protocol);
      if (sockfd < 0) continue;
      if (g_dial.vhost_family != AF_UNSPEC) {
        socklen_t addr_len = (g_dial.vhost_family == AF_INET) ? sizeof(struct sockaddr_in)
                                                              : sizeof(struct sockaddr_in6);
        if (bind(sockfd, (struct sockaddr *)&g_dial.vhost, addr_len) < 0) {
          log_message(L_INFO, state, "[WARN] Failed to bind VHOST %s: %s\n",
                      state->vhost, strerror(errno));
          close(sockfd);
          continue;
        }
      }
      g_dial.flags = fcntl(sockfd, F_GETFL, 0);
      if (g_dial.flags < 0 || fcntl(sockfd, F_SETFL, g_dial.flags | O_NONBLOCK) < 0) {
        close(sockfd);
        continue;
      }
      int r = connect(sockfd, p->ai_addr, p->ai_addrlen);
      if (r == 0 || errno == EINPROGRESS) {
        g_dial.fd = sockfd;
        g_dial.tls = false;
        g_dial.started = time(NULL);
        if (r == 0) dial_connected(state); /* connected at once (rare) */
        return;
      }
      close(sockfd);
    }
    if (g_dial.res) freeaddrinfo(g_dial.res);
    g_dial.res = NULL;
    if (++g_dial.port_idx >= 3 || !g_dial.ports[g_dial.port_idx]) return;
    log_message(L_INFO, state, "[INFO] Attempting to connect to %s:%s...\n",
                g_dial.host, g_dial.ports[g_dial.port_idx]);
    struct addrinfo hints;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    if (getaddrinfo(g_dial.host, g_dial.ports[g_dial.port_idx], &hints, &g_dial.res) != 0)
      g_dial.res = NULL;
    g_dial.ai = g_dial.res;
  }
}

void irc_connect(bot_state_t *state) {
  if (state->server_fd != -1 || g_dial.fd >= 0) return;
  time_t attempt_now = time(NULL);
  int pick = irc_pick_server(state, attempt_now);
  if (pick < 0) return; /* everything held; irc_pick_server logged why */
  state->current_server_index = pick;
  state->irc_server_idx = pick;
  state->last_irc_attempt = attempt_now;
  state->irc_refusal[0] = '\0';
  state->irc_refusal_ban = false;
  state->nick_refused[0] = '\0'; /* another server may take the target nick */

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
  memset(g_dial.ports, 0, sizeof(g_dial.ports));
  if (port_from_config) {
    snprintf(g_dial.port_cfg, sizeof(g_dial.port_cfg), "%s", port_from_config);
    g_dial.ports[0] = g_dial.port_cfg;
  } else {
    g_dial.ports[0] = "6667";
    g_dial.ports[1] = "6697";
  }
  snprintf(g_dial.host, sizeof(g_dial.host), "%s", host);

  g_dial.vhost_family = AF_UNSPEC;
  memset(&g_dial.vhost, 0, sizeof(g_dial.vhost));
  if (state->vhost[0] != '\0' && strcasecmp(state->vhost, "NULL") != 0) {
      struct sockaddr_in *v4 = (struct sockaddr_in *)&g_dial.vhost;
      struct sockaddr_in6 *v6 = (struct sockaddr_in6 *)&g_dial.vhost;

      if (inet_pton(AF_INET, state->vhost, &v4->sin_addr) == 1) {
          g_dial.vhost_family = AF_INET;
          v4->sin_family = AF_INET;
          v4->sin_port = 0;
      } else if (inet_pton(AF_INET6, state->vhost, &v6->sin6_addr) == 1) {
          g_dial.vhost_family = AF_INET6;
          v6->sin6_family = AF_INET6;
          v6->sin6_port = 0;
      } else {
          log_message(L_INFO, state, "[WARN] Invalid VHOST IP '%s'. Ignoring.\n", state->vhost);
      }
  }

  g_dial.port_idx = -1;
  g_dial.res = g_dial.ai = NULL;
  dial_next(state);
  state->current_server_index++;
}

/* Review 9: the CA certificates the server's chain is checked against:
 * OpenSSL's own default locations, and the first bundle found at the usual
 * paths (a static build does not know the host's layout).  False when none
 * could be loaded -- every server then reads as unverified. */
static bool tls_load_cas(SSL_CTX *ctx) {
  static const char *const bundles[] = {
      "/etc/ssl/certs/ca-certificates.crt", /* Debian, Ubuntu, Alpine */
      "/etc/pki/tls/certs/ca-bundle.crt",   /* RHEL, Rocky, Fedora */
      "/etc/ssl/ca-bundle.pem",             /* openSUSE */
      "/etc/ssl/cert.pem",                  /* BSDs, macOS, Alpine */
  };
  SSL_CTX_set_default_verify_paths(ctx);
  for (size_t i = 0; i < sizeof(bundles) / sizeof(bundles[0]); i++)
    if (access(bundles[i], R_OK) == 0 && SSL_CTX_load_verify_locations(ctx, bundles[i], NULL) == 1)
      break;
  ERR_clear_error(); /* a missing default path is not this link's error */
  return sk_X509_OBJECT_num(X509_STORE_get0_objects(SSL_CTX_get_cert_store(ctx))) > 0;
}

/* Review 9: the handshake is done; was the certificate good?  The chain was
 * checked with SSL_VERIFY_NONE, so a failure is only recorded: the link stays
 * up (IRC networks run self-signed certificates) and the log and `status`
 * say so. */
static void tls_check_result(bot_state_t *state, bool have_cas) {
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
  X509 *cert = SSL_get1_peer_certificate(state->ssl);
#else
  X509 *cert = SSL_get_peer_certificate(state->ssl);
#endif
  long vr = SSL_get_verify_result(state->ssl);
  state->irc_tls_verified = cert && vr == X509_V_OK;
  snprintf(state->irc_tls_why, sizeof(state->irc_tls_why), "%s",
           !cert ? "no certificate" : !have_cas ? "no CA certificates on this host"
                                                : X509_verify_cert_error_string(vr));
  X509_free(cert);
  if (state->irc_tls_verified)
    log_message(L_INFO, state, "[INFO] TLS certificate of %s verified.\n", g_dial.host);
  else
    log_message(L_INFO, state,
                "[WARN] TLS certificate of %s NOT verified (%s): the link is encrypted, "
                "but the server's identity is unchecked.\n",
                g_dial.host, state->irc_tls_why);
}

/* The connect finished: a TLS port starts its handshake, any other is up. */
static void dial_connected(bot_state_t *state) {
  if (strcmp(g_dial.ports[g_dial.port_idx], "6697") != 0) {
    dial_up(state, false);
    return;
  }
  state->ssl_ctx = SSL_CTX_new(TLS_client_method());
  if (state->ssl_ctx) {
    SSL_CTX_set_verify(state->ssl_ctx, SSL_VERIFY_NONE, NULL); /* checked, not enforced */
    g_dial.have_cas = tls_load_cas(state->ssl_ctx);
  }
  state->ssl = state->ssl_ctx ? SSL_new(state->ssl_ctx) : NULL;
  if (state->ssl) {
    /* the name the certificate must carry: an address literal as an IP SAN,
     * else a host name (sent as SNI too) */
    unsigned char ipbuf[16];
    bool is_ip = inet_pton(AF_INET, g_dial.host, ipbuf) == 1 ||
                 inet_pton(AF_INET6, g_dial.host, ipbuf) == 1;
    if (is_ip) {
      X509_VERIFY_PARAM_set1_ip_asc(SSL_get0_param(state->ssl), g_dial.host);
    } else {
      SSL_set_tlsext_host_name(state->ssl, g_dial.host);
      SSL_set1_host(state->ssl, g_dial.host);
    }
  }
  if (!state->ssl || SSL_set_fd(state->ssl, g_dial.fd) != 1) {
    g_dial.tls = true; /* so dial_drop frees what was made */
    dial_drop(state);
    g_dial.ai = NULL; /* as before: a failed TLS port is not tried further */
    dial_next(state);
    return;
  }
  g_dial.tls = true;
  g_dial.started = time(NULL);
  dial_tls_step(state);
}

/* One non-blocking step of the TLS handshake. */
static void dial_tls_step(bot_state_t *state) {
  int r = SSL_connect(state->ssl);
  if (r == 1) {
    log_message(L_INFO, state, "[INFO] Secure TLS connection established.\n");
    tls_check_result(state, g_dial.have_cas);
    dial_up(state, true);
    return;
  }
  int err = SSL_get_error(state->ssl, r);
  if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
    g_dial.want_read = err == SSL_ERROR_WANT_READ;
    return;
  }
  log_message(L_INFO, state, "[INFO] SSL handshake failed. Trying insecure.\n");
  dial_drop(state);
  g_dial.ai = NULL; /* as before: a failed TLS port is not tried further */
  dial_next(state);
}

/* Up: back to a blocking socket (the reads and writes are as before) and
 * the registration goes out. */
static void dial_up(bot_state_t *state, bool tls) {
  int sockfd = g_dial.fd;
  fcntl(sockfd, F_SETFL, g_dial.flags);
  g_dial.fd = -1;
  g_dial.tls = false;
  if (g_dial.res) freeaddrinfo(g_dial.res);
  g_dial.res = g_dial.ai = NULL;
  state->is_ssl = tls;
  if (!tls) {
    state->irc_tls_verified = false;
    state->irc_tls_why[0] = '\0';
    log_message(L_INFO, state, "[INFO] Insecure connection established.\n");
  }

  state->server_fd = sockfd;
  sendq_clear(state); /* new link: empty queue, full burst */
  isupport_reset(state);
  state->status = S_CONNECTED;
  state->last_pong_time = time(NULL);
  state->pong_pending = false;
  state->connection_time = time(NULL);
  snprintf(state->current_nick, sizeof(state->current_nick), "%s",
           state->target_nick);
  irc_printf(state, "NICK %s\r\n", state->current_nick);
  irc_printf(state, "USER %s 0 * :%s\r\n", state->user, state->gecos);
}

void irc_dial_fill_fds(bot_state_t *state, fd_set *rfds, fd_set *wfds, int *max_fd) {
  (void)state;
  if (g_dial.fd < 0) return;
  FD_SET(g_dial.fd, g_dial.tls && g_dial.want_read ? rfds : wfds);
  if (g_dial.fd > *max_fd) *max_fd = g_dial.fd;
}

void irc_dial_process(bot_state_t *state, const fd_set *rfds, const fd_set *wfds) {
  if (g_dial.fd < 0 || !(fd_isset(g_dial.fd, rfds) || fd_isset(g_dial.fd, wfds))) return;
  if (g_dial.tls) {
    dial_tls_step(state);
    return;
  }
  int err = 0;
  socklen_t el = sizeof(err);
  if (getsockopt(g_dial.fd, SOL_SOCKET, SO_ERROR, &err, &el) != 0) err = errno;
  if (err == 0) {
    dial_connected(state);
  } else {
    dial_drop(state);
    dial_next(state);
  }
}

/* A step that has not finished in its bound: on to the next address. */
void irc_dial_tick(bot_state_t *state) {
  int bound = g_dial.tls ? IRC_TLS_TIMEOUT : IRC_DIAL_TIMEOUT;
  if (g_dial.fd < 0 || time(NULL) - g_dial.started <= bound) return;
  log_message(L_INFO, state, g_dial.tls ? "[INFO] TLS handshake timeout after %d seconds.\n"
                                        : "[INFO] Connection timeout after %d seconds.\n",
              bound);
  if (g_dial.tls) g_dial.ai = NULL; /* a TLS port that stalls, as one that fails */
  dial_drop(state);
  dial_next(state);
}

bool irc_dialing(const bot_state_t *state) {
  (void)state;
  return g_dial.fd >= 0;
}

/* Give the dial up entirely (a disconnect, a server change, shutdown). */
void irc_dial_abort(bot_state_t *state) {
  dial_drop(state);
  if (g_dial.res) freeaddrinfo(g_dial.res);
  g_dial.res = g_dial.ai = NULL;
}

void irc_handle_read(bot_state_t *state) {
  if (buffer_len >= (int)(sizeof(read_buffer) - 1)) {
      log_message(L_INFO, state, "[WARN] Receive buffer full (line too long). Flushing buffer.\n");
      buffer_len = 0;
  }

  ssize_t bytes_read;
  if (state->is_ssl) {
    bytes_read = SSL_read(state->ssl, read_buffer + buffer_len,
                          (int)(sizeof(read_buffer) - (size_t)buffer_len - 1));
    if (bytes_read <= 0) {
      int ssl_err = SSL_get_error(state->ssl, (int)bytes_read);
      if (ssl_err != SSL_ERROR_WANT_READ && ssl_err != SSL_ERROR_WANT_WRITE) {
        if (ssl_err != SSL_ERROR_ZERO_RETURN) ERR_print_errors_fp(stderr);
        irc_disconnect(state);
      }
      return;
    }
  } else {
    bytes_read = read(state->server_fd, read_buffer + buffer_len,
                      sizeof(read_buffer) - (size_t)buffer_len - 1);
    if (bytes_read <= 0) {
      if (bytes_read == 0 || (!IO_WOULD_BLOCK(errno) && errno != EINTR)) {
        irc_disconnect(state);
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
    if (!HIDEPINGPONG || !irc_line_is_keepalive(line_start))
      log_raw(state, "[RAW_RECV] ", line_start);
    parser_handle_line(state, line_start);
    line_start = line_end + 2;
  }

  int remaining = buffer_len - (int)(line_start - read_buffer);
  if (remaining < 0) remaining = 0;
  if (remaining > 0 && line_start != read_buffer) {
      memmove(read_buffer, line_start, (size_t)remaining);
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
      /* the full teardown (session key wiped, auth state reset), keeping the
       * retry timing the watchdog always had */
      time_t last_attempt = state->last_hub_connect_attempt;
      hub_client_disconnect(state);
      state->last_hub_connect_attempt = last_attempt;
      // Note: the main loop's hub_client_connect() will handle the retry logic
    }
  } else if (state->hub_count > 0 && state->hub_fd != -1 && !state->hub_authenticated &&
             now - state->last_hub_connect_attempt > HUB_AUTH_TIMEOUT &&
             !hub_client_data_waiting(state)) {
    log_message(L_INFO, state, "[HUB] Handshake not finished in %d s — dropping the link\n",
                HUB_AUTH_TIMEOUT);
    hub_client_disconnect(state);
  }

  // --- IRC SERVER STATUS ---
  if (!(state->status & S_CONNECTED)) {
    /* Floor between attempts.  Without it a server that drops us before
     * registration is redialled every main-loop tick (~1 s) -- the pattern
     * that gets a host throttled and then Z-lined.  Per-server ban/throttle
     * holds are applied inside irc_connect(). */
    irc_dial_tick(state);
    if (!irc_dialing(state) && now - state->last_irc_attempt >= IRC_RECONNECT_MIN_INTERVAL)
      irc_connect(state);
    return;
  }

  /* Registration watchdog.  Any received byte refreshes last_pong_time, and
   * a server answers an unregistered client's PING (451 or PONG), so without
   * this a link that never reaches 001 is held open forever, off IRC. */
  if (!(state->status & S_AUTHED) &&
      now - state->connection_time > IRC_REGISTER_TIMEOUT) {
    log_message(L_INFO, state,
                "[INFO] No registration (001) after %d seconds. "
                "Disconnecting.\n", IRC_REGISTER_TIMEOUT);
    irc_disconnect(state);
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
  if ((state->status & S_AUTHED) && state->overlong_since &&
      now - state->overlong_since > NICK_OVERLONG_TIMEOUT) {
    log_message(L_INFO, state,
                "[INFO] Still under %s (over %d characters) after %ds: reconnecting\n",
                state->overlong_nick, MAX_NICK - 1, NICK_OVERLONG_TIMEOUT);
    irc_disconnect(state);
    return;
  }
  if (state->status & S_AUTHED) {
    channel_manager_check_joins(state);
    
    if (!state->nick_change_pending) {
      if (strcasecmp(state->current_nick, state->target_nick) != 0 &&
          strcasecmp(state->nick_refused, state->target_nick) != 0) {
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

/* Review 10b: the server put us under `nick`, over the 9 bytes a bot nick may
 * be (a long 001, a services rename to Guest123456).  Nothing longer is
 * stored or sent to the hub: the bot renames itself back to its target now,
 * and with current_nick empty the reclaim in irc_check_status keeps trying;
 * a refused target falls back to the 9-byte alternates (the 433 handler).
 * Still over 9 after NICK_OVERLONG_TIMEOUT, it reconnects. */
void irc_nick_overlong(bot_state_t *state, const char *nick) {
  if (!state->overlong_since) state->overlong_since = time(NULL);
  snprintf(state->overlong_nick, sizeof(state->overlong_nick), "%s", nick);
  state->current_nick[0] = '\0';
  log_message(L_INFO, state,
              "[INFO] Server put me under %s, over %d characters: renaming back to %s\n",
              state->overlong_nick, MAX_NICK - 1, state->target_nick);
  irc_attempt_nick_change(state, state->target_nick);
}

void irc_generate_new_nick(bot_state_t *state) {
  const char nick_append_chars[] = "_`^";
  const int num_special_chars = sizeof(nick_append_chars) - 1;
  char new_nick[MAX_NICK];
  int attempt = state->nick_generation_attempt;

  /* Alternates are the target cut to 8 characters plus one suffix.  A target
   * no ircd accepts (a nick loaded from an old config) would make every
   * alternate fail the same way, so only its RFC 2812 characters are kept,
   * and "bot" stands in if none can lead. */
  char base_nick[9];
  size_t base_len = 0;
  for (const char *p = state->target_nick;
       *p && base_len < sizeof(base_nick) - 1; p++) {
    char one[2] = {*p, '\0'};
    char probe[3] = {'a', *p, '\0'};
    if (base_len == 0 ? is_rfc_nick(one) : is_rfc_nick(probe))
      base_nick[base_len++] = *p;
  }
  base_nick[base_len] = '\0';
  if (base_len == 0)
    snprintf(base_nick, sizeof(base_nick), "bot");

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
