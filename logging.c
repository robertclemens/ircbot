#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "bot.h"

/* LOGFILE, kept open across lines; dev/ino say which file it is. */
static int g_log_fd = -1;
static dev_t g_log_dev;
static ino_t g_log_ino;

static int get_log_index(log_type_t flag) {
  switch (flag) {
    case L_MSG:
      return 0;
    case L_CTCP:
      return 1;
    case L_INFO:
      return 2;
    case L_CMD:
      return 3;
    case L_RAW:
      return 4;
    case L_DEBUG:
      return 5;
    default:
      return -1;
  }
}

/* Callers end their format strings with "\n"; strip it so the trailing
 * newline is added exactly once here (and never lands in the ring buffer,
 * where an embedded newline would split the PRIVMSG the .log command sends).
 * Any control byte left is part of logged data (hub- or IRC-supplied
 * strings), not layout: shown as '?', a CR/LF can't forge a second entry or
 * split `getlog`'s PRIVMSG, and ESC can't drive a reader's terminal. */
static void log_clean(char *s) {
  for (size_t i = strlen(s); i > 0; i--) {
    if (s[i - 1] != '\n' && s[i - 1] != '\r') break;
    s[i - 1] = '\0';
  }
  for (char *p = s; *p != '\0'; p++)
    if ((unsigned char)*p < 0x20 || *p == 0x7f)
      *p = '?';
}

/* One entry: `ring` goes to the in-memory ring (getlog), `file` -- the same
 * line, or a masked copy of it -- to LOGFILE. */
static void log_write(log_type_t flag, const bot_state_t *state, char *ring,
                      char *file) {
  char time_buf[32];
  time_t now = time(NULL);
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
  log_clean(ring);
  if (file != ring) log_clean(file);

  char full_log_line[MAX_LOG_LINE_LEN];
  snprintf(full_log_line, sizeof(full_log_line), "[%s] %s", time_buf, ring);

  /* The log ring is the one part of state every logger writes, including
   * callers holding only a const view (the state itself is never const); the
   * union drops the qualifier without a cast. */
  union { const bot_state_t *ro; bot_state_t *rw; } su = { .ro = state };
  bot_state_t *mutable_state = su.rw;

  int buffer_index = get_log_index(flag);
  if (buffer_index != -1) {
    log_buffer_t *buffer = &mutable_state->in_memory_logs[buffer_index];

    snprintf(buffer->entries[buffer->log_idx].line, MAX_LOG_LINE_LEN, "%s",
             full_log_line);

    buffer->log_idx = (buffer->log_idx + 1) % LOG_BUFFER_LINES;
  }

  if (!(state->log_type & flag)) {
    return;
  }

  if (file != ring)
    snprintf(full_log_line, sizeof(full_log_line), "[%s] %s", time_buf, file);

#ifdef DEBUG
  printf("%s\n", full_log_line);
#endif

  /* LOGFILE stays open between lines (it was opened, fdopen'd and closed for
   * every one).  The stat each line needs for the size cap also says whether
   * the open file is still LOGFILE -- removed, replaced, or a chdir into the
   * instance dir since -- and if not it is opened again. */
  struct stat log_stat;
  bool have_stat = stat(LOGFILE, &log_stat) == 0;
  if (g_log_fd >= 0 &&
      (!have_stat || log_stat.st_dev != g_log_dev || log_stat.st_ino != g_log_ino)) {
    close(g_log_fd);
    g_log_fd = -1;
  }
  if (g_log_fd < 0) {
    g_log_fd = open(LOGFILE, O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0600);
    if (g_log_fd < 0 || fstat(g_log_fd, &log_stat) != 0) {
      perror("Failed to open log file");
      if (g_log_fd >= 0) close(g_log_fd);
      g_log_fd = -1;
      return;
    }
    have_stat = true;
    g_log_dev = log_stat.st_dev;
    g_log_ino = log_stat.st_ino;
  }

  /* Enforce the size cap (L|, else BOT_LOG_FILE_SIZE) before appending:
   * past it the file is truncated rather than allowed to grow without bound,
   * and this line is then written after the truncation notice (O_APPEND puts
   * both at the new end). */
  long cap = state->log_max_size > 0 ? state->log_max_size : BOT_LOG_FILE_SIZE;
  if (have_stat && log_stat.st_size >= (off_t)cap && ftruncate(g_log_fd, 0) == 0)
    dprintf(g_log_fd, "[%s] Log file truncated (size limit reached)\n", time_buf);
  dprintf(g_log_fd, "%s\n", full_log_line);
}

void log_message(log_type_t flag, const bot_state_t *state, const char *format,
                 ...) {
  char base_message[MAX_LOG_LINE_LEN - 40];
  va_list args;
  va_start(args, format);
  vsnprintf(base_message, sizeof(base_message), format, args);
  va_end(args);
  log_write(flag, state, base_message, base_message);
}

/* Where a PRIVMSG / NOTICE text quotes a raw log line (a getlog raw reply):
 * just past its "[RAW_SEND] " / "[RAW_RECV] " tag, or NULL. */
static const char *raw_quote(const char *line) {
  const char *a = strstr(line, "[RAW_SEND] "), *b = strstr(line, "[RAW_RECV] ");
  const char *q = a && (!b || a < b) ? a : b;
  return q ? q + 11 : NULL;
}

/* Channel keys in a raw IRC line, masked: the key list of a JOIN and the
 * argument of each k in a MODE or a 324 (RPL_CHANNELMODEIS), found with the
 * server's ISUPPORT argument table so "+lk 20 key" masks the right one, and
 * the same in a raw line a PRIVMSG / NOTICE quotes (the bot's own getlog raw
 * reply, which would otherwise write the ring's keys into the file).
 * Everything else is copied as is. */
static void mask_line(const bot_state_t *state, const char *line, char *out, size_t cap,
                      int depth) {
  char buf[MAX_LOG_LINE_LEN];
  snprintf(buf, sizeof(buf), "%s", line);
  char *tok[64];
  int n = 0;
  for (char *p = buf; *p && n < 64;) {
    while (*p == ' ') *p++ = '\0';
    if (!*p) break;
    tok[n++] = p;
    while (*p && *p != ' ') p++;
  }
  bool mask[64] = {false};
  int i = n > 0 && tok[0][0] == ':' ? 1 : 0;
  const char *q;
  if (i < n && depth < 3 &&
      (strcasecmp(tok[i], "PRIVMSG") == 0 || strcasecmp(tok[i], "NOTICE") == 0) &&
      (q = raw_quote(line)) != NULL) {
    size_t pre = (size_t)(q - line) < cap ? (size_t)(q - line) : cap - 1;
    memcpy(out, line, pre);
    out[pre] = '\0';
    mask_line(state, q, out + pre, cap - pre, depth + 1);
    secure_wipe(buf, sizeof(buf));
    return;
  }
  if (i < n && strcasecmp(tok[i], "JOIN") == 0) {
    if (i + 2 < n) mask[i + 2] = true;
  } else if (i < n && (strcasecmp(tok[i], "MODE") == 0 || strcmp(tok[i], "324") == 0)) {
    int m = i + (tok[i][0] == '3' ? 3 : 2);
    int a = m + 1;
    bool adding = true;
    for (const char *c = m < n ? tok[m] : ""; *c && a < n; c++) {
      if (*c == '+' || *c == '-') adding = *c == '+';
      else if (*c != ':' && isupport_mode_has_arg(state, *c, adding)) {
        if (*c == 'k') mask[a] = true;
        a++;
      }
    }
  }
  size_t o = 0;
  out[0] = '\0';
  for (int k = 0; k < n && o + 1 < cap; k++) {
    const char *s = tok[k];
    char keys[MAX_LOG_LINE_LEN];
    if (mask[k]) {
      /* one **** per comma-separated key; a trailing-parameter colon stays */
      size_t ko = 0;
      if (*s == ':') keys[ko++] = *s++;
      for (bool first = true;; first = false) {
        const char *comma = strchr(s, ',');
        if (!first && ko + 1 < sizeof(keys)) keys[ko++] = ',';
        if ((comma ? comma > s : *s != '\0') && ko + 5 < sizeof(keys)) {
          memcpy(keys + ko, "****", 4);
          ko += 4;
        }
        if (!comma) break;
        s = comma + 1;
      }
      keys[ko] = '\0';
      s = keys;
    }
    int w = snprintf(out + o, cap - o, "%s%s", k ? " " : "", s);
    if (w < 0) break;
    o += (size_t)w < cap - o ? (size_t)w : cap - o - 1;
  }
  secure_wipe(buf, sizeof(buf));
}

void log_mask_keys(const bot_state_t *state, const char *line, char *out, size_t cap) {
  mask_line(state, line, out, cap, 0);
}

/* A raw IRC line ("[RAW_SEND] ", "[RAW_RECV] "): the ring keeps it as sent,
 * for an admin's getlog; LOGFILE gets its channel keys masked (L1b). */
void log_raw(const bot_state_t *state, const char *tag, const char *line) {
  char ring[MAX_LOG_LINE_LEN - 40], file[MAX_LOG_LINE_LEN - 40];
  snprintf(ring, sizeof(ring), "%s%s", tag, line);
  if (!(state->log_type & L_RAW)) { /* ring only: nothing reaches the file */
    log_write(L_RAW, state, ring, ring);
    secure_wipe(ring, sizeof(ring));
    return;
  }
  size_t tl = strlen(tag) < sizeof(file) ? strlen(tag) : 0;
  memcpy(file, tag, tl);
  log_clean(ring + tl);
  log_mask_keys(state, ring + tl, file + tl, sizeof(file) - tl);
  log_write(L_RAW, state, ring, file);
  secure_wipe(ring, sizeof(ring));
}
