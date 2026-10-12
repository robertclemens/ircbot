/* Output send queue and pacing (modes.md §10).
 *
 * Every line the bot sends to the IRC server goes through here (irc_printf ->
 * irc_send_line -> sendq_enqueue).  A token bucket lets `burst` lines out back
 * to back and then one per `interval_ms` (both live in state->sendq, from the
 * D| setting `sendq` B:I, default SENDQ_DEF_BURST : SENDQ_DEF_INTERVAL_MS) --
 * a bot answering a flood with a pile of KICK / MODE lines is otherwise
 * disconnected for "Excess Flood".  Interval 0 means unpaced: every queued
 * line is sent at once, with no credit gating; the lanes, the protection
 * dedupe and the MODE packing below still apply.
 *
 * Three lanes, always drained in this order:
 *   0 protocol    PONG, PING, registration (NICK USER PASS CAP), QUIT
 *   1 protection  MODE changes and KICK
 *   2 other       everything else (PRIVMSG, JOIN, WHO, ...)
 * Consecutive single-change MODE lines for one channel in lane 1 are packed
 * into one line, up to the server's 005 MODES= changes (default 3); KICKs go
 * one per line.  The queue holds at most MAX_SENDQ lines; when it is full the
 * oldest line of lane 2 is dropped (and, with lane 2 empty, the oldest of
 * lane 1 for a protocol or protection line, otherwise the new line itself).
 * A protection line identical to one already queued is not queued twice.
 *
 * No timer or thread of its own: sendq_drain() runs from irc_printf (credit
 * is usually there) and after every main-loop select(), whose timeout is
 * sendq_next_ms() (<= 1 s) while lines wait, so a line leaves on time. */
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>

#include "bot.h"

static long long mono_ms(void) {
  struct timespec ts;
  if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0)
    return (long long)time(NULL) * 1000;
  return (long long)ts.tv_sec * 1000 + ts.tv_nsec / 1000000;
}

void sendq_init(bot_state_t *state) {
  state->sendq.burst = SENDQ_DEF_BURST;
  state->sendq.interval_ms = SENDQ_DEF_INTERVAL_MS;
  sendq_clear(state);
}

/* Drop everything and refill the burst.  Called when the link goes away, so
 * a new connection starts with a full bucket and an empty queue. */
void sendq_clear(bot_state_t *state) {
  sendq_t *q = &state->sendq;
  for (int l = 0; l < SENDQ_LANES; l++) {
    for (int i = 0; i < q->count[l]; i++)
      free(q->q[l][(q->head[l] + i) % MAX_SENDQ]);
    q->head[l] = 0;
    q->count[l] = 0;
  }
  q->total = 0;
  q->credit_ms = (long long)q->burst * q->interval_ms;
  q->last_ms = mono_ms();
}

/* New live limits (D| sendq changed).  Out-of-range values are clamped; the
 * stored credit is cut to the new cap, never raised. */
void sendq_set_limits(bot_state_t *state, int burst, int interval_ms) {
  sendq_t *q = &state->sendq;
  if (burst < SENDQ_MIN_BURST) burst = SENDQ_MIN_BURST;
  if (burst > SENDQ_MAX_BURST) burst = SENDQ_MAX_BURST;
  if (interval_ms < SENDQ_MIN_INTERVAL_MS) interval_ms = SENDQ_MIN_INTERVAL_MS;
  if (interval_ms > SENDQ_MAX_INTERVAL_MS) interval_ms = SENDQ_MAX_INTERVAL_MS;
  q->burst = burst;
  q->interval_ms = interval_ms;
  long long cap = (long long)burst * interval_ms;
  if (q->credit_ms > cap)
    q->credit_ms = cap;
}

bool sendq_pending(const bot_state_t *state) {
  return state->sendq.total > 0;
}

static void refill(sendq_t *q) {
  long long now = mono_ms();
  long long cap = (long long)q->burst * q->interval_ms;
  if (now > q->last_ms)
    q->credit_ms += now - q->last_ms;
  q->last_ms = now;
  if (q->credit_ms > cap)
    q->credit_ms = cap;
}

bool sendq_ready(bot_state_t *state) {
  sendq_t *q = &state->sendq;
  if (q->total == 0)
    return false;
  refill(q);
  return q->credit_ms >= q->interval_ms; /* interval 0: always */
}

int sendq_next_ms(bot_state_t *state) {
  sendq_t *q = &state->sendq;
  if (q->total == 0)
    return -1;
  refill(q);
  if (q->credit_ms >= q->interval_ms)
    return 0;
  return (int)(q->interval_ms - q->credit_ms);
}

/* Is the line a MODE query (list or mode fetch) rather than a change? */
static bool mode_is_query(const char *line) {
  const char *p = line + 5; /* after "MODE " */
  const char *sp = strchr(p, ' ');
  if (!sp)
    return true; /* "MODE #chan" */
  sp++;
  /* "MODE #chan +b" with no argument lists the bans */
  const char *sp2 = strchr(sp, ' ');
  size_t mlen = sp2 ? (size_t)(sp2 - sp) : strcspn(sp, "\r\n");
  if (!sp2 || sp2[1] == '\r' || sp2[1] == '\n' || sp2[1] == '\0') {
    if (mlen == 2 && (sp[1] == 'b' || sp[1] == 'e' || sp[1] == 'I'))
      return true;
    if (mlen == 1 && (sp[0] == 'b' || sp[0] == 'e' || sp[0] == 'I'))
      return true;
  }
  return false;
}

int sendq_lane_of(const char *line) {
  size_t vl = strcspn(line, " \r\n");
  if ((vl == 4 && (strncasecmp(line, "PONG", 4) == 0 ||
                   strncasecmp(line, "PING", 4) == 0 ||
                   strncasecmp(line, "NICK", 4) == 0 ||
                   strncasecmp(line, "USER", 4) == 0 ||
                   strncasecmp(line, "PASS", 4) == 0 ||
                   strncasecmp(line, "QUIT", 4) == 0)) ||
      (vl == 3 && strncasecmp(line, "CAP", 3) == 0))
    return SENDQ_LANE_PROTO;
  if (vl == 4 && strncasecmp(line, "KICK", 4) == 0)
    return SENDQ_LANE_PROT;
  if (vl == 4 && strncasecmp(line, "MODE", 4) == 0 && line[4] == ' ' &&
      !mode_is_query(line))
    return SENDQ_LANE_PROT;
  return SENDQ_LANE_REST;
}

static char *lane_pop(sendq_t *q, int lane) {
  char *s = q->q[lane][q->head[lane]];
  q->q[lane][q->head[lane]] = NULL;
  q->head[lane] = (q->head[lane] + 1) % MAX_SENDQ;
  q->count[lane]--;
  q->total--;
  return s;
}

/* Make room for one more line of `lane`.  False: the new line is the one
 * to drop. */
static bool make_room(bot_state_t *state, int lane) {
  sendq_t *q = &state->sendq;
  if (q->total < MAX_SENDQ)
    return true;
  int victim = -1;
  if (q->count[SENDQ_LANE_REST] > 0)
    victim = SENDQ_LANE_REST;
  else if (lane != SENDQ_LANE_REST && q->count[SENDQ_LANE_PROT] > 0)
    victim = SENDQ_LANE_PROT; /* the oldest protection line is the stale one */
  if (victim < 0)
    return false;
  free(lane_pop(q, victim));
  q->dropped++;
  return true;
}

int sendq_enqueue(bot_state_t *state, const char *line, int len) {
  if (!line || len < 2)
    return -1;
  sendq_t *q = &state->sendq;
  int lane = sendq_lane_of(line);

  /* An IRC line is at most 512 bytes with CRLF; the server would cut it there
   * anyway.  Cutting here bounds what the queue can hold. */
  int body = len - 2;
  if (body > SENDQ_LINE_MAX)
    body = SENDQ_LINE_MAX;
  /* The sweep asks for the same KICK / MODE again while the first is still
   * waiting for its turn: one copy in the queue is enough. */
  if (lane == SENDQ_LANE_PROT) {
    for (int i = 0; i < q->count[lane]; i++) {
      const char *w = q->q[lane][(q->head[lane] + i) % MAX_SENDQ];
      if (strncmp(w, line, (size_t)body) == 0 && w[body] == '\r')
        return len;
    }
  }
  if (!make_room(state, lane)) {
    q->dropped++;
    int vl = (int)strcspn(line, " \r\n");
    log_message(L_INFO, state, "[SENDQ] Queue full; dropped a %.*s line\n",
                vl > 16 ? 16 : vl, line);
    return -1;
  }
  char *copy = malloc((size_t)body + 3);
  if (!copy)
    return -1;
  memcpy(copy, line, (size_t)body);
  memcpy(copy + body, "\r\n", 3);
  q->q[lane][(q->head[lane] + q->count[lane]) % MAX_SENDQ] = copy;
  q->count[lane]++;
  q->total++;
  sendq_drain(state);
  return len;
}

/* --- MODE packing ------------------------------------------------------- */

typedef struct {
  char chan[MAX_CHAN];
  char sign;
  char letter;
  char arg[300];
  bool has_arg;
} mode_item_t;

/* "MODE <chan> <+|-><letter> [arg]\r\n" for a letter we know the argument
 * rule of.  Anything else is sent as it stands. */
static bool mode_item_parse(const char *line, mode_item_t *it) {
  if (strncasecmp(line, "MODE ", 5) != 0)
    return false;
  const char *p = line + 5;
  size_t cl = strcspn(p, " \r\n");
  if (cl == 0 || cl >= sizeof(it->chan) || p[cl] != ' ')
    return false;
  memcpy(it->chan, p, cl);
  it->chan[cl] = '\0';
  p += cl + 1;
  if ((p[0] != '+' && p[0] != '-') || p[1] == '\0' || p[1] == '\r' ||
      p[1] == '\n' || (p[2] != ' ' && p[2] != '\r'))
    return false; /* exactly one signed letter */
  it->sign = p[0];
  it->letter = p[1];
  const char *a = p + 2;
  if (*a == ' ')
    a++;
  size_t al = strcspn(a, " \r\n");
  if (a[al] == ' ')
    return false; /* more than one argument */
  bool needs;
  switch (it->letter) {
  case 'o': case 'v': case 'h': case 'b': case 'e': case 'I': case 'k':
    needs = true;
    break;
  case 'l':
    needs = (it->sign == '+');
    break;
  case 'i': case 'm': case 'n': case 'p': case 's': case 't':
    needs = false;
    break;
  default:
    return false;
  }
  if (needs != (al > 0))
    return false;
  if (al >= sizeof(it->arg))
    return false;
  memcpy(it->arg, a, al);
  it->arg[al] = '\0';
  it->has_arg = needs;
  return true;
}

/* Build the line to send from lane 1's head, packing following single-change
 * MODEs for the same channel.  Pops what it uses.  out ends in CRLF. */
static char *take_protection(bot_state_t *state, size_t *out_len) {
  sendq_t *q = &state->sendq;
  int lane = SENDQ_LANE_PROT;
  mode_item_t first;
  char *head = q->q[lane][q->head[lane]];
  if (!mode_item_parse(head, &first)) {
    char *s = lane_pop(q, lane);
    *out_len = strlen(s);
    return s;
  }
  int limit = state->isup.modes;
  if (limit < 1) limit = ISUPPORT_MODES_DEFAULT;
  if (limit > ISUPPORT_MODES_MAX) limit = ISUPPORT_MODES_MAX;

  mode_item_t items[ISUPPORT_MODES_MAX];
  int n = 0;
  items[n++] = first;
  size_t est = 5 + strlen(first.chan) + 3 + strlen(first.arg) + 1;
  while (n < limit && n < q->count[lane]) {
    mode_item_t it;
    char *nxt = q->q[lane][(q->head[lane] + n) % MAX_SENDQ];
    if (!mode_item_parse(nxt, &it) ||
        strcasecmp(it.chan, first.chan) != 0)
      break;
    size_t add = 2 + strlen(it.arg) + 1;
    if (est + add > 400)
      break;
    est += add;
    items[n++] = it;
  }
  char *out = malloc(est + 16);
  if (!out)
    return NULL;
  size_t o = (size_t)snprintf(out, est + 16, "MODE %s ", first.chan);
  char cur = 0;
  for (int i = 0; i < n; i++) {
    if (items[i].sign != cur) {
      out[o++] = items[i].sign;
      cur = items[i].sign;
    }
    out[o++] = items[i].letter;
  }
  for (int i = 0; i < n; i++) {
    if (!items[i].has_arg)
      continue;
    out[o++] = ' ';
    size_t al = strlen(items[i].arg);
    memcpy(out + o, items[i].arg, al);
    o += al;
  }
  out[o++] = '\r';
  out[o++] = '\n';
  out[o] = '\0';
  for (int i = 0; i < n; i++)
    free(lane_pop(q, lane));
  *out_len = o;
  return out;
}

int sendq_drain(bot_state_t *state) {
  sendq_t *q = &state->sendq;
  int sent = 0;
  if (q->total == 0)
    return 0;
  refill(q);
  while (q->total > 0 && q->credit_ms >= q->interval_ms) {
    if (!(state->status & S_CONNECTED)) {
      sendq_clear(state);
      return sent;
    }
    char *line = NULL;
    size_t len = 0;
    if (q->count[SENDQ_LANE_PROTO] > 0) {
      line = lane_pop(q, SENDQ_LANE_PROTO);
      len = strlen(line);
    } else if (q->count[SENDQ_LANE_PROT] > 0) {
      line = take_protection(state, &len);
    } else {
      line = lane_pop(q, SENDQ_LANE_REST);
      len = strlen(line);
    }
    if (!line)
      break;
    q->credit_ms -= q->interval_ms;
    int rc = irc_write_raw(state, line, (int)len);
    free(line);
    if (rc < 0)
      return sent; /* irc_write_raw disconnected and cleared the queue */
    sent++;
  }
  return sent;
}
