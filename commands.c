#include <ctype.h>
#include <math.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <time.h>
#include <unistd.h>

#include "bot.h"

/* Render an elapsed span as "0d 16h 31m 55s" for the status readout. */
static void status_fmt_elapsed(char *buf, size_t len, time_t since) {
  long d = (long)(time(NULL) - since);
  if (since <= 0 || d < 0) d = 0;
  snprintf(buf, len, "%ldd %ldh %ldm %lds", d / 86400, (d % 86400) / 3600,
           (d % 3600) / 60, d % 60);
}

/* Anti-flood pause between reply lines on IRC.  A DCC chat is a direct
 * connection with no server flood limit, so its replies are not paced. */
static void reply_pace(const bot_state_t *state, const struct timespec *d) {
  if (!state->dcc_reply)
    nanosleep(d, NULL);
}

/* CMD-log redaction.  `secret` flags argument positions that carry a secret;
 * those are logged as REDACT_MASK, never as typed.  Since the passwordless
 * change no command takes one (public keys are not secret; channel keys have
 * always been logged as typed), but the table stays an allowlist: a verb
 * missing from it is logged without its name or arguments, because a typo can
 * put anything in any position.  A new command belongs here, with any secret
 * arguments flagged. */
#define REDACT_ARG1 1u
#define REDACT_ARG2 2u
#define REDACT_ARG3 4u
#define REDACT_MASK "********"

typedef struct {
  const char *name;
  unsigned secret;
} cmd_log_rule_t;

static const cmd_log_rule_t LOGGABLE_CMDS[] = {
  {"+admin", 0},   {"+oper", 0},    {"chkey", 0},
  {"die", 0},      {"jump", 0},     {"join", 0},      {"part", 0},
  {"op", 0},       {"invite", 0},   {"+bot", 0},      {"-bot", 0},
  {"status", 0},   {"givenick", 0}, {"chnick", 0},    {"saveconf", 0},
  {"setlog", 0},   {"getlog", 0},   {"admins", 0},    {"opers", 0},
  {"match", 0},    {"-admin", 0},   {"-oper", 0},     {"+usermask", 0},
  {"-usermask", 0}, {"+server", 0}, {"-server", 0},   {"update", 0},
  {"+hub", 0},     {"-hub", 0},     {"rekey", 0},     {"help", 0},
  {"dcc", 0},
  {NULL, 0}
};

/* ---- Passwordless admin/oper transport (irchub/docs/passwordless.md §4) ----
 *
 *   ~A2A <sig_b64> <ts>:<nonce>     auth request, Ed25519-signed
 *   ~A2K <b64(eph|iv|ct|tag)>       NOTICE reply: this bot's pubkey, sealed
 *                                   to the user's X25519 key
 *   ~A2  <b64(eph|iv|ct|tag)>       command, sealed to this bot's X25519 key
 *                                   with the user's static key mixed in
 *
 * Every context string is  LABEL "\0" lc(botnick) "\0" lc(user nick) ...:
 * the bot nick is `dest` (our current nick) and the user nick the PRIVMSG
 * source, so a frame is only valid for one bot and one sender nick.  On a DCC
 * chat both are the nicks from when the chat was offered (dcc_session_t). */

/* ASCII-lowercase copy; false if in does not fit. */
static bool lc_copy(char *out, size_t cap, const char *in) {
  size_t n = strlen(in);
  if (n == 0 || n >= cap) return false;
  for (size_t i = 0; i <= n; i++) {
    unsigned char c = (unsigned char)in[i];
    out[i] = (c >= 'A' && c <= 'Z') ? (char)(c + 32) : (char)c;
  }
  return true;
}

/* label "\0" lc(botnick) "\0" lc(usernick) [ "\0" extra ] -> buf; 0 on error */
static size_t a2_context(unsigned char *buf, size_t cap, const char *label,
                         const char *botnick, const char *usernick,
                         const char *extra) {
  char b[A2_NICK_MAX], u[A2_NICK_MAX];
  if (!lc_copy(b, sizeof(b), botnick) || !lc_copy(u, sizeof(u), usernick))
    return 0;
  int n = extra
      ? snprintf((char *)buf, cap, "%s%c%s%c%s%c%s", label, 0, b, 0, u, 0, extra)
      : snprintf((char *)buf, cap, "%s%c%s%c%s", label, 0, b, 0, u);
  return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}

static bool admin_nonce_seen(const bot_state_t *state, uint64_t nonce,
                             time_t now) {
  for (int i = 0; i < MAX_SEEN_HASHES; i++)
    if (state->admin_nonces[i].nonce == nonce &&
        now - state->admin_nonces[i].ts <= NONCE_TTL_SECONDS)
      return true;
  return false;
}

static void admin_nonce_record(bot_state_t *state, uint64_t nonce, time_t now) {
  state->admin_nonces[state->admin_nonce_idx] = (nonce_entry_t){nonce, now};
  state->admin_nonce_idx = (state->admin_nonce_idx + 1) % MAX_SEEN_HASHES;
}

/* ~A2A: verify the signed auth request and answer with the ~A2K lockbox.
 * Silent on the wire for every failure (no oracle for which usermasks
 * exist); each is logged at L_CMD. */
static void a2_handle_auth(bot_state_t *state, const char *nick,
                           const char *user_host, const char *dest,
                           const char *arg) {
  /* arg = "<sig_b64:88> <ts>:<nonce:16 hex>" */
  const char *sp = strchr(arg, ' ');
  if (!sp || sp - arg != 88) {
    log_message(L_CMD, state, "[CMD] ~A2A from %s: malformed\n", user_host);
    return;
  }
  char sig_b64[89];
  memcpy(sig_b64, arg, 88);
  sig_b64[88] = '\0';
  char tsn[40];
  if (strlen(sp + 1) >= sizeof(tsn)) {
    log_message(L_CMD, state, "[CMD] ~A2A from %s: malformed\n", user_host);
    return;
  }
  snprintf(tsn, sizeof(tsn), "%s", sp + 1);

  /* Validate "<ts>:<nonce>" by reusing the envelope parser on a copy with a
   * dummy command appended. */
  char probe[48];
  snprintf(probe, sizeof(probe), "%s:x", tsn);
  time_t ts;
  uint64_t nonce;
  char *dummy;
  if (!envelope_parse(probe, &ts, &nonce, &dummy) || strcmp(dummy, "x") != 0) {
    log_message(L_CMD, state, "[CMD] ~A2A from %s: bad ts/nonce\n", user_host);
    return;
  }
  time_t now = time(NULL);
  if (llabs((long long)(now - ts)) > A2_TS_SKEW) {
    log_message(L_CMD, state, "[CMD] ~A2A from %s: timestamp skew %lds\n",
                user_host, (long)(now - ts));
    return;
  }

  int sl = 0;
  unsigned char *sig = base64_decode(sig_b64, &sl);
  unsigned char msg[256];
  size_t ml = a2_context(msg, sizeof(msg), A2A_LABEL, dest, nick, tsn);
  if (!sig || sl != 64 || ml == 0) {
    free(sig);
    log_message(L_CMD, state, "[CMD] ~A2A from %s: malformed\n", user_host);
    return;
  }

  user_record_t *cands[MAX_USER_RECORDS];
  int midx[MAX_USER_RECORDS];
  int nc = auth_user_candidates(state, user_host, cands, midx, MAX_USER_RECORDS);
  user_record_t *who = NULL;
  int who_mask = -1;
  for (int i = 0; i < nc && !who; i++) {
    unsigned char pub[HUB_KEY_RAW_LEN];
    if (crypto_pubkey_b64_decode(cands[i]->pubkey_b64, pub) &&
        crypto_ed25519_verify(pub, msg, ml, sig)) {
      who = cands[i];
      who_mask = midx[i];
    }
  }
  free(sig);
  if (!who) {
    log_message(L_CMD, state, "[CMD] ~A2A from %s: no matching key verified "
                              "(%d candidate%s)\n", user_host, nc,
                nc == 1 ? "" : "s");
    return;
  }
  if (admin_nonce_seen(state, nonce, now)) {
    log_message(L_CMD, state, "[CMD] ~A2A replay from %s\n", user_host);
    return;
  }
  admin_nonce_record(state, nonce, now);
  if (now - who->last_auth_reply < A2_AUTH_REPLY_MIN_INTERVAL ||
      now - state->last_auth_reply_any < A2_AUTH_REPLY_GLOBAL_INTERVAL) {
    log_message(L_CMD, state, "[CMD] ~A2A from %s (%s): throttled\n",
                who->name, user_host);
    return;
  }
  if (!state->self_pub_set) {
    log_message(L_CMD, state, "[CMD] ~A2A: this bot has no identity key\n");
    return;
  }

  /* Lockbox: our public key, sealed anonymously to the user's X25519 key and
   * bound to this request's ts:nonce so the client accepts only the reply
   * to a request it sent. */
  unsigned char upub[HUB_KEY_RAW_LEN], aad[256];
  size_t al = a2_context(aad, sizeof(aad), A2K_LABEL, dest, nick, tsn);
  unsigned char frame[HUB_KEY_RAW_LEN + SEAL_OVERHEAD];
  int fl = -1;
  if (al && crypto_pubkey_b64_decode(who->pubkey_b64, upub))
    fl = crypto_seal(NULL, NULL, upub + 32, A2K_LABEL, aad, al, state->self_pub,
                     HUB_KEY_RAW_LEN, frame, sizeof(frame));
  char *b64 = (fl > 0) ? base64_encode(frame, fl) : NULL;
  if (!b64) {
    log_message(L_CMD, state, "[CMD] ~A2A: sealing the lockbox failed\n");
    return;
  }
  who->last_auth_reply = now;
  state->last_auth_reply_any = now;
  auth_mark_used(state, who, who_mask, now);
  irc_printf(state, "NOTICE %s :~A2K %s\r\n", nick, b64);
  free(b64);
  log_message(L_CMD, state, "[CMD] ~A2A: %s (%s) authenticated; key sent\n",
              who->name, user_host);
}

/* ~A2: open a sealed command.  Tries the key of every record whose usermask
 * matches the sender; the one whose tag verifies is the sender.  only_uuid
 * (a DCC chat's owner, else NULL) limits that to one record.  Returns the
 * record with *cmd pointing into pt, or NULL (logged, silent on the wire).
 * pt must hold SEAL_MAX_PLAINTEXT + 1 bytes; the caller wipes it. */
static user_record_t *a2_open_command(bot_state_t *state, const char *nick,
                                      const char *user_host, const char *dest,
                                      const char *only_uuid, const char *b64,
                                      char *pt, char **cmd) {
  if (strlen(b64) > A2_LINE_MAX - 4) {
    log_message(L_CMD, state, "[CMD] ~A2 from %s: oversized\n", user_host);
    return NULL;
  }
  unsigned char aad[160];
  size_t al = a2_context(aad, sizeof(aad), A2_LABEL, dest, nick, NULL);
  int flen = 0;
  unsigned char *frame = base64_decode(b64, &flen);
  if (!frame || flen < SEAL_OVERHEAD || al == 0 || !state->self_pub_set) {
    free(frame);
    log_message(L_CMD, state, "[CMD] ~A2 from %s: malformed\n", user_host);
    return NULL;
  }

  user_record_t *cands[MAX_USER_RECORDS];
  int midx[MAX_USER_RECORDS];
  int nc = auth_user_candidates(state, user_host, cands, midx, MAX_USER_RECORDS);
  user_record_t *who = NULL;
  int who_mask = -1, n = -1;
  unsigned char ed_priv[32], x_priv[32];
  if (nc > 0 && bot_key_decode(state, ed_priv, x_priv)) {
    for (int i = 0; i < nc && !who; i++) {
      unsigned char upub[HUB_KEY_RAW_LEN];
      if (only_uuid && strcmp(cands[i]->uuid, only_uuid) != 0) continue;
      if (!crypto_pubkey_b64_decode(cands[i]->pubkey_b64, upub)) continue;
      n = crypto_open(x_priv, state->self_pub + 32, upub + 32, A2_LABEL, aad,
                      al, frame, (size_t)flen, (unsigned char *)pt,
                      SEAL_MAX_PLAINTEXT);
      if (n >= 0) {
        who = cands[i];
        who_mask = midx[i];
      }
    }
  }
  secure_wipe(ed_priv, sizeof(ed_priv));
  secure_wipe(x_priv, sizeof(x_priv));
  free(frame);
  if (!who) {
    log_message(L_CMD, state, "[CMD] ~A2 from %s: did not open for any "
                              "matching key (%d candidate%s)\n", user_host, nc,
                nc == 1 ? "" : "s");
    return NULL;
  }
  pt[n] = '\0';

  /* Reject, don't repair: a CR/LF in an argument would reach irc_printf and
   * split into a second IRC command. */
  time_t ts;
  uint64_t nonce;
  time_t now = time(NULL);
  if (has_control_bytes(pt, (size_t)n)) {
    log_message(L_CMD, state, "[CMD] ~A2 from %s: control character in "
                              "command; dropped\n", user_host);
    return NULL;
  }
  if (!envelope_parse(pt, &ts, &nonce, cmd)) {
    log_message(L_CMD, state, "[CMD] ~A2 from %s: bad envelope\n", user_host);
    return NULL;
  }
  if (llabs((long long)(now - ts)) > A2_TS_SKEW) {
    log_message(L_CMD, state, "[CMD] ~A2 from %s: timestamp skew %lds\n",
                user_host, (long)(now - ts));
    return NULL;
  }
  if (admin_nonce_seen(state, nonce, now)) {
    log_message(L_CMD, state, "[CMD] ~A2 replay from %s\n", user_host);
    return NULL;
  }
  admin_nonce_record(state, nonce, now);
  auth_mark_used(state, who, who_mask, now);
  /* No command text here: log_user_command records it. */
  log_message(L_DEBUG, state, "[CMD_DEBUG] ~A2 verified: User='%s' Type=%c\n",
              who->name, who->type);
  return who;
}

/* Append src to dst (current length *len, capacity cap), stopping at the cap.
 * No escaping here: log_message neutralizes control bytes in every line. */
static void cmd_log_append(char *dst, size_t cap, size_t *len,
                           const char *src) {
  for (; *src != '\0' && *len + 1 < cap; src++)
    dst[(*len)++] = *src;
  dst[*len] = '\0';
}

/* Log an authenticated admin/oper command to L_CMD as
 *   [CMD_ADMIN] <account> (<nick!user@host>): <command> <args>
 * with each secret argument replaced by REDACT_MASK.  The dispatcher reads
 * only arg1..arg3 and drops the rest of the line, so nothing past arg3 is
 * logged either. */
static void log_user_command(bot_state_t *state, const char *tag,
                             const user_record_t *who, const char *user_host,
                             const char *command, const char *arg1,
                             const char *arg2, const char *arg3) {
  const cmd_log_rule_t *rule = NULL;
  for (int i = 0; LOGGABLE_CMDS[i].name; i++) {
    if (strcasecmp(command, LOGGABLE_CMDS[i].name) == 0) {
      rule = &LOGGABLE_CMDS[i];
      break;
    }
  }

  char line[MAX_LOG_LINE_LEN];
  size_t len = 0;
  line[0] = '\0';
  cmd_log_append(line, sizeof(line), &len, who ? who->name : "?");
  cmd_log_append(line, sizeof(line), &len, " (");
  cmd_log_append(line, sizeof(line), &len, user_host);
  cmd_log_append(line, sizeof(line), &len,
                 state->dcc_reply ? " via DCC): " : "): ");

  if (!rule) {
    cmd_log_append(line, sizeof(line), &len,
                   "unrecognized command (not logged)");
  } else {
    cmd_log_append(line, sizeof(line), &len, rule->name);
    const char *args[3] = {arg1, arg2, arg3};
    for (int i = 0; i < 3 && args[i]; i++) {
      cmd_log_append(line, sizeof(line), &len, " ");
      cmd_log_append(line, sizeof(line), &len,
                     (rule->secret & (1u << i)) ? REDACT_MASK : args[i]);
    }
  }
  log_message(L_CMD, state, "[%s] %s\n", tag, line);
}

static void dispatch_user_command(bot_state_t *state, const char *nick,
                                  const char *user_host,
                                  user_record_t *auth_user, bool is_admin,
                                  bool is_op, char *command, char *arg1,
                                  char *arg2, char *arg3);

/* Split, screen and dispatch one opened command line, from PRIVMSG or a DCC
 * chat.  nick is the reply target; cmd_line points into the caller's
 * plaintext buffer, which the caller wipes. */
static void run_user_command(bot_state_t *state, const char *nick,
                             const char *user_host, user_record_t *auth_user,
                             char *cmd_line) {
  char *sp_cmd;
  char *command = strtok_r(cmd_line, " ", &sp_cmd);
  char *arg1    = strtok_r(NULL,     " ", &sp_cmd);
  char *arg2    = strtok_r(NULL,     " ", &sp_cmd);
  char *arg3    = strtok_r(NULL,     " ", &sp_cmd);
  bool is_admin = command && auth_user->type == 'a';
  bool is_op    = command && auth_user->type == 'o';
  if (!is_admin && !is_op) {
    log_message(L_CMD, state, "[CMD_DEBUG] Auth failed for %s.\n", user_host);
    return;
  }

  /* Every value a command stores lands in a '|'-delimited config line and
   * hub record (o|uuid|name|pubkey|add|last_seen|ts|), where a '|' shifts
   * the fields after it: `+usermask me x|add|0|<far future>` would plant a
   * timestamp that outranks any later -usermask. */
  const char *const toks[] = {command, arg1, arg2, arg3};
  bool has_delim = false;
  for (size_t i = 0; i < sizeof(toks) / sizeof(toks[0]); i++)
    if (toks[i] && strchr(toks[i], '|'))
      has_delim = true;

  if (has_delim) {
    log_message(L_CMD, state, "[CMD] '|' in command from %s (%s); dropped\n",
                auth_user->name, user_host);
    irc_printf(state,
               "PRIVMSG %s :Error: '|' is not allowed in commands.\r\n", nick);
  } else {
    log_user_command(state, is_admin ? "CMD_ADMIN" : "CMD_OP", auth_user,
                     user_host, command, arg1, arg2, arg3);
    dispatch_user_command(state, nick, user_host, auth_user, is_admin, is_op,
                          command, arg1, arg2, arg3);
  }
}

void commands_handle_private_message(bot_state_t *state, const char *nick,
                                     const char *user, const char *host,
                                     const char *dest, char *message) {
  if (strcasecmp(dest, state->current_nick) != 0)
    return;

  char user_host[256];
  snprintf(user_host, sizeof(user_host), "%s!%s@%s", nick, user, host);

  log_message(L_MSG, state, "[MSG] (%s): %s\n", user_host, message);

  /* --- Block 1: trusted-bot commands (~B2, bot_comms.c) --- */
  if (bot_comms_handle_privmsg(state, nick, user_host, message))
    return;

  /* --- Block 2: admin/oper (irchub/docs/passwordless.md §4) ---
   * ~A2A is the auth request, answered with a ~A2K lockbox and nothing else;
   * ~A2 carries a sealed command.  Anything else — including the retired
   * password formats ~A1 / ~A1c — is unauthenticated and dropped below. */
  if (strncmp(message, "~A2A ", 5) == 0) {
    a2_handle_auth(state, nick, user_host, dest, message + 5);
    return;
  }

  char cmd_plaintext[SEAL_MAX_PLAINTEXT + 1];  /* decrypted command */
  char *cmd_line = NULL;
  user_record_t *auth_user = NULL;
  cmd_plaintext[0] = '\0';

  if (strncmp(message, "~A2 ", 4) == 0) {
    auth_user = a2_open_command(state, nick, user_host, dest, NULL,
                                message + 4, cmd_plaintext, &cmd_line);
  } else if (strncmp(message, "~A1", 3) == 0) {
    log_message(L_CMD, state,
                "[CMD] Retired password frame (~A1/~A1c) from %s; the client "
                "script needs updating to the key-based ~A2\n", user_host);
  }
  /* Nothing past this point may run for an unauthenticated sender. */
  if (auth_user && cmd_line)
    run_user_command(state, nick, user_host, auth_user, cmd_line);
  else
    log_message(L_CMD, state, "[CMD_DEBUG] Auth failed for %s.\n", user_host);
  /* The decrypted command (channel keys, masks, hub addresses) never outlives
   * its processing; nothing points into it once dispatch has returned. */
  secure_wipe(cmd_plaintext, sizeof(cmd_plaintext));
}

bool commands_handle_dcc_line(bot_state_t *state, dcc_session_t *s,
                              char *line) {
  if (strncmp(line, "~A2 ", 4) != 0) {
    log_message(L_CMD, state, "[CMD] DCC line from %s (%s) is not a sealed "
                              "command\n", s->name, s->user_host);
    return false;
  }
  char cmd_plaintext[SEAL_MAX_PLAINTEXT + 1];
  char *cmd_line = NULL;
  cmd_plaintext[0] = '\0';
  /* Same checks as PRIVMSG (usermask, key, timestamp, replay), with the chat's
   * owner as the only key that may open it and the chat's nicks as the
   * context.  The chat was granted to an admin: a record demoted since then
   * ends it. */
  user_record_t *who = a2_open_command(state, s->nick, s->user_host,
                                       s->botnick, s->uuid, line + 4,
                                       cmd_plaintext, &cmd_line);
  bool ok = who && cmd_line && who->type == 'a';
  if (ok) {
    s->last_active = time(NULL);
    state->dcc_reply = s;
    run_user_command(state, s->nick, s->user_host, who, cmd_line);
    state->dcc_reply = NULL;
  }
  secure_wipe(cmd_plaintext, sizeof(cmd_plaintext));
  return ok;
}

/* Fingerprint of a user's key for listings, or "(no key)". */
static void user_key_fp(const user_record_t *u, char out[KEY_FP_LEN + 1]) {
  unsigned char pub[HUB_KEY_RAW_LEN];
  if (u->has_pubkey && crypto_pubkey_b64_decode(u->pubkey_b64, pub))
    crypto_key_fingerprint(pub, out);
  else
    snprintf(out, KEY_FP_LEN + 1, "(no key)");
}

/* Validate a user public-key argument: the canonical 88-char key, not held
 * by any other active user (keys identify users on the hub).  `self` is the
 * record being re-keyed (NULL when adding).  Replies with the reason. */
static bool user_key_arg_ok(bot_state_t *state, const char *nick,
                            const char *key, const user_record_t *self,
                            const char *cmdname) {
  unsigned char raw[HUB_KEY_RAW_LEN];
  if (!key || !crypto_pubkey_b64_decode(key, raw)) {
    irc_printf(state,
               "PRIVMSG %s :Error: %s needs the user's public key — the "
               "88-char contents of their <ts>_<name>.public.b64. Ask them "
               "for it; 'help %s' shows how they make one.\r\n",
               nick, cmdname, cmdname);
    return false;
  }
  for (int i = 0; i < state->user_record_count; i++) {
    const user_record_t *o = &state->user_records[i];
    if (o == self || !o->is_active || !o->has_pubkey) continue;
    if (strcmp(o->pubkey_b64, key) == 0) {
      irc_printf(state,
                 "PRIVMSG %s :Error: that key already belongs to '%s'. Each "
                 "user needs their own keypair.\r\n", nick, o->name);
      return false;
    }
  }
  return true;
}

static void set_user_key(bot_state_t *state, user_record_t *u,
                         const char *key) {
  snprintf(u->pubkey_b64, sizeof(u->pubkey_b64), "%s", key);
  u->has_pubkey = true;
  u->timestamp = lww_next_ts(u->timestamp);
  u->last_auth_reply = 0;
  config_write_with_state_pass(state);
  hub_client_push_admin_delta(state);
}

/* Shared by help +admin / +oper / chkey: how a user makes a keypair.
 * Each line stays well under the IRC line limit. */
static void help_keypair(bot_state_t *state, const char *nick) {
  static const char *const lines[] = {
    "<pubkey> is the user's 88-char public key. The user makes a keypair on "
    "their own machine, keeps the .private.b64 (chmod 600) for their IRC "
    "script, and sends you only the .public.b64 contents:",
    "  keygen <name>     (ircbot/utils/keygen or irchub/bin/keygen; writes "
    "<YYYYMMDDHHMMSS>_<name>.private.b64 and .public.b64)",
    "  or with openssl 1.1.1+:  umask 077; openssl genpkey -algorithm ED25519 "
    "-out ed.pem; openssl genpkey -algorithm X25519 -out x.pem",
    "  (openssl pkey -in ed.pem -outform DER | tail -c 32; openssl pkey -in "
    "x.pem -outform DER | tail -c 32) | openssl base64 -A > NAME.private.b64",
    "  (openssl pkey -in ed.pem -pubout -outform DER | tail -c 32; openssl "
    "pkey -in x.pem -pubout -outform DER | tail -c 32) | openssl base64 -A > "
    "NAME.public.b64",
    "  shred -u ed.pem x.pem    (or rm -f; the .pem files hold the private key)",
    NULL
  };
  struct timespec d = {0, 100000000};
  for (int i = 0; lines[i]; i++) {
    irc_printf(state, "PRIVMSG %s :%s\r\n", nick, lines[i]);
    reply_pace(state, &d);
  }
}

static void help_auth(bot_state_t *state, const char *nick) {
  static const char *const lines[] = {
    "Admins and opers sign in with their Curve25519 key; there are no "
    "passwords. Use a client script from ircbot/utils (irssi, hexchat, "
    "weechat, mIRC via bot-auth.exe, or the bot-auth CLI) pointed at your "
    ".private.b64.",
    "On the first command to a bot the script sends a signed ~A2A request; "
    "the bot answers with a ~A2K notice carrying its public key (the script "
    "shows its fingerprint). Commands then travel sealed as ~A2 frames.",
    "Compare that fingerprint once with this bot's 'status' or hub_admin's "
    "bot list. After a bot 'rekey', run /botforget <bot> so the script "
    "fetches the new key.",
    NULL
  };
  struct timespec d = {0, 100000000};
  for (int i = 0; lines[i]; i++) {
    irc_printf(state, "PRIVMSG %s :%s\r\n", nick, lines[i]);
    reply_pace(state, &d);
  }
}

/* The admin/oper command tree, split out of commands_handle_private_message
 * so the caller wipes the decrypted command after every return path here.
 * command/arg1..arg3 point into the caller's cmd_plaintext. */
static void dispatch_user_command(bot_state_t *state, const char *nick,
                                  const char *user_host,
                                  user_record_t *auth_user, bool is_admin,
                                  bool is_op, char *command, char *arg1,
                                  char *arg2, char *arg3) {
  if (is_admin) {
    /* opt 'h' (OPT_HUB_ONLY_MUTATIONS): when set by the network, the bot
     * refuses local mutation of hub-authoritative records.  These commands
     * must be performed via hub_admin instead.  Help text also hides them. */
    if (is_opt_set(state, OPT_HUB_ONLY_MUTATIONS)) {
      static const char * const HUB_ONLY_CMDS[] = {
        "+admin", "-admin", "+oper", "-oper",
        "+usermask", "-usermask",
        "+bot", "-bot",
        "join", "part",
        "chkey",
        /* +hub / -hub are intentionally NOT here: hub membership is a
         * bot-local connection concern (the hub-only-mutation boundary
         * covers mesh-replicated records, not which hubs this bot dials),
         * and with per-hub keypairs adding a hub must work even under
         * opt 'h'. */
        NULL
      };
      for (int i = 0; HUB_ONLY_CMDS[i]; i++) {
        if (strcasecmp(command, HUB_ONLY_CMDS[i]) == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Error: '%s' is disabled — network is in "
                     "hub-only-mutation mode (opt 'h'). Use hub_admin.\r\n",
                     nick, HUB_ONLY_CMDS[i]);
          return;
        }
      }
    }

    if (strcasecmp(command, "die") == 0) {
      irc_printf(state, "QUIT :Sayonara.\r\n");
      state->status |= S_DIE;
    } else if (strcasecmp(command, "dcc") == 0) {
      if (state->dcc_reply)
        irc_printf(state, "PRIVMSG %s :You are already in a DCC chat with "
                          "me.\r\n", nick);
      else
        dcc_offer(state, nick, user_host, auth_user);
    } else if (strcasecmp(command, "jump") == 0) {
      if (arg1) {
        /* Jump to named server: match by hostname only, ignore stored port */
        char arg_host[256];
        snprintf(arg_host, sizeof(arg_host), "%s", arg1);
        char *arg_colon = strrchr(arg_host, ':');
        if (arg_colon) *arg_colon = '\0';
        int target_idx = -1;
        for (int i = 0; i < state->server_count; i++) {
          char srv_host[256];
          snprintf(srv_host, sizeof(srv_host), "%s", state->server_list[i]);
          char *srv_colon = strrchr(srv_host, ':');
          if (srv_colon) *srv_colon = '\0';
          if (strcasecmp(arg_host, srv_host) == 0) { target_idx = i; break; }
        }
        if (target_idx == -1) {
          irc_printf(state, "PRIVMSG %s :Error: Server '%s' not in list.\r\n",
                     nick, arg1);
        } else {
          /* An explicit jump overrides any ban/throttle hold on the target. */
          char held[64];
          irc_server_block_desc(state, target_idx, held, sizeof(held));
          if (held[0])
            log_message(L_INFO, state, "[BAN] %s: hold (%s) cleared by jump.\n",
                        state->server_list[target_idx], held);
          irc_server_block_clear(state, target_idx);
          state->current_server_index = target_idx;
          irc_printf(state, "QUIT :Jumping to %s...\r\n", arg1);
          irc_disconnect(state);
        }
      } else {
        irc_printf(state, "QUIT :Jumping servers...\r\n");
        irc_disconnect(state);
      }
    } else if (strcasecmp(command, "join") == 0) {
      char channel_name[MAX_CHAN];
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: join <#channel>\r\n", nick);
        return;
      }
      if (arg1[0] == '#') {
        snprintf(channel_name, sizeof(channel_name), "%s", arg1);
      } else {
        snprintf(channel_name, sizeof(channel_name), "#%s", arg1);
      }

      chan_t *c = channel_find(state, channel_name);
      if (c && c->is_managed) {
        irc_printf(state,
                   "PRIVMSG %s :Error: Channel %s is already in my list.\r\n",
                   nick, channel_name);
        return;
      }
      /* Past any stamp this channel had (a part in this same second), so
       * the newest of the two wins everywhere. */
      time_t prev_ts = c ? c->timestamp : 0;
      if (!c) {
        c = channel_add(state, channel_name);
      }
      if (c) {
        if (arg2)
          snprintf(c->key, MAX_KEY, "%s", arg2);
        c->is_managed = true;      // Mark as managed for syncing
        c->timestamp = lww_next_ts(prev_ts);
        log_message(L_DEBUG, state, "[JOIN] Channel %s: re-enabled ts=%ld\n",
                    channel_name, (long)c->timestamp);
      }
      config_write_with_state_pass(state);
      hub_client_push_config(state); // Sync to hub immediately
      irc_printf(state, "PRIVMSG %s :JOIN %s and saving config file.\r\n", nick,
                 arg1);
    } else if (strcasecmp(command, "part") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: part <#channel>\r\n", nick);
        return;
      }
      char channel_name[MAX_CHAN];
      if (arg1[0] == '#') {
        snprintf(channel_name, sizeof(channel_name), "%s", arg1);
      } else {
        snprintf(channel_name, sizeof(channel_name), "#%s", arg1);
      }
      chan_t *c = channel_find(state, channel_name);
      if (c) {
        // Soft delete - mark as unmanaged instead of removing
        c->is_managed = false;
        c->timestamp = lww_next_ts(c->timestamp);
        log_message(L_DEBUG, state, "[PART-OP] Channel %s: soft delete ts=%ld\n",
                    channel_name, (long)c->timestamp);
        irc_printf(state, "PART %s\r\n", channel_name);
        config_write_with_state_pass(state);
      }
    } else if (strcasecmp(command, "op") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: op <#channel>\r\n", nick);
        return;
      }
      irc_printf(state, "MODE %s +o %s\r\n", arg1, nick);
    } else if (strcasecmp(command, "invite") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: invite <#channel>\r\n", nick);
        return;
      }
      char inv_channel[MAX_CHAN];
      if (arg1[0] == '#' || arg1[0] == '&') {
        snprintf(inv_channel, sizeof(inv_channel), "%s", arg1);
      } else {
        snprintf(inv_channel, sizeof(inv_channel), "#%s", arg1);
      }
      chan_t *ic = channel_find(state, inv_channel);
      if (ic && ic->status == C_IN) {
        /* i_am_opped, not our roster entry: the roster isn't re-read while
         * we hold ops, so after a nick change our entry has the old nick. */
        if (ic->i_am_opped) {
          irc_printf(state, "INVITE %s %s\r\n", nick, inv_channel);
          irc_printf(state, "PRIVMSG %s :Inviting you to %s\r\n",
                     nick, inv_channel);
          return;
        }
      }
      /* Escalate: hub, else a sealed ~B2 PRIVMSG to each trusted bot */
      if (!hub_client_send_invite_request(state, nick, inv_channel)) {
        for (int i = 0; i < state->trusted_bot_count; i++) {
          char tb_nick[MAX_NICK];
          auth_trusted_bot_nick(&state->trusted_bots[i], tb_nick);
          if (tb_nick[0])
            bot_comms_send_command(state, tb_nick,
                                   "INVITE %s %s", inv_channel, nick);
        }
      }
    } else if (strcasecmp(command, "+bot") == 0) {
      if (state->hub_count > 0) {
        irc_printf(state,
                   "PRIVMSG %s :Error: Bot management disabled when hub is configured. "
                   "Bot additions/deletions must be performed on the hub.\r\n",
                   nick);
        return;
      }
      /* +bot <nick!user@host> <uuid> <pubkey> — all three come from the
       * other bot's 'status' output.  The key is what ~B2 is sealed with. */
      if (!arg1 || !arg2 || !arg3) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: +bot <nick!user@host> <uuid> <pubkey> "
                   "- copy the UUID and Pubkey lines from that bot's "
                   "'status'.\r\n", nick);
        return;
      }
      trusted_bot_t nb;
      memset(&nb, 0, sizeof(nb));
      if (strlen(arg1) >= sizeof(nb.mask) || !strchr(arg1, '!') ||
          !strchr(arg1, '@')) {
        irc_printf(state, "PRIVMSG %s :Error: mask must be nick!user@host "
                          "(max %d chars).\r\n", nick, MAX_MASK_LEN - 1);
        return;
      }
      if (strlen(arg2) != 36 || arg2[8] != '-' || arg2[13] != '-' ||
          arg2[18] != '-' || arg2[23] != '-') {
        irc_printf(state, "PRIVMSG %s :Error: '%s' is not a bot UUID.\r\n",
                   nick, arg2);
        return;
      }
      if (!crypto_pubkey_b64_decode(arg3, nb.pub)) {
        irc_printf(state, "PRIVMSG %s :Error: pubkey must be the bot's "
                          "88-char public key (Pubkey line of its "
                          "'status').\r\n", nick);
        return;
      }
      if (strcmp(arg2, state->bot_uuid) == 0) {
        irc_printf(state, "PRIVMSG %s :Error: that is this bot.\r\n", nick);
        return;
      }
      for (int i = 0; i < state->trusted_bot_count; i++) {
        if (strcasecmp(state->trusted_bots[i].mask, arg1) == 0 ||
            strcmp(state->trusted_bots[i].uuid, arg2) == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Error: Trusted bot '%s' already exists (same mask "
              "or UUID). Remove it with -bot first.\r\n",
              nick, arg1);
          return;
        }
      }
      if (state->trusted_bot_count >= MAX_TRUSTED_BOTS) {
        irc_printf(state, "PRIVMSG %s :Error: trusted bot list is full.\r\n",
                   nick);
        return;
      }
      snprintf(nb.mask, sizeof(nb.mask), "%s", arg1);
      snprintf(nb.uuid, sizeof(nb.uuid), "%s", arg2);
      nb.has_pub = true;
      nb.ts = time(NULL);
      state->trusted_bots[state->trusted_bot_count++] = nb;
      config_write_with_state_pass(state);
      char fp[KEY_FP_LEN + 1];
      crypto_key_fingerprint(nb.pub, fp);
      irc_printf(state, "PRIVMSG %s :Added trusted bot: %s (key %s)\r\n", nick,
                 arg1, fp);
    } else if (strcasecmp(command, "-bot") == 0) {
      if (state->hub_count > 0) {
        irc_printf(state,
                   "PRIVMSG %s :Error: Bot management disabled when hub is configured. "
                   "Bot additions/deletions must be performed on the hub.\r\n",
                   nick);
        return;
      }
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: -bot <nick*!*user@hostmask.com>\r\n",
                   nick);
        return;
      }
      int found_index = -1;
      for (int i = 0; i < state->trusted_bot_count; i++) {
        if (strcasecmp(state->trusted_bots[i].mask, arg1) == 0) {
          found_index = i;
          break;
        }
      }
      if (found_index != -1) {
        memmove(&state->trusted_bots[found_index],
                &state->trusted_bots[found_index + 1],
                (size_t)(state->trusted_bot_count - found_index - 1) *
                    sizeof(trusted_bot_t));
        state->trusted_bot_count--;
        memset(&state->trusted_bots[state->trusted_bot_count], 0,
               sizeof(trusted_bot_t));
        config_write_with_state_pass(state);
        irc_printf(state, "PRIVMSG %s :Removed trusted bot: %s\r\n", nick,
                   arg1);
      } else {
        irc_printf(state, "PRIVMSG %s :Error: no trusted bot with mask '%s' "
                          "(see 'status').\r\n", nick, arg1);
      }
    } else if (strcasecmp(command, "status") == 0) {
#define ST_SEP  "+----------------------------------------------------------------------------"
#define ST_FOOT "`----------------------------------------------------------------------------"
#define ST_LINE "| "
      /* Uptime — bot process lifetime, independent of any connection */
      char uptime_str[64];
      if (state->bot_start_time > 0)
        status_fmt_elapsed(uptime_str, sizeof(uptime_str), state->bot_start_time);
      else
        snprintf(uptime_str, sizeof(uptime_str), "N/A");

      /* Network string — include port after hostname */
      char srv_buf[300] = "N/A";
      if (state->actual_server_name[0] != '\0') {
        int srv_port = 0;
        if (state->current_server_index > 0) {
          const char *sl = state->server_list[state->current_server_index - 1];
          const char *colon = sl ? strrchr(sl, ':') : NULL;
          if (colon) srv_port = atoi(colon + 1);
        }
        if (srv_port > 0)
          snprintf(srv_buf, sizeof(srv_buf), "%s:%d", state->actual_server_name, srv_port);
        else
          snprintf(srv_buf, sizeof(srv_buf), "%s", state->actual_server_name);
      } else if (state->current_server_index > 0 &&
                 state->server_list[state->current_server_index - 1]) {
        snprintf(srv_buf, sizeof(srv_buf), "%s",
                 state->server_list[state->current_server_index - 1]);
      }
      const char *srv = srv_buf;
      /* Connected time on the Network line tracks the IRC link only */
      char conn_buf[80];
      if (state->status & S_CONNECTED) {
        if (state->connection_time > 0) {
          char irc_up_str[64];
          status_fmt_elapsed(irc_up_str, sizeof(irc_up_str), state->connection_time);
          snprintf(conn_buf, sizeof(conn_buf), "CONNECTED %s", irc_up_str);
        } else {
          snprintf(conn_buf, sizeof(conn_buf), "CONNECTED");
        }
      } else {
        snprintf(conn_buf, sizeof(conn_buf), "DISCONNECTED");
      }
      const char *conn_str = conn_buf;

      /* Count active admins and opers */
      int admin_count = 0, oper_count = 0;
      for (int i = 0; i < state->user_record_count; i++) {
        if (!state->user_records[i].is_active) continue;
        if (state->user_records[i].type == 'a') admin_count++;
        else if (state->user_records[i].type == 'o') oper_count++;
      }

      struct timespec st_delay = {0, 80000000}; /* 80ms anti-flood */

      irc_printf(state, "PRIVMSG %s :| ircbot %s status\r\n", nick, BOT_VERSION);
      irc_printf(state, "PRIVMSG %s :%s\r\n", nick, ST_SEP);
      irc_printf(state, "PRIVMSG %s :| Identity : %s (Target: %s) | UUID: %s\r\n",
                 nick, state->current_nick, state->target_nick,
                 state->bot_uuid[0] ? state->bot_uuid : "none");
      if (state->self_pub_set) {
        char *spb = base64_encode(state->self_pub, HUB_KEY_RAW_LEN);
        char sfp[KEY_FP_LEN + 1];
        crypto_key_fingerprint(state->self_pub, sfp);
        irc_printf(state, "PRIVMSG %s :| Pubkey   : %s (fp %s)\r\n", nick,
                   spb ? spb : "?", sfp);
        free(spb);
      } else {
        irc_printf(state, "PRIVMSG %s :| Pubkey   : NONE (re-run -setup)\r\n",
                   nick);
      }
      irc_printf(state, "PRIVMSG %s :| Uptime   : %s\r\n", nick, uptime_str);
      irc_printf(state, "PRIVMSG %s :| Network  : %s (%s, TLS: %s)\r\n",
                 nick, srv, conn_str, state->is_ssl ? "YES" : "NO");
      reply_pace(state, &st_delay);

      /* Servers section — only shown when multiple servers configured */
      if (state->server_count > 1) {
        irc_printf(state, "PRIVMSG %s :+-[ Servers ]---------------------------------------------------------------\r\n", nick);
        char srv_line[600] = ""; int soff = 0;
        for (int i = 0; i < state->server_count; i++) {
          const char *s = state->server_list[i];
          if (!s) continue;
          bool is_cur = (state->current_server_index > 0 &&
                         i == state->current_server_index - 1 &&
                         (state->status & S_CONNECTED));
          char held[64], entry[200];
          irc_server_block_desc(state, i, held, sizeof(held));
          snprintf(entry, sizeof(entry), "%s%s%s%s%s", is_cur ? "*" : " ", s,
                   held[0] ? " (" : "", held, held[0] ? ")" : "");
          int elen = (int)strlen(entry);
          if (soff > 0 && soff + 2 + elen < (int)sizeof(srv_line) - 1) {
            srv_line[soff++] = ','; srv_line[soff++] = ' ';
          }
          if (soff + elen < (int)sizeof(srv_line) - 1) {
            memcpy(srv_line + soff, entry, elen);
            soff += elen; srv_line[soff] = '\0';
          }
        }
        irc_printf(state, "PRIVMSG %s :| %s\r\n", nick, srv_line);
        reply_pace(state, &st_delay);
      }

      /* Channels section — collect IN and OUT into comma-wrapped lines */
      irc_printf(state, "PRIVMSG %s :+-[ Channels ]---------------------------------------------------------------\r\n", nick);
      {
        /* Build IN channel list */
        char in_buf[800] = "", out_buf[400] = "";
        int in_off = 0, out_off = 0;
        for (chan_t *c = state->chanlist; c; c = c->next) {
          if (!c->is_managed) continue;
          char entry[128];
          if (c->status == C_IN) {
            snprintf(entry, sizeof(entry), "%s%s",
                     c->i_am_opped ? "@" : "", c->name);
            int elen = (int)strlen(entry);
            if (in_off > 0 && in_off + 2 + elen < (int)sizeof(in_buf) - 1) {
              in_buf[in_off++] = ','; in_buf[in_off++] = ' ';
            }
            if (in_off + elen < (int)sizeof(in_buf) - 1) {
              memcpy(in_buf + in_off, entry, elen);
              in_off += elen; in_buf[in_off] = '\0';
            }
          } else {
            int elen = (int)strlen(c->name);
            if (out_off > 0 && out_off + 2 + elen < (int)sizeof(out_buf) - 1) {
              out_buf[out_off++] = ','; out_buf[out_off++] = ' ';
            }
            if (out_off + elen < (int)sizeof(out_buf) - 1) {
              memcpy(out_buf + out_off, c->name, elen);
              out_off += elen; out_buf[out_off] = '\0';
            }
          }
        }
        /* Word-wrap and send IN line(s): prefix "| (IN)  " = 8 chars, content 68 */
        if (in_buf[0]) {
          const char *pfx1 = "| (IN)  ", *pfx2 = "|        ";
          int cw = 68;
          char *p = in_buf; int first = 1;
          while (*p) {
            char seg[80]; int n = 0;
            while (*p && n < cw) seg[n++] = *p++;
            /* back up to last comma+space if not at end */
            if (*p) {
              int back = n;
              while (back > 0 && !(seg[back-1] == ' ' && back > 1 && seg[back-2] == ','))
                back--;
              if (back > 0) { p -= (n - back); n = back; }
            }
            seg[n] = '\0';
            irc_printf(state, "PRIVMSG %s :%s%s\r\n", nick, first ? pfx1 : pfx2, seg);
            first = 0;
          }
        } else {
          irc_printf(state, "PRIVMSG %s :| (IN)  (none)\r\n", nick);
        }
        if (out_buf[0])
          irc_printf(state, "PRIVMSG %s :| (OUT) %s\r\n", nick, out_buf);
      }
      reply_pace(state, &st_delay);

      /* Access Control — counts only */
      irc_printf(state, "PRIVMSG %s :+-[ Access Control ]---------------------------------------------------------\r\n", nick);
      irc_printf(state, "PRIVMSG %s :| Admins : %-4d  Ops: %d\r\n",
                 nick, admin_count, oper_count);
      reply_pace(state, &st_delay);

      /* Hub Config or standalone Bots section */
#define HUB_TRUST_MAX 100
#define BOTS_PFX1 "| Bots   : "
#define BOTS_PFX2 "|          "
#define BOTS_CW   66
      if (state->hub_count > 0) {
        /* Hub is configured — show full Hub Config */
        irc_printf(state, "PRIVMSG %s :+-[ Hub Config ]-------------------------------------------------------------\r\n", nick);
        if (state->hub_connected && state->current_hub[0]) {
          if (state->hub_connect_time > 0 && state->hub_authenticated) {
            char hub_up_str[64];
            status_fmt_elapsed(hub_up_str, sizeof(hub_up_str),
                               state->hub_connect_time);
            irc_printf(state, "PRIVMSG %s :| Hub    : %s (CONNECTED %s)\r\n",
                       nick, state->current_hub, hub_up_str);
          } else {
            irc_printf(state, "PRIVMSG %s :| Hub    : %s (CONNECTED)\r\n",
                       nick, state->current_hub);
          }
        } else {
          irc_printf(state, "PRIVMSG %s :| Hub    : DISCONNECTED\r\n", nick);
        }
        /* Configured hubs */
        {
          char hubs_line[300] = ""; int hoff = 0;
          for (int i = 0; i < state->hub_count; i++) {
            int hlen = (int)strlen(state->hubs[i].addr);
            if (hoff) { hubs_line[hoff++] = ','; hubs_line[hoff++] = ' '; }
            if (hoff + hlen < (int)sizeof(hubs_line) - 1) {
              memcpy(hubs_line + hoff, state->hubs[i].addr, hlen);
              hoff += hlen; hubs_line[hoff] = '\0';
            }
          }
          irc_printf(state, "PRIVMSG %s :| Hubs   : %s\r\n", nick, hubs_line);
        }
        /* Bots — word-wrap, truncate after 100 */
        if (state->trusted_bot_count > 0) {
          char trust_line[512] = ""; int toff = 0;
          int first = 1, shown = 0;
          for (int i = 0; i < state->trusted_bot_count && shown < HUB_TRUST_MAX; i++, shown++) {
            char tname[MAX_NICK];
            auth_trusted_bot_nick(&state->trusted_bots[i], tname);
            int tlen = (int)strlen(tname);
            int need = toff ? tlen + 2 : tlen;
            if (toff && toff + need > BOTS_CW) {
              irc_printf(state, "PRIVMSG %s :%s%s\r\n", nick, first ? BOTS_PFX1 : BOTS_PFX2, trust_line);
              first = 0; toff = 0; trust_line[0] = '\0';
            }
            if (toff) { trust_line[toff++] = ','; trust_line[toff++] = ' '; }
            memcpy(trust_line + toff, tname, tlen);
            toff += tlen; trust_line[toff] = '\0';
          }
          if (toff)
            irc_printf(state, "PRIVMSG %s :%s%s\r\n", nick, first ? BOTS_PFX1 : BOTS_PFX2, trust_line);
          if (state->trusted_bot_count > HUB_TRUST_MAX)
            irc_printf(state, "PRIVMSG %s :|          ...and %d more\r\n", nick,
                       state->trusted_bot_count - HUB_TRUST_MAX);
        } else {
          irc_printf(state, "PRIVMSG %s :| Bots   : (none)\r\n", nick);
        }
        irc_printf(state, "PRIVMSG %s :%s\r\n", nick, ST_FOOT);
      } else if (state->trusted_bot_count > 0) {
        /* No hub — standalone bot-to-bot mode, show Bots section only */
        irc_printf(state, "PRIVMSG %s :+-[ Bots ]-------------------------------------------------------------------\r\n", nick);
        char trust_line[512] = ""; int toff = 0;
        int first = 1, shown = 0;
        for (int i = 0; i < state->trusted_bot_count && shown < HUB_TRUST_MAX; i++, shown++) {
          char tname[MAX_NICK];
          auth_trusted_bot_nick(&state->trusted_bots[i], tname);
          int tlen = (int)strlen(tname);
          int need = toff ? tlen + 2 : tlen;
          if (toff && toff + need > BOTS_CW) {
            irc_printf(state, "PRIVMSG %s :%s%s\r\n", nick, first ? BOTS_PFX1 : BOTS_PFX2, trust_line);
            first = 0; toff = 0; trust_line[0] = '\0';
          }
          if (toff) { trust_line[toff++] = ','; trust_line[toff++] = ' '; }
          memcpy(trust_line + toff, tname, tlen);
          toff += tlen; trust_line[toff] = '\0';
        }
        if (toff)
          irc_printf(state, "PRIVMSG %s :%s%s\r\n", nick, first ? BOTS_PFX1 : BOTS_PFX2, trust_line);
        if (state->trusted_bot_count > HUB_TRUST_MAX)
          irc_printf(state, "PRIVMSG %s :|          ...and %d more\r\n", nick,
                     state->trusted_bot_count - HUB_TRUST_MAX);
        irc_printf(state, "PRIVMSG %s :%s\r\n", nick, ST_FOOT);
      } else {
        /* No hub, no bots — just close the box */
        irc_printf(state, "PRIVMSG %s :%s\r\n", nick, ST_FOOT);
      }
#undef HUB_TRUST_MAX
#undef BOTS_PFX1
#undef BOTS_PFX2
#undef BOTS_CW
#undef ST_SEP
#undef ST_FOOT
#undef ST_LINE
    } else if (strcasecmp(command, "givenick") == 0) {
      irc_printf(state,
                 "PRIVMSG %s :You have about %d seconds to retrieve.\r\n", nick,
                 NICK_TAKE_TIME);
      irc_generate_new_nick(state);
      state->nick_release_time = time(NULL);
    } else if (strcasecmp(command, "chnick") == 0) {
      if (!arg1 || !arg2) {
        irc_printf(state, "PRIVMSG %s :Syntax: chnick <oldnick> <newnick>\r\n", nick);
        return;
      }
      if (!is_valid_bot_nick(arg2)) {
        if (strchr(arg2, '|'))
          irc_printf(state,
              "PRIVMSG %s :Error: New nick cannot contain '|'.\r\n", nick);
        else
          irc_printf(state,
              "PRIVMSG %s :Error: New nick too long (max %d chars).\r\n",
              nick, MAX_NICK - 1);
        return;
      }
      /* Uniqueness check: newnick must not already exist in any type */
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].is_active &&
            strcasecmp(state->user_records[i].name, arg2) == 0) {
          irc_printf(state, "PRIVMSG %s :Error: Name '%s' already in use.\r\n",
                     nick, arg2);
          return;
        }
      }
      if (strcasecmp(state->target_nick, arg2) == 0) {
        irc_printf(state, "PRIVMSG %s :Error: Name '%s' already in use by this bot.\r\n",
                   nick, arg2);
        return;
      }
      for (int i = 0; i < state->trusted_bot_count; i++) {
        char bnick[MAX_NICK];
        auth_trusted_bot_nick(&state->trusted_bots[i], bnick);
        if (strcasecmp(bnick, arg2) == 0) {
          irc_printf(state, "PRIVMSG %s :Error: Name '%s' already in use by a bot.\r\n",
                     nick, arg2);
          return;
        }
      }
      /* A bot's new name is its IRC nick, so it must be one the ircd takes;
       * admin/oper names are account names and keep the rule above. */
      static const char *const rfc_nick_err =
          "PRIVMSG %s :Error: '%s' is not a valid IRC nick: a letter or one "
          "of []\\`_^{} first, then letters, digits, those or '-'.\r\n";
      bool cn_found = false;
      /* Case 1: this bot's own target nick */
      if (strcasecmp(state->target_nick, arg1) == 0) {
        if (!is_rfc_nick(arg2)) {
          irc_printf(state, rfc_nick_err, nick, arg2);
          return;
        }
        snprintf(state->target_nick, MAX_NICK, "%s", arg2);
        state->current_nick_ts = time(NULL);
        config_write_with_state_pass(state);
        hub_client_push_delta(state, "n", arg2, state->current_nick_ts);
        irc_printf(state, "PRIVMSG %s :This bot's nick changed to '%s' and saved.\r\n",
                   nick, arg2);
        cn_found = true;
      }
      /* Case 2: admin or oper */
      if (!cn_found) {
        for (int i = 0; i < state->user_record_count; i++) {
          user_record_t *u = &state->user_records[i];
          if (u->is_active && strcasecmp(u->name, arg1) == 0) {
            snprintf(u->name, sizeof(u->name), "%s", arg2);
            u->timestamp = lww_next_ts(u->timestamp);
            config_write_with_state_pass(state);
            hub_client_push_admin_delta(state);
            irc_printf(state, "PRIVMSG %s :User '%s' renamed to '%s'.\r\n",
                       nick, arg1, arg2);
            cn_found = true;
            break;
          }
        }
      }
      /* Case 3: trusted bot */
      if (!cn_found) {
        for (int i = 0; i < state->trusted_bot_count; i++) {
          trusted_bot_t *tb = &state->trusted_bots[i];
          char bnick[MAX_NICK];
          auth_trusted_bot_nick(tb, bnick);
          if (strcasecmp(bnick, arg1) != 0) continue;
          if (!is_rfc_nick(arg2)) {
            irc_printf(state, rfc_nick_err, nick, arg2);
            return;
          }
          /* Replace the nick part of the mask (up to '!') */
          char newmask[MAX_MASK_LEN] = "";
          const char *bang = strchr(tb->mask, '!');
          int nm = bang ? snprintf(newmask, sizeof(newmask), "%s%s", arg2, bang)
                        : snprintf(newmask, sizeof(newmask), "%s", arg2);
          if (nm < 0 || nm >= (int)sizeof(newmask)) {
            irc_printf(state, "PRIVMSG %s :Error: resulting mask too long.\r\n",
                       nick);
            return;
          }
          /* Notify first: the sealed SETNICK is addressed by the bot's
           * current (old) nick, which the lookup reads from this entry. */
          bot_comms_send_command(state, arg1, "SETNICK %s", arg2);
          snprintf(tb->mask, sizeof(tb->mask), "%s", newmask);
          tb->ts = time(NULL);
          config_write_with_state_pass(state);
          irc_printf(state, "PRIVMSG %s :Bot '%s' renamed to '%s' and notified.\r\n",
                     nick, arg1, arg2);
          cn_found = true;
          break;
        }
      }
      if (!cn_found)
        irc_printf(state, "PRIVMSG %s :Error: No bot/admin/oper named '%s' found.\r\n",
                   nick, arg1);
    } else if (strcasecmp(command, "saveconf") == 0) {
      config_write_with_state_pass(state);
      irc_printf(state, "PRIVMSG %s :Configuration state saved to %s.\r\n",
                 nick, CONFIG_FILE);
    } else if (strcasecmp(command, "setlog") == 0) {
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: setlog <loglevel> :: LOGLEVELS: "
                   "0=NONE,15=INFO,63=DEBUG\r\n",
                   nick);
        return;
      }
      bool is_valid_int = true;
      for (int i = 0; arg1[i] != '\0'; i++)
        if (!isdigit(arg1[i])) {
          is_valid_int = false;
          break;
        }
      if (is_valid_int) {
        int new_level = atoi(arg1);
        state->log_type = (log_type_t)new_level;
        irc_printf(state, "PRIVMSG %s :Log level set to %d.\r\n", nick,
                   new_level);
        config_write_with_state_pass(state);
      } else
        irc_printf(state,
                   "PRIVMSG %s :Invalid log level. Please provide a valid "
                   "integer.\r\n",
                   nick);
    } else if (strcasecmp(command, "getlog") == 0) {
      if (!arg1) {
        irc_printf(
            state,
            "PRIVMSG %s :Syntax: getlog <level> [lines]. Levels are 'msg' "
            "'ctcp' 'info' 'cmd' 'raw' 'debug'. Default: %d. Max: %d.\r\n",
            nick, DEFAULT_LOG_LINES, MAX_LOG_LINES);
        return;
      }
      int buffer_index = -1;
      if (strcasecmp(arg1, "msg") == 0)
        buffer_index = 0;
      else if (strcasecmp(arg1, "ctcp") == 0)
        buffer_index = 1;
      else if (strcasecmp(arg1, "info") == 0)
        buffer_index = 2;
      else if (strcasecmp(arg1, "cmd") == 0)
        buffer_index = 3;
      else if (strcasecmp(arg1, "raw") == 0)
        buffer_index = 4;
      else if (strcasecmp(arg1, "debug") == 0)
        buffer_index = 5;

      if (buffer_index == -1) {
        irc_printf(state, "PRIVMSG %s :Error: Unknown log level '%s'.\r\n",
                   nick, arg1);
        return;
      }

      int lines_to_show = DEFAULT_LOG_LINES;
      if (arg2) {
        lines_to_show = atoi(arg2);
        if (lines_to_show <= 0)
          lines_to_show = DEFAULT_LOG_LINES;
        if (lines_to_show > MAX_LOG_LINES) {
          irc_printf(state, "PRIVMSG %s :Warning: Line count capped at %d.\r\n",
                     nick, MAX_LOG_LINES);
          lines_to_show = MAX_LOG_LINES;
        }
      }

      log_entry_t *matches[LOG_BUFFER_LINES];
      int matches_found = 0;
      log_buffer_t *log_buf_ptr = &state->in_memory_logs[buffer_index];

      for (int i = 0; i < LOG_BUFFER_LINES; i++) {
        int idx = (log_buf_ptr->log_idx + i) % LOG_BUFFER_LINES;
        log_entry_t *entry = &log_buf_ptr->entries[idx];
        if (entry->line[0] != '\0')
          matches[matches_found++] = entry;
      }

      int lines_to_print =
          (matches_found < lines_to_show) ? matches_found : lines_to_show;
      int start_index = matches_found - lines_to_print;
      irc_printf(state,
                 "PRIVMSG %s :--- Start of Log (%s) - Showing last %d of %d "
                 "lines --- \r\n",
                 nick, arg1, lines_to_print, matches_found);

      struct timespec delay = {0, 250000000};
      for (int i = matches_found - 1; i >= start_index; i--) {
        irc_printf(state, "PRIVMSG %s :%s\r\n", nick, matches[i]->line);
        reply_pace(state, &delay);
      }
      irc_printf(state, "PRIVMSG %s :--- End of Log (%s) --- \r\n", nick, arg1);
    } else if (strcasecmp(command, "admins") == 0) {
      struct timespec delay = {0, 100000000};
      /* Find max name width for alignment (min 8) */
      int name_w = 8;
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].type != 'a') continue;
        int nl = (int)strlen(state->user_records[i].name);
        if (nl > name_w) name_w = nl;
      }
      irc_printf(state, "PRIVMSG %s :| ircbot %s admins\r\n", nick, BOT_VERSION);
      irc_printf(state, "PRIVMSG %s :+----------------------------------------------------------------------------\r\n", nick);
      int shown = 0;
      for (int i = 0; i < state->user_record_count && shown < BOT_STATUS_MAX_LINES; i++) {
        user_record_t *u = &state->user_records[i];
        if (u->type != 'a') continue;
        char ts_buf[48];
        if (u->last_seen == 0) {
          snprintf(ts_buf, sizeof(ts_buf), "never");
        } else {
          struct tm *tm = gmtime(&u->last_seen);
          if (tm) strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S UTC", tm);
          else    snprintf(ts_buf, sizeof(ts_buf), "invalid");
        }
        char del_tag[16] = "";
        if (!u->is_active) snprintf(del_tag, sizeof(del_tag), " [deleted]");
        char kfp[KEY_FP_LEN + 1];
        user_key_fp(u, kfp);
        irc_printf(state, "PRIVMSG %s :| %-*s  key %s  (last seen: %s)%s\r\n",
                   nick, name_w, u->name, kfp, ts_buf, del_tag);
        shown++;
        reply_pace(state, &delay);
      }
      if (shown == 0)
        irc_printf(state, "PRIVMSG %s :| (no admins)\r\n", nick);
      irc_printf(state, "PRIVMSG %s :`----------------------------------------------------------------------------\r\n", nick);

    } else if (strcasecmp(command, "opers") == 0) {
      struct timespec delay = {0, 100000000};
      int name_w = 8;
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].type != 'o') continue;
        int nl = (int)strlen(state->user_records[i].name);
        if (nl > name_w) name_w = nl;
      }
      irc_printf(state, "PRIVMSG %s :| ircbot %s opers\r\n", nick, BOT_VERSION);
      irc_printf(state, "PRIVMSG %s :+----------------------------------------------------------------------------\r\n", nick);
      int shown = 0;
      for (int i = 0; i < state->user_record_count && shown < BOT_STATUS_MAX_LINES; i++) {
        user_record_t *u = &state->user_records[i];
        if (u->type != 'o') continue;
        char ts_buf[48];
        if (u->last_seen == 0) {
          snprintf(ts_buf, sizeof(ts_buf), "never");
        } else {
          struct tm *tm = gmtime(&u->last_seen);
          if (tm) strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S UTC", tm);
          else    snprintf(ts_buf, sizeof(ts_buf), "invalid");
        }
        char del_tag[16] = "";
        if (!u->is_active) snprintf(del_tag, sizeof(del_tag), " [deleted]");
        char kfp[KEY_FP_LEN + 1];
        user_key_fp(u, kfp);
        irc_printf(state, "PRIVMSG %s :| %-*s  key %s  (last seen: %s)%s\r\n",
                   nick, name_w, u->name, kfp, ts_buf, del_tag);
        shown++;
        reply_pace(state, &delay);
      }
      if (shown == 0)
        irc_printf(state, "PRIVMSG %s :| (no opers)\r\n", nick);
      irc_printf(state, "PRIVMSG %s :`----------------------------------------------------------------------------\r\n", nick);

    } else if (strcasecmp(command, "match") == 0) {
      /* Show active records for named user or * for all */
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: match <name|*>\r\n", nick);
        return;
      }
      bool match_all = (strcmp(arg1, "*") == 0);
      irc_printf(state, "PRIVMSG %s :| ircbot %s match%s\r\n", nick, BOT_VERSION,
                 match_all ? " *" : "");
      irc_printf(state, "PRIVMSG %s :+----------------------------------------------------------------------------\r\n", nick);
      struct timespec delay = {0, 100000000};
      int shown = 0;
      for (int i = 0; i < state->user_record_count; i++) {
        user_record_t *u = &state->user_records[i];
        if (!match_all && strcasecmp(u->name, arg1) != 0) continue;
        if (!u->is_active) continue;
        char ts_buf[48];
        if (u->last_seen == 0) {
          snprintf(ts_buf, sizeof(ts_buf), "never");
        } else {
          struct tm *tm_utc = gmtime(&u->last_seen);
          if (tm_utc) strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S UTC", tm_utc);
          else        snprintf(ts_buf, sizeof(ts_buf), "invalid");
        }
        char kfp[KEY_FP_LEN + 1];
        user_key_fp(u, kfp);
        irc_printf(state, "PRIVMSG %s :| [%c] %-20s  key %s  (last seen: %s)\r\n",
                   nick, u->type, u->name, kfp, ts_buf);
        reply_pace(state, &delay);
        for (int j = 0; j < state->mask_record_count; j++) {
          mask_record_t *m = &state->mask_records[j];
          if (strcmp(m->uuid, u->uuid) != 0) continue;
          if (!m->is_active) continue;
          char used_buf[48];
          if (m->last_used == 0) {
            snprintf(used_buf, sizeof(used_buf), "never");
          } else {
            struct tm *tm_used = gmtime(&m->last_used);
            if (tm_used) strftime(used_buf, sizeof(used_buf), "%Y-%m-%d %H:%M:%S UTC", tm_used);
            else         snprintf(used_buf, sizeof(used_buf), "invalid");
          }
          irc_printf(state, "PRIVMSG %s :|   %s  (last used: %s)\r\n",
                     nick, m->mask, used_buf);
          reply_pace(state, &delay);
          if (++shown >= BOT_STATUS_MAX_LINES) goto match_done;
        }
      }
      /* If no user record found and not wildcard, check trusted bots */
      if (shown == 0 && !match_all) {
        for (int i = 0; i < state->trusted_bot_count; i++) {
          const trusted_bot_t *tb = &state->trusted_bots[i];
          const char *bot_mask = tb->mask, *bot_uuid = tb->uuid;
          long long bot_ts = (long long)tb->ts;
          char bot_nick[MAX_NICK];
          auth_trusted_bot_nick(tb, bot_nick);
          if (strcasecmp(bot_nick, arg1) != 0) continue;
          /* Found a matching bot */
          char ts_buf[48];
          if (bot_ts == 0) {
            snprintf(ts_buf, sizeof(ts_buf), "never");
          } else {
            time_t bts = (time_t)bot_ts;
            struct tm *tm_utc = gmtime(&bts);
            if (tm_utc) strftime(ts_buf, sizeof(ts_buf), "%Y-%m-%d %H:%M:%S UTC", tm_utc);
            else        snprintf(ts_buf, sizeof(ts_buf), "invalid");
          }
          irc_printf(state, "PRIVMSG %s :| [b] %-20s  (last seen: %s)\r\n",
                     nick, bot_nick, ts_buf);
          reply_pace(state, &delay);
          if (bot_mask[0])
            irc_printf(state, "PRIVMSG %s :|   mask: %s\r\n", nick, bot_mask);
          if (bot_uuid[0])
            irc_printf(state, "PRIVMSG %s :|   uuid: %s\r\n", nick, bot_uuid);
          if (tb->has_pub) {
            char bfp[KEY_FP_LEN + 1];
            crypto_key_fingerprint(tb->pub, bfp);
            irc_printf(state, "PRIVMSG %s :|   key : %s\r\n", nick, bfp);
          } else {
            irc_printf(state, "PRIVMSG %s :|   key : (none on file)\r\n", nick);
          }
          const char *hub_str = (state->hub_connected && state->current_hub[0])
                                ? state->current_hub : "none";
          irc_printf(state, "PRIVMSG %s :|   hub : %s\r\n", nick, hub_str);
          shown++;
          reply_pace(state, &delay);
          break;
        }
      }
      if (shown == 0 && !match_all)
        irc_printf(state, "PRIVMSG %s :| unknown user: %s\r\n", nick, arg1);
      match_done:
      irc_printf(state, "PRIVMSG %s :`----------------------------------------------------------------------------\r\n", nick);

    } else if (strcasecmp(command, "+admin") == 0 ||
               strcasecmp(command, "+oper") == 0) {
      /* +admin|+oper <name> <pubkey> <nick!user@host>.  The user makes their
       * own keypair and hands over only the public half, so nothing secret
       * travels and the bot never mints or delivers a key. */
      const bool add_admin = (strcasecmp(command, "+admin") == 0);
      const char *what = add_admin ? "+admin" : "+oper";
      if (!arg1 || !arg2 || !arg3) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: %s <name> <pubkey> <nick!user@host> - "
                   "<pubkey> is the user's 88-char public key. Ask them for "
                   "it; 'help %s' shows how they make one.\r\n",
                   nick, what, what);
        return;
      }
      if (strlen(arg1) > 63) {
        irc_printf(state, "PRIVMSG %s :Error: name too long (max 63).\r\n", nick);
        return;
      }
      if (!strchr(arg3, '!') || !strchr(arg3, '@') ||
          strlen(arg3) >= MAX_MASK_LEN) {
        irc_printf(state, "PRIVMSG %s :Error: mask must be nick!user@host "
                          "(max %d chars)\r\n", nick, MAX_MASK_LEN - 1);
        return;
      }
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].is_active &&
            strcasecmp(state->user_records[i].name, arg1) == 0) {
          irc_printf(state, "PRIVMSG %s :Error: name '%s' already exists.\r\n",
                     nick, arg1);
          return;
        }
      }
      if (!user_key_arg_ok(state, nick, arg2, NULL, what)) return;
      if (state->user_record_count >= MAX_USER_RECORDS) {
        irc_printf(state, "PRIVMSG %s :Error: user record table full.\r\n", nick);
        return;
      }
      if (state->mask_record_count >= MAX_USER_MASKS) {
        irc_printf(state, "PRIVMSG %s :Error: mask table full.\r\n", nick);
        return;
      }
      /* Generate UUID using random bytes */
      unsigned char rnd[16];
      if (RAND_bytes(rnd, sizeof(rnd)) != 1) {
        irc_printf(state, "PRIVMSG %s :Error: RNG failure.\r\n", nick);
        return;
      }
      rnd[6]=(rnd[6]&0x0f)|0x40; rnd[8]=(rnd[8]&0x3f)|0x80;
      char new_uuid[37];
      snprintf(new_uuid, sizeof(new_uuid),
               "%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x",
               rnd[0],rnd[1],rnd[2],rnd[3],rnd[4],rnd[5],rnd[6],rnd[7],
               rnd[8],rnd[9],rnd[10],rnd[11],rnd[12],rnd[13],rnd[14],rnd[15]);
      time_t now = time(NULL);
      user_record_t *u = &state->user_records[state->user_record_count++];
      memset(u, 0, sizeof(*u));
      snprintf(u->uuid, sizeof(u->uuid), "%s", new_uuid);
      snprintf(u->name, sizeof(u->name), "%s", arg1);
      snprintf(u->pubkey_b64, sizeof(u->pubkey_b64), "%s", arg2);
      u->has_pubkey = true;
      u->type = add_admin ? 'a' : 'o';
      u->is_active = true; u->timestamp = now;
      mask_record_t *m = &state->mask_records[state->mask_record_count++];
      memset(m, 0, sizeof(*m));
      snprintf(m->uuid, sizeof(m->uuid), "%s", new_uuid);
      snprintf(m->mask, sizeof(m->mask), "%s", arg3);
      m->is_active = true; m->timestamp = now;
      config_write_with_state_pass(state);
      hub_client_push_admin_delta(state);
      char kfp[KEY_FP_LEN + 1];
      user_key_fp(u, kfp);
      irc_printf(state, "PRIVMSG %s :%s '%s' added with mask %s (key %s)\r\n",
                 nick, add_admin ? "Admin" : "Oper", arg1, arg3, kfp);

    } else if (strcasecmp(command, "-admin") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: -admin <name>\r\n", nick); return;
      }
      user_record_t *target = NULL;
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].is_active && state->user_records[i].type=='a' &&
            strcasecmp(state->user_records[i].name, arg1) == 0) {
          target = &state->user_records[i]; break;
        }
      }
      if (!target) { irc_printf(state, "PRIVMSG %s :Error: admin '%s' not found.\r\n", nick, arg1); return; }
      target->is_active = false;
      target->timestamp = lww_next_ts(target->timestamp);
      for (int i = 0; i < state->mask_record_count; i++)
        if (strcmp(state->mask_records[i].uuid, target->uuid) == 0) {
          state->mask_records[i].is_active = false;
          state->mask_records[i].timestamp =
              lww_next_ts(state->mask_records[i].timestamp);
        }
      config_write_with_state_pass(state);
      hub_client_push_admin_delta(state);
      irc_printf(state, "PRIVMSG %s :Admin '%s' and all their masks removed.\r\n", nick, arg1);

    } else if (strcasecmp(command, "-oper") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: -oper <name>\r\n", nick); return;
      }
      user_record_t *target_o = NULL;
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].is_active && state->user_records[i].type=='o' &&
            strcasecmp(state->user_records[i].name, arg1) == 0) {
          target_o = &state->user_records[i]; break;
        }
      }
      if (!target_o) { irc_printf(state, "PRIVMSG %s :Error: oper '%s' not found.\r\n", nick, arg1); return; }
      target_o->is_active = false;
      target_o->timestamp = lww_next_ts(target_o->timestamp);
      for (int i = 0; i < state->mask_record_count; i++)
        if (strcmp(state->mask_records[i].uuid, target_o->uuid) == 0) {
          state->mask_records[i].is_active = false;
          state->mask_records[i].timestamp =
              lww_next_ts(state->mask_records[i].timestamp);
        }
      config_write_with_state_pass(state);
      hub_client_push_admin_delta(state);
      irc_printf(state, "PRIVMSG %s :Oper '%s' and all their masks removed.\r\n", nick, arg1);

    } else if (strcasecmp(command, "+usermask") == 0) {
      /* +usermask <name> <mask> */
      if (!arg1 || !arg2) {
        irc_printf(state, "PRIVMSG %s :Syntax: +usermask <name> <nick!user@host>\r\n", nick); return;
      }
      if (!strchr(arg2,'!') || !strchr(arg2,'@')) {
        irc_printf(state, "PRIVMSG %s :Error: mask must contain ! and @\r\n", nick); return;
      }
      user_record_t *tum = NULL;
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].is_active &&
            strcasecmp(state->user_records[i].name, arg1) == 0) {
          tum = &state->user_records[i]; break;
        }
      }
      if (!tum) { irc_printf(state, "PRIVMSG %s :Error: user '%s' not found.\r\n", nick, arg1); return; }
      mask_record_t *old_m = NULL;   /* a tombstone for this exact mask */
      for (int i = 0; i < state->mask_record_count; i++) {
        if (strcmp(state->mask_records[i].uuid, tum->uuid) != 0 ||
            strcasecmp(state->mask_records[i].mask, arg2) != 0)
          continue;
        if (state->mask_records[i].is_active) {
          irc_printf(state, "PRIVMSG %s :Error: mask already exists.\r\n", nick); return;
        }
        old_m = &state->mask_records[i];
      }
      if (old_m) {
        /* Revive the tombstone past its stamp: a second record for the same
         * uuid+mask could tie with the remove and lose on the hub. */
        old_m->is_active = true;
        old_m->timestamp = lww_next_ts(old_m->timestamp);
        config_write_with_state_pass(state);
        hub_client_push_admin_delta(state);
        irc_printf(state, "PRIVMSG %s :Mask %s added to %s\r\n", nick, arg2, arg1);
        return;
      }
      if (state->mask_record_count >= MAX_USER_MASKS) {
        irc_printf(state, "PRIVMSG %s :Error: mask table full.\r\n", nick); return;
      }
      char tum_uuid[37]; snprintf(tum_uuid, sizeof(tum_uuid), "%s", tum->uuid);
      mask_record_t *nm = &state->mask_records[state->mask_record_count++];
      memset(nm, 0, sizeof(*nm));
      snprintf(nm->uuid, sizeof(nm->uuid), "%s", tum_uuid);
      snprintf(nm->mask, sizeof(nm->mask), "%s", arg2);
      nm->is_active = true; nm->timestamp = time(NULL);
      config_write_with_state_pass(state);
      hub_client_push_admin_delta(state);
      irc_printf(state, "PRIVMSG %s :Mask %s added to %s\r\n", nick, arg2, arg1);

    } else if (strcasecmp(command, "-usermask") == 0) {
      /* -usermask <name> <mask> */
      if (!arg1 || !arg2) {
        irc_printf(state, "PRIVMSG %s :Syntax: -usermask <name> <mask>\r\n", nick); return;
      }
      user_record_t *dum = NULL;
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].is_active &&
            strcasecmp(state->user_records[i].name, arg1) == 0) {
          dum = &state->user_records[i]; break;
        }
      }
      if (!dum) { irc_printf(state, "PRIVMSG %s :Error: user '%s' not found.\r\n", nick, arg1); return; }
      mask_record_t *fdm = NULL;
      for (int i = 0; i < state->mask_record_count; i++) {
        if (state->mask_records[i].is_active &&
            strcmp(state->mask_records[i].uuid, dum->uuid) == 0 &&
            strcasecmp(state->mask_records[i].mask, arg2) == 0) {
          fdm = &state->mask_records[i]; break;
        }
      }
      if (!fdm) { irc_printf(state, "PRIVMSG %s :Error: mask '%s' not found for %s.\r\n", nick, arg2, arg1); return; }
      fdm->is_active = false;
      fdm->timestamp = lww_next_ts(fdm->timestamp);
      config_write_with_state_pass(state);
      hub_client_push_admin_delta(state);
      irc_printf(state, "PRIVMSG %s :Mask %s removed from %s\r\n", nick, arg2, arg1);

    } else if (strcasecmp(command, "+server") == 0) {
      if (!arg1) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: +server <irc.server.net:6667>\r\n",
                   nick);
        return;
      }
      if (state->server_count < MAX_SERVERS) {
        char *dup = strdup(arg1);
        if (!dup) return;
        irc_server_block_clear(state, state->server_count); /* fresh slot */
        state->server_list[state->server_count++] = dup;
        state->server_list[state->server_count] = NULL;
        config_write_with_state_pass(state);
        irc_printf(state, "PRIVMSG %s :Added server '%s' and saved config.\r\n",
                   nick, arg1);
      } else
        irc_printf(state, "PRIVMSG %s :Error: Server list is full.\r\n", nick);
    } else if (strcasecmp(command, "-server") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: -server <server>\r\n", nick);
        return;
      }
      int found_index = -1;
      for (int i = 0; i < state->server_count; i++)
        if (strcasecmp(state->server_list[i], arg1) == 0) {
          found_index = i;
          break;
        }
      if (found_index != -1) {
        irc_server_block_remove(state, found_index); /* before compaction */
        free(state->server_list[found_index]);
        for (int i = found_index; i < state->server_count - 1; i++)
          state->server_list[i] = state->server_list[i + 1];
        state->server_count--;
        state->server_list[state->server_count] = NULL;
        config_write_with_state_pass(state);
        irc_printf(state,
                   "PRIVMSG %s :Removed server '%s' and saved config.\r\n",
                   nick, arg1);
      }
    } else if (strcasecmp(command, "update") == 0) {
      if (arg1)
        updater_perform_upgrade(state, nick, arg1);
      else
        updater_check_for_updates(state, nick);
    } else if (strcasecmp(command, "+hub") == 0) {
      /* +hub <host:port> <pubkey-b64>
       * The pubkey is the hub's pinned long-term Ed25519 public key — either
       * 44-char base64 (raw 32-byte Ed25519) or 88-char base64 (combined
       * 64-byte Curve25519 pubkey, first 32 bytes used; same as the hub's
       * hub_public.b64). Per-hub keypairs mean the pinned key is REQUIRED:
       * the bot refuses to connect to a hub it can't authenticate. This
       * folds in the old 'sethubpub' behaviour per hub. */
      if (!arg1 || !arg2) {
        irc_printf(state,
                   "PRIVMSG %s :Syntax: +hub <host:port> <pubkey-b64>\r\n",
                   nick);
        return;
      }
      /* Validate address has a host and a numeric port. */
      const char *colon = strrchr(arg1, ':');
      if (!colon || colon == arg1 || atoi(colon + 1) <= 0) {
        irc_printf(state,
                   "PRIVMSG %s :Error: address must be HOST:PORT (e.g. "
                   "hub.example.com:7000).\r\n", nick);
        return;
      }
      /* Duplicate check (by address). */
      for (int i = 0; i < state->hub_count; i++) {
        if (strcmp(state->hubs[i].addr, arg1) == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Error: Hub '%s' already exists. Remove it "
                     "with -hub first to change its key.\r\n", nick, arg1);
          return;
        }
      }
      if (state->hub_count >= MAX_SERVERS) {
        irc_printf(state, "PRIVMSG %s :Error: Hub list is full.\r\n", nick);
        return;
      }
      /* Validate + decode the pinned pubkey. */
      int dec_len = 0;
      unsigned char *dec = base64_decode(arg2, &dec_len);
      if (!dec || (dec_len != 32 && dec_len != HUB_KEY_RAW_LEN)) {
        irc_printf(state,
                   "PRIVMSG %s :Error: pubkey must be base64 of a 32-byte "
                   "Ed25519 key (44 chars) or 64-byte combined Curve25519 "
                   "key (88 chars).\r\n", nick);
        if (dec) free(dec);
        return;
      }
      hub_entry_t *he = &state->hubs[state->hub_count];
      memset(he, 0, sizeof(*he));
      snprintf(he->addr, sizeof(he->addr), "%s", arg1);
      memcpy(he->ed_pub, dec, 32);
      he->ed_pub_set = true;
      secure_wipe(dec, (size_t)dec_len);
      free(dec);
      state->hub_count++;
      config_write_with_state_pass(state);
      irc_printf(state,
                 "PRIVMSG %s :Added Hub: %s (pubkey pinned)\r\n", nick, arg1);
      /* If we are not connected to any hub yet, try the new one now. */
      if (state->hub_fd == -1) {
        state->last_hub_connect_attempt = 0;
        hub_client_connect(state);
      }
    } else if (strcasecmp(command, "-hub") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s :Syntax: -hub <host:port>\r\n", nick);
        return;
      }
      int found = -1;
      for (int i = 0; i < state->hub_count; i++)
        if (strcmp(state->hubs[i].addr, arg1) == 0) {
          found = i;
          break;
        }
      if (found != -1) {
        // Check if this is the currently connected hub
        bool is_current_hub = (state->hub_connected &&
                               strcmp(state->current_hub, arg1) == 0);

        // If removing the currently connected hub, disconnect first
        if (is_current_hub) {
          irc_printf(state, "PRIVMSG %s :Disconnecting from current hub: %s\r\n",
                     nick, arg1);
          hub_client_disconnect(state);
        }

        // Remove the hub from the list (shift entries down, wiping the key)
        secure_wipe(state->hubs[found].ed_pub, sizeof(state->hubs[found].ed_pub));
        for (int i = found; i < state->hub_count - 1; i++)
          state->hubs[i] = state->hubs[i + 1];
        state->hub_count--;
        memset(&state->hubs[state->hub_count], 0,
               sizeof(state->hubs[state->hub_count]));
        config_write_with_state_pass(state);
        irc_printf(state, "PRIVMSG %s :Removed Hub: %s\r\n", nick, arg1);

        // If we disconnected and there are other hubs available, reconnect
        if (is_current_hub && state->hub_count > 0) {
          irc_printf(state, "PRIVMSG %s :Reconnecting to another hub...\r\n", nick);
          state->last_hub_connect_attempt = 0; // Reset cooldown
          hub_client_connect(state);
        } else if (is_current_hub && state->hub_count == 0) {
          irc_printf(state, "PRIVMSG %s :No other hubs available to connect to.\r\n",
                     nick);
        }
      } else {
        irc_printf(state, "PRIVMSG %s :Error: Hub '%s' not found.\r\n",
                   nick, arg1);
      }
    } else if (strcasecmp(command, "rekey") == 0) {
      /* Rotate the bot's own Curve25519 identity keypair.
       *
       * Trust model: the bot generates the new keypair locally (the private
       * key never leaves this host) and pushes only the new PUBLIC key to the
       * hub. The push rides the CURRENT authenticated session, so possession
       * of the OLD private key authorises the rotation — only the legitimate
       * bot can rekey itself, and only its own record (the hub keys the entry
       * by the authenticated client UUID). The hub is the source of trust: it
       * stores the new pub, re-verifies us against it on reconnect, and fans
       * it out to peer hubs. The UUID is unchanged.
       *
       * Ordering is fail-safe: we push the new pub FIRST and only commit the
       * new private key locally if that send succeeds, so an interrupted
       * rekey can never leave us holding a key the hub has never seen. */
      if (state->hub_count == 0) {
        irc_printf(state,
                   "PRIVMSG %s :Error: no hub configured; nothing to rekey.\r\n",
                   nick);
        return;
      }
      if (!state->hub_authenticated || state->hub_fd == -1) {
        irc_printf(state,
                   "PRIVMSG %s :Error: not authenticated to a hub. Rekey needs "
                   "an active session so the new key is pushed under the old "
                   "one. Try again once connected.\r\n", nick);
        return;
      }

      unsigned char new_priv[HUB_KEY_RAW_LEN], new_pub[HUB_KEY_RAW_LEN];
      if (!crypto_generate_combined_keypair(new_priv, new_pub)) {
        irc_printf(state,
                   "PRIVMSG %s :Error: keypair generation failed.\r\n", nick);
        return;
      }
      char *new_priv_b64 = base64_encode(new_priv, HUB_KEY_RAW_LEN);
      char *new_pub_b64  = base64_encode(new_pub,  HUB_KEY_RAW_LEN);
      if (!new_priv_b64 || !new_pub_b64) {
        if (new_priv_b64) { secure_wipe(new_priv_b64, strlen(new_priv_b64)); free(new_priv_b64); }
        if (new_pub_b64) free(new_pub_b64);
        secure_wipe(new_priv, sizeof(new_priv));
        secure_wipe(new_pub, sizeof(new_pub));
        irc_printf(state, "PRIVMSG %s :Error: base64 encode failed.\r\n", nick);
        return;
      }

      /* 1) Push the new PUBLIC key to the hub under the current session. */
      if (!hub_client_push_delta(state, "pub", new_pub_b64, time(NULL))) {
        secure_wipe(new_priv, sizeof(new_priv));
        secure_wipe(new_pub, sizeof(new_pub));
        secure_wipe(new_priv_b64, strlen(new_priv_b64));
        free(new_priv_b64);
        free(new_pub_b64);
        irc_printf(state,
                   "PRIVMSG %s :Error: failed to push new pubkey to hub; key "
                   "left UNCHANGED.\r\n", nick);
        return;
      }

      /* 2) Commit the new PRIVATE key locally: mlock'd raw cache, the base64
       *    serialization field, and the encrypted config on disk. */
      OPENSSL_cleanse(state->hub_key_raw, sizeof(state->hub_key_raw));
      memcpy(state->hub_key_raw, new_priv, HUB_KEY_RAW_LEN);
      secure_wipe(state->hub_key, sizeof(state->hub_key));
      snprintf(state->hub_key, sizeof(state->hub_key), "%s", new_priv_b64);
      bot_self_pub_refresh(state);
      config_write_with_state_pass(state);

      char rfp[KEY_FP_LEN + 1];
      crypto_key_fingerprint(new_pub, rfp);
      irc_printf(state,
                 "PRIVMSG %s :✓ Rekeyed (new key %s). New pubkey pushed to "
                 "hub; reconnecting with new key. Clients must re-auth "
                 "(/botforget %s).\r\n", nick, rfp, state->current_nick);
      log_message(L_INFO, state,
                  "[HUB] Rekey: generated new identity, pushed new pub to hub, "
                  "reconnecting.\n");

      secure_wipe(new_priv, sizeof(new_priv));
      secure_wipe(new_pub, sizeof(new_pub));
      secure_wipe(new_priv_b64, strlen(new_priv_b64));
      free(new_priv_b64);
      free(new_pub_b64);

      /* 3) Reconnect so the hub re-verifies us against the new pub. */
      hub_client_disconnect(state);
      state->last_hub_connect_attempt = 0;
      hub_client_connect(state);
    } else if (strcasecmp(command, "chkey") == 0) {
      /* chkey <name> <pubkey> — admins change anyone's key (opers: own only,
       * handled in the oper branch).  UUID, masks and history are kept. */
      if (!arg1 || !arg2) {
        irc_printf(state, "PRIVMSG %s :Syntax: chkey <name> <pubkey>\r\n", nick);
        return;
      }
      user_record_t *ck = NULL;
      for (int i = 0; i < state->user_record_count; i++) {
        if (state->user_records[i].is_active &&
            strcasecmp(state->user_records[i].name, arg1) == 0) {
          ck = &state->user_records[i]; break;
        }
      }
      if (!ck) { irc_printf(state, "PRIVMSG %s :Error: user '%s' not found.\r\n", nick, arg1); return; }
      if (!user_key_arg_ok(state, nick, arg2, ck, "chkey")) return;
      set_user_key(state, ck, arg2);
      char kfp[KEY_FP_LEN + 1];
      user_key_fp(ck, kfp);
      irc_printf(state, "PRIVMSG %s :Key for %s changed (key %s). They must "
                        "use the new private key from now on.\r\n",
                 nick, ck->name, kfp);

    } else if (strcasecmp(command, "help") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s : | " BOT_NAME " " BOT_VERSION " help\r\n", nick);
        irc_printf(state, "PRIVMSG %s : +----------------------------------------------------------------------------\r\n", nick);
        irc_printf(state, "PRIVMSG %s : | \r\n", nick);
        if (is_opt_set(state, OPT_HUB_ONLY_MUTATIONS)) {
          irc_printf(state, "PRIVMSG %s : |   die, jump, op, invite, status, givenick, chnick\r\n", nick);
          irc_printf(state, "PRIVMSG %s : |   +server, -server, admins, opers, match, dcc\r\n", nick);
          irc_printf(state, "PRIVMSG %s : |   +hub, -hub, rekey, saveconf, setlog, getlog, update, help\r\n", nick);
          irc_printf(state, "PRIVMSG %s : |   (hub-only-mutation mode: users, masks, keys, channels via hub_admin)\r\n", nick);
        } else {
          irc_printf(state, "PRIVMSG %s : |   die, jump, op, invite, join, part, status, givenick, chnick\r\n", nick);
          irc_printf(state, "PRIVMSG %s : |   +server, -server, admins, opers, match, dcc\r\n", nick);
          irc_printf(state, "PRIVMSG %s : |   +admin, -admin, +oper, -oper, +usermask, -usermask, chkey\r\n", nick);
          irc_printf(state, "PRIVMSG %s : |   +bot, -bot, +hub, -hub, rekey\r\n", nick);
          irc_printf(state, "PRIVMSG %s : |   saveconf, setlog, getlog, update, help\r\n", nick);
        }
        irc_printf(state, "PRIVMSG %s : |   'help auth' explains how clients sign in with their key\r\n", nick);
        irc_printf(state, "PRIVMSG %s : |\r\n", nick);
        irc_printf(state, "PRIVMSG %s : `----------------------------------------------------------------------------\r\n", nick);
      } else {
        if (strcasecmp(arg1, "die") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: die - Kills the bot process.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "jump") == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Syntax: jump [server] - Jump to the next IRC server, "
              "or to a specific server by hostname (port-independent match). "
              "Servers that banned or throttled the bot are skipped; naming one "
              "clears its hold and retries it now.\r\n",
              nick);
        } else if (strcasecmp(arg1, "op") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: op <#channel> - Get operator status "
                     "on a channel.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "status") == 0) {
          irc_printf(state, "PRIVMSG %s :Syntax: status - Show bot status.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "givenick") == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Syntax: givenick - Temporarily changes the bot nick "
              "to an alternate. Will try to regain primary nick after 20 "
              "seconds until it accomplishes the task.\r\n",
              nick);
        } else if (strcasecmp(arg1, "chnick") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: chnick <oldnick> <newnick> - Renames "
                     "a bot, admin, or oper. Nicks must be unique across all types. "
                     "For bots, propagates the change via hub mesh.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "+server") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: +server <irc.network.net:6667> - Add "
                     "another irc server to the bot's server list. Port not "
                     "required.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "-server") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: -server <irc.network.net:6667> - "
                     "Removes a server from the bot's server list. Specify "
                     "server as it is listed in 'status' command.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "admins") == 0) {
          irc_printf(state, "PRIVMSG %s :Syntax: admins - List all admins.\r\n", nick);
        } else if (strcasecmp(arg1, "opers") == 0) {
          irc_printf(state, "PRIVMSG %s :Syntax: opers - List all opers.\r\n", nick);
        } else if (strcasecmp(arg1, "+admin") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: +admin <name> <pubkey> <nick!user@host> - "
                     "Add a named admin with a first usermask. Name must be unique across admins and opers.\r\n", nick);
          help_keypair(state, nick);
        } else if (strcasecmp(arg1, "-admin") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: -admin <name> - Remove admin and all their masks.\r\n", nick);
        } else if (strcasecmp(arg1, "+oper") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: +oper <name> <pubkey> <nick!user@host> - "
                     "Add a named oper with a first usermask. Opers may use op, chkey (own key) and help.\r\n", nick);
          help_keypair(state, nick);
        } else if (strcasecmp(arg1, "-oper") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: -oper <name> - Remove oper and all their masks.\r\n", nick);
        } else if (strcasecmp(arg1, "+usermask") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: +usermask <name> <mask> - Add a usermask to admin or oper.\r\n", nick);
        } else if (strcasecmp(arg1, "-usermask") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: -usermask <name> <mask> - Remove a specific usermask from admin or oper.\r\n", nick);
        } else if (strcasecmp(arg1, "chkey") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: chkey <name> <pubkey> - Replace the public key of a named admin or oper "
                     "(UUID and usermasks are kept). Opers may only change their own key.\r\n", nick);
          help_keypair(state, nick);
        } else if (strcasecmp(arg1, "invite") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: invite <#channel> - Invite yourself to a channel (asks the hub or a "
                     "trusted bot if this bot is not opped there).\r\n", nick);
        } else if (strcasecmp(arg1, "auth") == 0) {
          help_auth(state, nick);
        } else if (strcasecmp(arg1, "dcc") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: dcc - Open a DCC chat with this bot "
                     "for long replies. The bot never accepts connections: it "
                     "sends a passive offer and connects out to the port your "
                     "client opens, so open your client's DCC port range in "
                     "your firewall and set its DCC address to your public "
                     "IP.\r\n", nick);
          irc_printf(state,
                     "PRIVMSG %s :Commands in the chat are still sealed: "
                     "while it is open, /botcmd <bot> <command> sends them "
                     "down it and the replies come back there; anything else "
                     "typed there closes it. A command sent by PRIVMSG is "
                     "still answered by PRIVMSG. Admins only.\r\n", nick);
        } else if (strcasecmp(arg1, "match") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: match <name|*> - Show all records for a user, or * for all users.\r\n", nick);
        } else if (strcasecmp(arg1, "+bot") == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Syntax: +bot <nick!user@host> <uuid> <pubkey> - "
              "Standalone bots only (hub-managed bots get peers from the hub): "
              "trust another bot for encrypted bot-to-bot commands. Copy the "
              "UUID and Pubkey from that bot's 'status' (or its -setup "
              "output). The mask should be the one the network shows for it.\r\n",
              nick);
        } else if (strcasecmp(arg1, "-bot") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: -bot <nick*!*user@hostmask.com> - "
                     "Removes a bot from the known bot list as shown in the "
                     "'status' command.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "saveconf") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: saveconf - Immediately save config "
                     "file.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "setlog") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: setlog <loglevel> - Set loglevel for "
                     "output to a log file. 0=NONE,15=INFO,63=DEBUG.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "getlog") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: getlog <loglevel> [lines]. Get "
                     "latest logs for requested loglevel. Levels are 'msg' "
                     "'ctcp' 'info' 'cmd' 'raw' 'debug'. Default number of "
                     "lines: %d. Max number of lines: %d.\r\n",
                     nick, DEFAULT_LOG_LINES, MAX_LOG_LINES);
        } else if (strcasecmp(arg1, "update") == 0) {
          irc_printf(state,
                     "PRIVMSG %s :Syntax: update without argument shows "
                     "available versions. "
                     "Run with update <ver> to download/compile/and update bot "
                     "binary.\r\n",
                     nick);
        } else if (strcasecmp(arg1, "join") == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Syntax: join <#channel> - Joins a channel.\r\n",
              nick);
        } else if (strcasecmp(arg1, "part") == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Syntax: part <#channel> - Parts a channel.\r\n",
              nick);
        } else if (strcasecmp(arg1, "+hub") == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Syntax: +hub <host:port> <pubkey-b64> - Add a hub "
              "and pin its Ed25519 pubkey (44 or 88 char base64 from the "
              "hub's hub_public.b64).\r\n",
              nick);
        } else if (strcasecmp(arg1, "-hub") == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Syntax: -hub <host:port> - Remove a configured "
              "hub.\r\n",
              nick);
        } else if (strcasecmp(arg1, "rekey") == 0) {
          irc_printf(
              state,
              "PRIVMSG %s :Syntax: rekey - Generate a new Curve25519 identity "
              "keypair locally, push the new public key to the hub, and "
              "reconnect. UUID is unchanged. Requires an active hub session. "
              "Clients holding the old key must re-auth (/botforget <bot>).\r\n",
              nick);
        } else {
          irc_printf(state,
                     "PRIVMSG %s :No help available for command '%s'.\r\n",
                     nick, arg1);
        }
      }
    }

  } else if (is_op) {
    if (strcasecmp(command, "op") == 0 && arg1) {
      char *saveptr_op;
      char *op_arg1 = strtok_r(arg1, " ", &saveptr_op);
      if (op_arg1)
        irc_printf(state, "MODE %s +o %s\r\n", op_arg1, nick);
    } else if (strcasecmp(command, "chkey") == 0) {
      /* Opers can only change their own key (refused under opt 'h', like
       * every other local mutation of a hub-authoritative record). */
      if (is_opt_set(state, OPT_HUB_ONLY_MUTATIONS)) {
        irc_printf(state,
                   "PRIVMSG %s :Error: 'chkey' is disabled — network is in "
                   "hub-only-mutation mode (opt 'h'). Ask a hub admin.\r\n",
                   nick);
        return;
      }
      if (!arg1 || !arg2) {
        irc_printf(state, "PRIVMSG %s :Syntax: chkey <yourname> <pubkey>\r\n", nick); return;
      }
      if (!auth_user || strcasecmp(auth_user->name, arg1) != 0) {
        irc_printf(state, "PRIVMSG %s :Error: opers may only change their own key.\r\n", nick); return;
      }
      if (!user_key_arg_ok(state, nick, arg2, auth_user, "chkey")) return;
      set_user_key(state, auth_user, arg2);
      char kfp[KEY_FP_LEN + 1];
      user_key_fp(auth_user, kfp);
      irc_printf(state, "PRIVMSG %s :Your key has been changed (key %s). Use "
                        "the new private key from now on.\r\n", nick, kfp);
    } else if (strcasecmp(command, "help") == 0) {
      if (!arg1) {
        irc_printf(state, "PRIVMSG %s : | " BOT_NAME " " BOT_VERSION " help\r\n", nick);
        irc_printf(state, "PRIVMSG %s : +----------------------------------------------------------------------------\r\n", nick);
        irc_printf(state, "PRIVMSG %s : | \r\n", nick);
        irc_printf(state, "PRIVMSG %s : |   op, chkey, help\r\n", nick);
        irc_printf(state, "PRIVMSG %s : |\r\n", nick);
        irc_printf(state, "PRIVMSG %s : `----------------------------------------------------------------------------\r\n", nick);
      } else {
        if (strcasecmp(arg1, "op") == 0) {
          irc_printf(state, "PRIVMSG %s :Syntax: op <#channel> - Get operator status on a channel.\r\n", nick);
        } else if (strcasecmp(arg1, "chkey") == 0) {
          irc_printf(state, "PRIVMSG %s :Syntax: chkey <yourname> <pubkey> - Replace your own public key.\r\n", nick);
          help_keypair(state, nick);
        } else if (strcasecmp(arg1, "auth") == 0) {
          help_auth(state, nick);
        } else if (strcasecmp(arg1, "help") == 0) {
          irc_printf(state, "PRIVMSG %s :Syntax: help [command] - Show available commands.\r\n", nick);
        } else {
          irc_printf(state, "PRIVMSG %s :No help available for command '%s'.\r\n", nick, arg1);
        }
      }
    }
  }
}
