#include <errno.h>
#include <math.h>
#include <openssl/rand.h>
#include <stdarg.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "bot.h"

/* Bot-to-bot commands, sealed with the peers' public keys (~B2,
 * irchub/docs/passwordless.md §5):
 *
 *   ~B2 <b64( eph_pub(32) || iv(12) || ct || tag(16) )>
 *   pt  = "<ts>:<nonce16hex>:<OPME|SETNICK|INVITE ...>"
 *   ikm = X25519(eph, R_x) || X25519(S_x, R_x)          (crypto_seal)
 *   AAD = B2_LABEL "\0" sender_uuid "\0" recipient_uuid
 *
 * Carried by the hub relay (CMD_BOT_RELAY / CMD_BOT_MSG, opaque to the hub)
 * when a hub is connected, else by direct PRIVMSG.  Only the holder of the
 * sender's private key can produce a frame that opens, so the b| pubkey is
 * the whole trust anchor; the hub can neither read nor forge. */

/* "<ts>:<nonce>:<command>" — ts 1..19 digits, nonce exactly 16 lowercase hex.
 * The shape is validated before any field is converted (pt must already be
 * free of control bytes).  On success *cmd points into pt. */
bool envelope_parse(char *pt, time_t *ts, uint64_t *nonce, char **cmd) {
  size_t nd = 0;
  while (pt[nd] >= '0' && pt[nd] <= '9') nd++;
  if (nd == 0 || nd > 19 || pt[nd] != ':') return false;
  char *q = pt + nd + 1;
  for (int i = 0; i < 16; i++)
    if (!((q[i] >= '0' && q[i] <= '9') || (q[i] >= 'a' && q[i] <= 'f')))
      return false;
  if (q[16] != ':' || q[17] == '\0') return false;
  pt[nd] = '\0';
  q[16] = '\0';
  errno = 0;
  long long t = strtoll(pt, NULL, 10);
  if (errno) return false;
  *ts = (time_t)t;
  *nonce = strtoull(q, NULL, 16);
  *cmd = q + 17;
  return true;
}

static size_t b2_aad(unsigned char *aad, size_t cap, const char *sender_uuid,
                     const char *recipient_uuid) {
  int n = snprintf((char *)aad, cap, "%s%c%s%c%s", B2_LABEL, 0, sender_uuid, 0,
                   recipient_uuid);
  return (n > 0 && (size_t)n < cap) ? (size_t)n : 0;
}

/* Open a ~B2 frame from `sender` and run it.  sender_nick is the PRIVMSG
 * source (NULL on the relay path): OPME ops that nick, so it is only
 * accepted over PRIVMSG, as before. */
static void b2_open_and_dispatch(bot_state_t *state, const trusted_bot_t *sender,
                                 const char *b64, const char *sender_nick) {
  if (!sender->has_pub || sender->uuid[0] == '\0') {
    log_message(L_CMD, state,
                "[BOT-COMM] ~B2 from %s dropped: no public key on file yet\n",
                sender->mask);
    return;
  }
  if (!state->self_pub_set || state->bot_uuid[0] == '\0') {
    log_message(L_CMD, state, "[BOT-COMM] ~B2 dropped: no identity key\n");
    return;
  }
  if (strlen(b64) > 4 * ((SEAL_MAX_PLAINTEXT + SEAL_OVERHEAD + 2) / 3)) {
    log_message(L_CMD, state, "[BOT-COMM] ~B2 from %s oversized; dropped\n",
                sender->mask);
    return;
  }
  int flen = 0;
  unsigned char *frame = base64_decode(b64, &flen);
  if (!frame || flen < SEAL_OVERHEAD) {
    free(frame);
    log_message(L_CMD, state, "[BOT-COMM] ~B2 from %s malformed; dropped\n",
                sender->mask);
    return;
  }

  unsigned char aad[160];
  size_t aad_len = b2_aad(aad, sizeof(aad), sender->uuid, state->bot_uuid);
  unsigned char ed_priv[32], x_priv[32];
  unsigned char pt[SEAL_MAX_PLAINTEXT + 1];
  int n = -1;
  if (aad_len && bot_key_decode(state, ed_priv, x_priv))
    n = crypto_open(x_priv, state->self_pub + 32, sender->pub + 32, B2_LABEL,
                    aad, aad_len, frame, (size_t)flen, pt, SEAL_MAX_PLAINTEXT);
  secure_wipe(ed_priv, sizeof(ed_priv));
  secure_wipe(x_priv, sizeof(x_priv));
  free(frame);
  if (n < 0) {
    log_message(L_CMD, state, "[BOT-COMM] ~B2 from %s did not open; dropped\n",
                sender->mask);
    return;
  }
  pt[n] = '\0';

  time_t ts;
  uint64_t nonce;
  char *cmd = NULL;
  if (has_control_bytes(pt, (size_t)n)) {
    log_message(L_CMD, state,
                "[BOT-COMM] Control character in command from %s; dropped\n",
                sender->mask);
  } else if (!envelope_parse((char *)pt, &ts, &nonce, &cmd)) {
    log_message(L_CMD, state, "[BOT-COMM] ~B2 from %s: bad envelope\n",
                sender->mask);
  } else if (fabs(difftime(time(NULL), ts)) > B2_TS_SKEW) {
    log_message(L_CMD, state, "[BOT-COMM] ~B2 from %s: stale timestamp\n",
                sender->mask);
  } else {
    time_t now = time(NULL);
    bool reused = false;
    for (int i = 0; i < NONCE_CACHE_SIZE; i++)
      if (state->recent_nonces[i].nonce == nonce &&
          now - state->recent_nonces[i].ts <= NONCE_TTL_SECONDS) {
        reused = true;
        break;
      }
    if (reused) {
      log_message(L_CMD, state, "[BOT-COMM] ~B2 replay from %s; dropped\n",
                  sender->mask);
    } else {
      state->recent_nonces[state->nonce_idx] = (nonce_entry_t){nonce, now};
      state->nonce_idx = (state->nonce_idx + 1) % NONCE_CACHE_SIZE;
      log_message(L_DEBUG, state, "[BOT-COMM] ~B2 verified from %s (%s)\n",
                  sender->uuid, sender_nick ? "privmsg" : "hub relay");

      char *sp;
      char *bot_command = strtok_r(cmd, " ", &sp);
      char *bot_arg1 = strtok_r(NULL, " ", &sp);
      if (bot_command && bot_arg1 && strcasecmp(bot_command, "OPME") == 0) {
        if (sender_nick)
          irc_printf(state, "MODE %s +o %s\r\n", bot_arg1, sender_nick);
      } else if (bot_command && bot_arg1 &&
                 strcasecmp(bot_command, "SETNICK") == 0) {
        if (is_valid_bot_nick(bot_arg1)) {
          snprintf(state->target_nick, MAX_NICK, "%s", bot_arg1);
          state->current_nick_ts = time(NULL);
          hub_client_push_delta(state, "n", bot_arg1, state->current_nick_ts);
          config_write_with_state_pass(state);
        }
      } else if (bot_command && bot_arg1 &&
                 strcasecmp(bot_command, "INVITE") == 0) {
        char *bot_arg2 = strtok_r(NULL, " ", &sp);
        if (bot_arg2) {
          chan_t *ic = channel_find(state, bot_arg1);
          if (ic && ic->status == C_IN && ic->i_am_opped) {
            log_message(L_INFO, state,
                        "[BOT-COMMS] Inviting %s to %s (bot req)\n", bot_arg2,
                        bot_arg1);
            irc_printf(state, "INVITE %s %s\r\n", bot_arg2, bot_arg1);
          }
        }
      }
    }
  }
  secure_wipe(pt, sizeof(pt));
}

/* Hub-relayed CMD_BOT_MSG: "<sender_uuid>|~B2 <b64>".  The UUID is the one
 * the hub authenticated; it only selects which b| key must open the frame. */
void bot_comms_process_payload(bot_state_t *state, const char *payload) {
  if (!payload) return;
  const char *bar = strchr(payload, '|');
  if (!bar) return;
  size_t ul = (size_t)(bar - payload);
  char uuid[37];
  if (ul == 0 || ul >= sizeof(uuid)) return;
  memcpy(uuid, payload, ul);
  uuid[ul] = '\0';
  if (strncmp(bar + 1, "~B2 ", 4) != 0) {
    log_message(L_CMD, state,
                "[BOT-COMM] Relayed frame from %s is not ~B2 (pre-passwordless "
                "sender?); dropped\n", uuid);
    return;
  }
  trusted_bot_t *tb = auth_trusted_bot_by_uuid(state, uuid);
  if (!tb) {
    log_message(L_CMD, state, "[BOT-COMM] Relayed ~B2 from unknown bot %s\n",
                uuid);
    return;
  }
  b2_open_and_dispatch(state, tb, bar + 5, NULL);
}

bool bot_comms_handle_privmsg(bot_state_t *state, const char *nick,
                              const char *user_host, const char *message) {
  if (strncmp(message, "~B2 ", 4) != 0) return false;
  trusted_bot_t *tb = auth_trusted_bot_by_host(state, user_host);
  if (!tb) {
    log_message(L_CMD, state, "[BOT-COMM] ~B2 from untrusted %s dropped\n",
                user_host);
    return true;
  }
  b2_open_and_dispatch(state, tb, message + 4, nick);
  return true;
}

/* Seal `format` to trusted bot `tb` and send it to IRC nick `target_nick`
 * (hub relay when connected, else PRIVMSG). */
static void b2_vsend(bot_state_t *state, const trusted_bot_t *tb,
                     const char *target_nick, const char *format,
                     va_list args) {
  if (!tb || !tb->has_pub || tb->uuid[0] == '\0') {
    log_message(L_DEBUG, state,
                "[BOT-COMM] Cannot send to %s: no public key on file\n",
                target_nick);
    return;
  }
  if (!state->self_pub_set || state->bot_uuid[0] == '\0') {
    log_message(L_DEBUG, state, "[BOT-COMM] Cannot send: no identity key\n");
    return;
  }

  char command_part[256];
  int vn = vsnprintf(command_part, sizeof(command_part), format, args);
  if (vn < 0 || vn >= (int)sizeof(command_part)) return;

  unsigned char rnd[8];
  if (RAND_bytes(rnd, sizeof(rnd)) != 1) return;
  char pt[512];
  int pl = snprintf(pt, sizeof(pt),
                    "%lld:%02x%02x%02x%02x%02x%02x%02x%02x:%s",
                    (long long)time(NULL), rnd[0], rnd[1], rnd[2], rnd[3],
                    rnd[4], rnd[5], rnd[6], rnd[7], command_part);
  if (pl <= 0 || pl >= (int)sizeof(pt)) return;

  unsigned char aad[160];
  size_t aad_len = b2_aad(aad, sizeof(aad), state->bot_uuid, tb->uuid);
  unsigned char frame[sizeof(pt) + SEAL_OVERHEAD];
  unsigned char ed_priv[32], x_priv[32];
  int fl = -1;
  if (aad_len && bot_key_decode(state, ed_priv, x_priv))
    fl = crypto_seal(x_priv, state->self_pub + 32, tb->pub + 32, B2_LABEL, aad,
                     aad_len, (const unsigned char *)pt, (size_t)pl, frame,
                     sizeof(frame));
  secure_wipe(ed_priv, sizeof(ed_priv));
  secure_wipe(x_priv, sizeof(x_priv));
  secure_wipe(pt, sizeof(pt));
  if (fl < 0) {
    log_message(L_INFO, state, "[BOT-COMM] Sealing to %s failed\n", target_nick);
    return;
  }
  char *b64 = base64_encode(frame, fl);
  if (!b64) return;
  char line[1024];
  int ll = snprintf(line, sizeof(line), "~B2 %s", b64);
  free(b64);
  if (ll <= 0 || ll >= (int)sizeof(line)) return;

  /* Route through hub if connected; PRIVMSG is the fallback for hub-less bots */
  bool sent_via_hub = false;
  if (state->hub_connected && state->hub_authenticated && state->hub_fd != -1) {
    log_message(L_DEBUG, state, "[BOT-COMM] Relaying %s to %s via hub\n",
                command_part, target_nick);
    sent_via_hub = hub_client_relay_bot_command(state, tb->uuid, line);
  }
  if (!sent_via_hub) {
    log_message(L_DEBUG, state, "[BOT-COMM] Sending ~B2 PRIVMSG to %s: %s\n",
                target_nick, command_part);
    irc_printf(state, "PRIVMSG %s :%s\r\n", target_nick, line);
  }
}

/* Send to a trusted bot addressed by nick (its mask's nick part). */
void bot_comms_send_command(bot_state_t *state, const char *target_nick,
                            const char *format, ...) {
  if (!target_nick || !format) return;
  va_list args;
  va_start(args, format);
  b2_vsend(state, auth_trusted_bot_by_nick(state, target_nick), target_nick,
           format, args);
  va_end(args);
}

/* Send to the trusted bot whose mask matches `hostmask`, at IRC nick
 * `target_nick` — for a roster entry whose nick may carry a collision
 * suffix the stored mask does not. */
void bot_comms_send_to_host(bot_state_t *state, const char *hostmask,
                            const char *target_nick, const char *format, ...) {
  if (!hostmask || !target_nick || !format) return;
  va_list args;
  va_start(args, format);
  b2_vsend(state, auth_trusted_bot_by_host(state, hostmask), target_nick,
           format, args);
  va_end(args);
}
