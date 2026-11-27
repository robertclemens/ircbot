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
                  bot_who(state, 'b', sender->uuid), sender_nick ? "privmsg" : "hub relay");

      char *sp;
      char *bot_command = strtok_r(cmd, " ", &sp);
      char *bot_arg1 = strtok_r(NULL, " ", &sp);
      if (bot_command && bot_arg1 && strcasecmp(bot_command, "NETPROBE") == 0) {
        /* the link proof: over IRC only (a hub relay proves nothing) */
        if (sender_nick) netproof_probe(state, sender_nick, bot_arg1);
      } else if (bot_command && bot_arg1 && strcasecmp(bot_command, "NETPROBE-OK") == 0) {
        char *srv = strtok_r(NULL, " ", &sp);
        if (sender_nick) netproof_ok(state, bot_arg1, srv, sender_nick);
      } else if (bot_command && bot_arg1 && strcasecmp(bot_command, "OPME") == 0) {
        /* Only where we can: in the channel and opped (as OPUSER).  The
         * sender is a trusted bot, so +bitch does not apply to it. */
        chan_t *mc = sender_nick ? channel_find(state, bot_arg1) : NULL;
        if (mc && mc->status == C_IN && mc->i_am_opped)
          irc_printf(state, "MODE %s +o %s\r\n", mc->name, sender_nick);
      } else if (bot_command && bot_arg1 &&
                 strcasecmp(bot_command, "SETNICK") == 0) {
        if (is_rfc_nick(bot_arg1)) {
          snprintf(state->target_nick, MAX_NICK, "%s", bot_arg1);
          state->current_nick_ts = time(NULL);
          hub_client_push_delta(state, "n", bot_arg1, state->current_nick_ts);
          config_write_with_state_pass(state);
        } else {
          log_message(L_INFO, state, "[BOT-COMM] SETNICK from %s refused: "
                                     "'%s' is not a valid IRC nick\n",
                      bot_who(state, 'b', sender->uuid), bot_arg1);
        }
      } else if (bot_command && bot_arg1 &&
                 strcasecmp(bot_command, "INVITE") == 0) {
        char *bot_arg2 = strtok_r(NULL, " ", &sp);
        char *imask = strtok_r(NULL, " ", &sp), *iuser = strtok_r(NULL, " ", &sp);
        char snick[MAX_NICK];
        auth_trusted_bot_nick(sender, snick);
        if (bot_arg2) {
          chan_t *ic = channel_find(state, bot_arg1);
          if (ic && ic->status == C_IN && ic->i_am_opped) {
            if (imask && iuser) {
              /* a person the sender validated: its mask, checked live */
              invite_check_start(state, "", bot_arg1, bot_arg2, imask, iuser);
            } else if (irc_casecmp(bot_arg2, snick) == 0) {
              /* the sender itself: its published mask, checked live */
              invite_check_start(state, "", bot_arg1, bot_arg2, sender->mask, "");
            } else {
              /* a 2.5.3 sender's person invite (no mask): as before,
               * unchecked -- 2.5.5 drops this form */
              log_message(L_INFO, state,
                          "[BOT-COMMS] Inviting %s to %s (older bot's request, unchecked)\n",
                          bot_arg2, bot_arg1);
              irc_printf(state, "INVITE %s %s\r\n", bot_arg2, bot_arg1);
            }
          }
        }
      } else if (bot_command && bot_arg1 &&
                 strcasecmp(bot_command, "OPUSER") == 0) {
        /* OPUSER #chan nick: a person the sender vouched for (an admin or
         * an oper bound to the channel, user_flags plan §5).  +bitch still
         * holds here: only an authorised member is opped. */
        char *bot_arg2 = strtok_r(NULL, " ", &sp);
        char *omask = strtok_r(NULL, " ", &sp), *ouser = strtok_r(NULL, " ", &sp);
        chan_t *oc = bot_arg2 ? channel_find(state, bot_arg1) : NULL;
        if (oc && oc->status == C_IN && oc->i_am_opped && omask && ouser) {
          /* the nick's mask here must be the one the sender validated, and
           * still that user's (2026-11-23) */
          const char *hm = NULL;
          for (int i = 0; i < oc->roster_count; i++)
            if (irc_casecmp(oc->roster[i].nick, bot_arg2) == 0) hm = oc->roster[i].hostmask;
          if (hm && auth_mask_equal(hm, omask) && auth_user_live_ok(state, ouser, hm, bot_arg1)) {
            log_message(L_INFO, state, "[BOT-COMMS] Opping %s in %s (bot req, %s checked)\n",
                        bot_arg2, bot_arg1, hm);
            irc_printf(state, "MODE %s +o %s\r\n", bot_arg1, bot_arg2);
          } else {
            log_message(L_INFO, state, "[BOT-COMMS] Not opping %s in %s: not the requester here\n",
                        bot_arg2, bot_arg1);
          }
        } else if (oc && oc->status == C_IN && oc->i_am_opped) {
          /* a 2.5.3 sender (no mask): as before, +bitch only -- 2.5.5 drops
           * this form */
          bool found = false;
          bool auth = chan_member_authorised(state, oc, bot_arg2, &found);
          if (!chancfg_get(state, oc, CS_BITCH) || (found && auth)) {
            log_message(L_INFO, state, "[BOT-COMMS] Opping %s in %s (bot req)\n", bot_arg2,
                        bot_arg1);
            irc_printf(state, "MODE %s +o %s\r\n", bot_arg1, bot_arg2);
          }
        }
      } else if (bot_command && bot_arg1 &&
                 strcasecmp(bot_command, "UNBANUSER") == 0) {
        /* UNBANUSER #chan nick!user@host: lift the bans that match a person
         * the sender vouched for (its hostmask as the IRC server showed it) */
        char *bot_arg2 = strtok_r(NULL, " ", &sp);
        if (bot_arg2 && strchr(bot_arg2, '!') && strchr(bot_arg2, '@'))
          chan_access_service(state, "", CHAN_REQ_UNBAN, bot_arg1, sender->uuid, NULL,
                              bot_arg2, NULL);
      } else if (bot_command && bot_arg1 &&
                 strcasecmp(bot_command, "UNBAN") == 0) {
        /* Hubless counterpart of CMD_CHAN_ACTION unban.  The mask matched
         * against the ban list is the sender's own b| record -- never
         * anything the sender put in the message -- so this cannot be used
         * to lift a ban on a third party. */
        chan_access_service(state, "", CHAN_REQ_UNBAN, bot_arg1, sender->uuid,
                            NULL, sender->mask, NULL);
      } else if (bot_command && bot_arg1 &&
                 strcasecmp(bot_command, "KEY") == 0) {
        if (sender_nick)
          chan_access_service(state, "", CHAN_REQ_KEY, bot_arg1, sender->uuid,
                              NULL, NULL, sender_nick);
        else
          log_message(L_DEBUG, state,
                      "[DEBUG] [BOT-COMM] KEY over hub relay has no reply "
                      "nick; the hub path answers these\n");
      } else if (bot_command && bot_arg1 &&
                 strcasecmp(bot_command, "KEYIS") == 0) {
        char *bot_arg2 = strtok_r(NULL, " ", &sp);
        if (bot_arg2)
          chan_access_accept_key(state, bot_arg1, bot_arg2);
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
                "[BOT-COMM] Relayed frame from %s is not ~B2; dropped\n",
                bot_who(state, 'b', uuid));
    return;
  }
  trusted_bot_t *tb = auth_trusted_bot_by_uuid(state, uuid);
  if (!tb) {
    log_message(L_CMD, state, "[BOT-COMM] Relayed ~B2 from unknown %s\n",
                bot_who(state, 'b', uuid));
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
 * (hub relay when connected and the target is on a hub, else PRIVMSG).
 * irc_only: PRIVMSG whatever the hub link -- a failback because the hub did
 * not get the job done (bot chan request plan 2026-11-23). */
static void b2_vsend(bot_state_t *state, const trusted_bot_t *tb,
                     const char *target_nick, bool irc_only, const char *format,
                     va_list args)
    __attribute__((format(printf, 5, 0)));
static void b2_vsend(bot_state_t *state, const trusted_bot_t *tb,
                     const char *target_nick, bool irc_only, const char *format,
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

  /* Route through hub if connected and the target is on a hub (the bot
   * tree); PRIVMSG for hub-less bots and for a target no hub holds. */
  bool sent_via_hub = false;
  if (!irc_only && state->hub_connected && state->hub_authenticated && state->hub_fd != -1 &&
      hub_client_bot_on_hub(state, tb->uuid)) {
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
  b2_vsend(state, auth_trusted_bot_by_nick(state, target_nick), target_nick, false,
           format, args);
  va_end(args);
}

void bot_comms_send_command_irc(bot_state_t *state, const char *target_nick,
                                const char *format, ...) {
  if (!target_nick || !format) return;
  va_list args;
  va_start(args, format);
  b2_vsend(state, auth_trusted_bot_by_nick(state, target_nick), target_nick, true,
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
  b2_vsend(state, auth_trusted_bot_by_host(state, hostmask), target_nick, false,
           format, args);
  va_end(args);
}

void bot_comms_send_to_host_irc(bot_state_t *state, const char *hostmask,
                                const char *target_nick, const char *format, ...) {
  if (!hostmask || !target_nick || !format) return;
  va_list args;
  va_start(args, format);
  b2_vsend(state, auth_trusted_bot_by_host(state, hostmask), target_nick, true,
           format, args);
  va_end(args);
}

/* A person's op / invite / unban with no hub to ask (or a hub that never
 * answered): every trusted bot gets it over ~B2; one that is in the channel
 * and opped does it (user_flags plan §5). */
void bot_comms_user_chan_fallback(bot_state_t *state, const char *kind, const char *chan,
                                  const char *nick, const char *mask, const char *uuid) {
  /* op / invite carry the person's validated mask and uuid: the bot that
   * acts checks the nick's live mask against them first (2026-11-23) */
  for (int i = 0; i < state->trusted_bot_count; i++) {
    char tb_nick[MAX_NICK];
    auth_trusted_bot_nick(&state->trusted_bots[i], tb_nick);
    if (!tb_nick[0]) continue;
    if (strcmp(kind, "invite") == 0)
      bot_comms_send_command(state, tb_nick, "INVITE %s %s %s %s", chan, nick, mask, uuid);
    else if (strcmp(kind, "op") == 0)
      bot_comms_send_command(state, tb_nick, "OPUSER %s %s %s %s", chan, nick, mask, uuid);
    else if (strcmp(kind, "unban") == 0)
      bot_comms_send_command(state, tb_nick, "UNBANUSER %s %s", chan, mask);
  }
}
