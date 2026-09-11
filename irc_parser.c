#include <stdlib.h>
#include <string.h>
#include <strings.h>

#include "bot.h"

// Look up the hub UUID for a roster entry whose IRC nick may carry trailing '_'
// suffixes from nick collisions.  Tries exact hostmask match first, then exact
// nick-prefix match, then base-nick match (strips trailing '_' from both sides).
// Returns true and populates uuid_out if a match is found.
static bool find_uuid_for_helper(const bot_state_t *state,
                                  const roster_entry_t *helper,
                                  char *uuid_out, size_t uuid_len) {
  for (int tb = 0; tb < state->trusted_bot_count; tb++) {
    char mask[MAX_MASK_LEN], uuid[64];
    if (sscanf(state->trusted_bots[tb], "%255[^|]|%63[^|]", mask, uuid) < 2)
      continue;

    // 1. Exact hostmask match
    if (strcasecmp(mask, helper->hostmask) == 0) {
      snprintf(uuid_out, uuid_len, "%s", uuid);
      return true;
    }

    // 2. Nick-prefix match: stored entry starts with "helper_nick!"
    char pfx[MAX_NICK + 1];
    snprintf(pfx, sizeof(pfx), "%s!", helper->nick);
    if (strncasecmp(mask, pfx, strlen(pfx)) == 0) {
      snprintf(uuid_out, uuid_len, "%s", uuid);
      return true;
    }

    // 3. Base-nick match: strip trailing '_' from both nicks and compare.
    // Handles ghost "bot6" matching stored "bot6_!~ircbot@..." and vice-versa.
    char stored_nick[MAX_NICK] = "";
    const char *bang = strchr(mask, '!');
    if (bang) {
      size_t n = (size_t)(bang - mask);
      if (n >= MAX_NICK) n = MAX_NICK - 1;
      memcpy(stored_nick, mask, n);
      stored_nick[n] = '\0';
    }
    // Strip trailing underscores
    char base_stored[MAX_NICK], base_helper[MAX_NICK];
    snprintf(base_stored, sizeof(base_stored), "%s", stored_nick);
    snprintf(base_helper, sizeof(base_helper), "%s", helper->nick);
    size_t ls = strlen(base_stored), lh = strlen(base_helper);
    while (ls > 0 && base_stored[ls - 1] == '_') base_stored[--ls] = '\0';
    while (lh > 0 && base_helper[lh - 1] == '_') base_helper[--lh] = '\0';

    if (ls > 0 && strcasecmp(base_stored, base_helper) == 0) {
      snprintf(uuid_out, uuid_len, "%s", uuid);
      return true;
    }
  }
  return false;
}

// [UPDATED] Helper to handle mode changes securely + immediate Op Recovery
static void channel_handle_mode_change(bot_state_t *state, const char *channel,
                                       const char *modes, char *args) {
  chan_t *c = channel_find(state, channel);
  if (!c)
    return;

  bool adding = true; // Default direction
  char *saveptr;
  char no_args[1] = "";
  /* args is NULL when the MODE line carries no trailing parameters at all
   * (e.g. "+nt" - neither mode takes an argument). strtok_r() requires a
   * non-NULL string on its first call - passing NULL makes it read from an
   * uninitialized saveptr here, which is what crashed. Fall back to an
   * empty buffer so saveptr ends up validly initialized either way; every
   * later strtok_r(NULL, " ", &saveptr) continuation call below then just
   * keeps returning NULL, as intended when there are no more arguments. */
  char *current_arg = strtok_r(args ? args : no_args, " ", &saveptr);

  for (int i = 0; modes[i] != '\0'; i++) {
    char mode = modes[i];

    if (mode == '+') {
      adding = true;
    } else if (mode == '-') {
      adding = false;
    }
    // --- Modes that ALWAYS take an argument ---
    else if (mode == 'o' || mode == 'v' || mode == 'b' || mode == 'e' ||
             mode == 'I') {
      if (current_arg) {
        // Handle OPS (+o / -o)
        if (mode == 'o') {
          // Check if it affects US
          if (strcasecmp(current_arg, state->current_nick) == 0) {
            c->i_am_opped = adding;
            for (int k = 0; k < c->roster_count; k++) {
              if (strcasecmp(c->roster[k].nick, state->current_nick) == 0) {
                c->roster[k].is_op = adding;
                break;
              }
            }
            if (adding) {
              c->op_request_pending = false;
              c->op_request_retry_count = 0;
              log_message(L_INFO, state, "[INFO] I am now OP in %s\n", channel);
            } else {
              /* Deopped: re-read the channel before choosing a helper.  While
               * we held ops the roster was never refreshed, so peers that left
               * or renamed may still be listed and peers that joined are not.
               * The 315 handler picks a trusted op from the fresh WHO and sends
               * the request, with the usual rate limit and retries.  Skipped
               * while a request is already pending; its timeout re-WHOs. */
              log_message(L_INFO, state,
                          "[INFO] I was DEOPPED in %s. Refreshing roster to "
                          "find a trusted op.\n",
                          channel);
              if (!c->op_request_pending) {
                c->roster_count = 0;
                irc_printf(state, "WHO %s\r\n", c->name);
                c->last_who_request = time(NULL);
              }
            }
          }
          // Check if it affects SOMEONE ELSE in our roster
          else {
            for (int k = 0; k < c->roster_count; k++) {
              if (strcasecmp(c->roster[k].nick, current_arg) == 0) {
                c->roster[k].is_op = adding;
                log_message(L_DEBUG, state,
                            "[DEBUG] Roster update: %s is_op=%d in %s\n",
                            current_arg, adding, channel);
                break;
              }
            }
          }
        }

        // Consumed one argument, move to next
        current_arg = strtok_r(NULL, " ", &saveptr);
      }
    }
    // --- Modes that CONDITIONALLY take an argument ---
    else if (mode == 'k') {
      if (adding && current_arg) {
        /* Store key and set M_K flag */
        size_t klen = strlen(current_arg);
        if (klen >= MAX_KEY) klen = MAX_KEY - 1;
        memcpy(c->key, current_arg, klen);
        c->key[klen] = '\0';
        c->modes |= M_K;
      } else if (!adding) {
        /* -k clears the key regardless of arg */
        c->key[0] = '\0';
        c->modes &= ~(chan_mode_t)M_K;
      }
      if (current_arg)
        current_arg = strtok_r(NULL, " ", &saveptr);
    } else if (mode == 'l') {
      // +l takes arg (limit). -l DOES NOT take arg.
      if (adding && current_arg) {
        current_arg = strtok_r(NULL, " ", &saveptr);
      }
    } else if (mode == 'i') {
      if (adding)
        c->modes |= M_I;
      else
        c->modes &= ~(chan_mode_t)M_I;
    }
    // --- Modes that NEVER take an argument (t, s, n, m, p, etc) ---
  }
}

/* Record the bot's own hostmask.  Only two things may call this, and both hand
 * it a string the server itself presented to OTHER clients verbatim:
 *   - our own entry in a 352 (RPL_WHOREPLY) — the numeric peers parse into
 *     their rosters and store in trusted_bots[];
 *   - the prefix of our own JOIN echo — what the channel was shown.
 * Both were verified byte-identical against ngircd (2026-09-08).
 *
 * Nothing here parses a self-directed answer, resolves a name, or splices a
 * mask together.  The reason is that the server's choice of host form is per
 * session and outside our control: an ircd prints the resolved name only when
 * forward-confirmed rDNS succeeds within its timeout, and the raw IP otherwise
 * — the same box is legitimately `nick!~i@host.example.net` in one session and
 * `nick!~i@203.0.113.7` in the next.  So a remembered host re-spliced onto a
 * new nick, or an ident carried over from config, silently publishes a mask no
 * peer can match.  Events that can change the mask (001, 396 cloak, own NICK)
 * therefore only re-ask via request_own_hostmask().
 *
 * Idempotent: updates actual_hostname(+ts) and calls hub_client_sync_hostmask
 * only when the value actually changes, so repeated WHOs never re-push. */
static void update_own_hostmask(bot_state_t *state, const char *mask) {
  if (!mask || mask[0] == '\0')
    return;
  if (strcmp(state->actual_hostname, mask) == 0)
    return; // unchanged — nothing to push

  snprintf(state->actual_hostname, sizeof(state->actual_hostname), "%s", mask);
  state->actual_hostname_ts = time(NULL);
  log_message(L_INFO, state, "[INFO] My hostmask is now: %s\n",
              state->actual_hostname);

  if (state->hub_connected && state->hub_authenticated)
    hub_client_sync_hostmask(state);
}

/* Ask the server for our own DISPLAYED hostmask.  `WHO <nick>` is answered by
 * every IRC network with a 352 carrying exactly the nick!ident@host other
 * clients are shown — the same numeric peers build their rosters from — and it
 * works without joining a channel (the reply's channel field is "*").
 * USERHOST is not used: its answer is addressed to us alone, so nothing
 * guarantees it is the string the network puts in front of anyone else, and we
 * have no reason to publish a form no peer will ever match against.  Sent on
 * connect, on a cloak change, and after a settled nick change, so it adds no
 * sustained traffic. */
static void request_own_hostmask(bot_state_t *state) {
  if (state->current_nick[0] != '\0')
    irc_printf(state, "WHO %s\r\n", state->current_nick);
}

/* The trailing parameter ("... :text"), or all of params if there is none. */
static const char *irc_trailing(const char *params) {
  if (params[0] == ':') return params + 1;
  const char *t = strstr(params, " :");
  return t ? t + 2 : params;
}

void parser_handle_line(bot_state_t *state, char *line) {
  if (strncmp(line, "PING :", 6) == 0) {
    irc_printf(state, "PONG :%s\r\n", line + 6);
    state->last_pong_time = time(NULL);
    state->pong_pending = false;
    return;
  }

  char line_copy[MAX_BUFFER];
  snprintf(line_copy, sizeof(line_copy), "%s", line);

  char *prefix = NULL, *command = NULL, *params = NULL;
  char *p = line_copy;

  if (*p == ':') {
    prefix = p + 1;
    p = strchr(p, ' ');
    if (!p)
      return;
    *p++ = '\0';
  }

  command = p;
  p = strchr(p, ' ');
  if (p) {
    *p++ = '\0';
    params = p;
  } else {
    return;
  }

  char *saveptr_irc;

  if (strcmp(command, "PONG") == 0) {
    state->last_pong_time = time(NULL);
    state->pong_pending = false;
    return;
  }
  if (strcmp(command, "004") == 0) {
    char *server_name = strtok_r(params, " ", &saveptr_irc);
    server_name = strtok_r(NULL, " ", &saveptr_irc);
    if (server_name) {
      snprintf(state->actual_server_name, sizeof(state->actual_server_name),
               "%s", server_name);
    }
  }
  if (strcmp(command, "001") == 0) {
    state->status |= S_AUTHED;
    irc_note_registered(state); /* server accepted us: drop any ban hold */
    /* 001's first parameter is the nick the server actually registered us
     * under, which is not always the one we asked for (length truncation,
     * collision handling, a services rename).  Self-recognition in the 352
     * and 302 handlers is a strcasecmp against current_nick, so a stale value
     * here silently disables every self-mask capture and the bot goes on
     * publishing whatever the 001 welcome line happened to say. */
    {
      const char *sp = strchr(params, ' ');
      size_t nlen = sp ? (size_t)(sp - params) : strlen(params);
      if (nlen > 0 && nlen < sizeof(state->current_nick)) {
        char srv_nick[MAX_NICK];
        memcpy(srv_nick, params, nlen);
        srv_nick[nlen] = '\0';
        if (strcmp(state->current_nick, srv_nick) != 0) {
          log_message(L_INFO, state,
                      "[INFO] Server registered me as %s (was %s)\n", srv_nick,
                      state->current_nick[0] ? state->current_nick : "unset");
          snprintf(state->current_nick, sizeof(state->current_nick), "%s",
                   srv_nick);
          state->current_nick_ts = time(NULL);
          if (state->hub_connected && state->hub_authenticated)
            hub_client_push_delta(state, "n", state->current_nick,
                                  state->current_nick_ts);
        }
      }
    }
    /* The mask embedded in the 001 welcome text is deliberately NOT used:
     * it is a self-directed greeting, and networks fill it with the real
     * (pre-resolution / pre-cloak) host that no other client is ever shown.
     * Ask instead, and take the answer only from the 352. */
    request_own_hostmask(state);
  } else if (strcmp(command, "433") == 0) {
    state->nick_change_pending = false;
    if (!(state->status & S_AUTHED)) {
      irc_generate_new_nick(state);
    }
  } else if (strcmp(command, "465") == 0 || strcmp(command, "463") == 0) {
    /* ERR_YOUREBANNEDCREEP / ERR_NOPERMFORHOST: this server is refusing us.
     * Only recorded here; irc_disconnect() classifies it and holds the server
     * when the link drops.  (474 below is a channel ban, not a server one.) */
    irc_note_refusal(state, irc_trailing(params), true);
  } else if (strcmp(command, "ERROR") == 0) {
    /* The server's last words before closing the link -- "Closing Link: ...
     * (K-Lined)", "(Throttled: ...)", "(Ping timeout)".  Classified at
     * disconnect alongside any 465/463. */
    irc_note_refusal(state, irc_trailing(params), false);
  } else if (strcmp(command, "474") == 0) {
    strtok_r(params, " ", &saveptr_irc);
    char *chan_name = strtok_r(NULL, " ", &saveptr_irc);
    if (chan_name) {
      chan_t *c = channel_find(state, chan_name);
      if (c) {
        c->status = C_OUT;
      }
    }
  } else if (strcmp(command, "405") == 0) {
    /* ERR_TOOMANYCHANNELS: server channel limit reached; stop retrying this channel */
    strtok_r(params, " ", &saveptr_irc);
    char *chan_name = strtok_r(NULL, " ", &saveptr_irc);
    if (chan_name) {
      chan_t *c = channel_find(state, chan_name);
      if (c) {
        c->join_disabled = true;
        log_message(L_INFO, state,
                    "[405] Channel limit reached, disabling join retry: %s\n",
                    chan_name);
      }
    }
  } else if (strcmp(command, "473") == 0) {
    /* ERR_INVITEONLYCHAN: need invite to join managed channel */
    strtok_r(params, " ", &saveptr_irc);
    char *chan_name = strtok_r(NULL, " ", &saveptr_irc);
    if (chan_name) {
      chan_t *c = channel_find(state, chan_name);
      if (c && c->is_managed) {
        log_message(L_INFO, state,
                    "[473] Channel %s is invite-only, requesting invite\n",
                    chan_name);
        if (!hub_client_send_invite_request(state, state->current_nick,
                                            chan_name)) {
          for (int tb = 0; tb < state->trusted_bot_count; tb++) {
            char tb_nick[MAX_NICK];
            /* %9 not %63: tb_nick is MAX_NICK(10); a longer nick in a
             * (mesh-synced) trusted_bots entry would overflow the stack. */
            if (sscanf(state->trusted_bots[tb], "%9[^!]", tb_nick) == 1) {
              bot_comms_send_command(state, tb_nick,
                                     "INVITE %s %s",
                                     chan_name, state->current_nick);
            }
          }
        }
      }
    }
  }
  // [MODIFIED] Robust MODE Parsing + Immediate Op Recovery
  else if (strcmp(command, "MODE") == 0 && params) {
    char params_copy[MAX_BUFFER];
    snprintf(params_copy, sizeof(params_copy), "%s", params);

    char *target = strtok_r(params_copy, " ", &saveptr_irc);
    char *modes = strtok_r(NULL, " ", &saveptr_irc);
    char *args = strtok_r(NULL, "", &saveptr_irc);

    if (target && modes && (target[0] == '#' || target[0] == '&')) {
      channel_handle_mode_change(state, target, modes, args);
      /* Push key/invite-only changes to hub */
      if (strchr(modes, 'k') || strchr(modes, 'i')) {
        chan_t *mc = channel_find(state, target);
        if (mc && mc->is_managed) {
          mc->timestamp = time(NULL);
          hub_client_push_channel(state, mc);
        }
      }
    }
  } else if (strcmp(command, "352") == 0) {
    strtok_r(params, " ", &saveptr_irc);
    char *chan_name = strtok_r(NULL, " ", &saveptr_irc);
    char *ident = strtok_r(NULL, " ", &saveptr_irc);
    char *host = strtok_r(NULL, " ", &saveptr_irc);
    strtok_r(NULL, " ", &saveptr_irc);
    char *nick = strtok_r(NULL, " ", &saveptr_irc);
    char *modes = strtok_r(NULL, " ", &saveptr_irc);

    if (!nick || !ident || !host || !modes)
      return;

    bool is_op = (strstr(modes, "@") != NULL);

    /* Self-mask capture, ahead of the channel lookup on purpose: the reply to
     * `WHO <nick>` (request_own_hostmask) carries "*" as the channel, so
     * gating this on channel_find would discard the one authoritative,
     * channel-independent source of our displayed mask.  This is the same
     * nick!ident@host every peer stores in trusted_bots[]. */
    if (strcasecmp(nick, state->current_nick) == 0) {
      char self_mask[MAX_MASK_LEN];
      snprintf(self_mask, sizeof(self_mask), "%s!%s@%s", nick, ident, host);
      update_own_hostmask(state, self_mask);
    }

    chan_t *c = channel_find(state, chan_name);
    if (!c)
      return;

    /* Always update own op status even when the roster array is full.
     * Without this, the bot's own 352 entry can be silently dropped in
     * large channels (>MAX_ROSTER_SIZE users), leaving i_am_opped = false
     * and triggering spurious OP-REQs on the next 315. */
    if (strcasecmp(nick, state->current_nick) == 0)
      c->i_am_opped = is_op;

    if (c->roster_count < MAX_ROSTER_SIZE) {
      roster_entry_t *entry = &c->roster[c->roster_count];
      snprintf(entry->nick, sizeof(entry->nick), "%s", nick);
      snprintf(entry->hostmask, sizeof(entry->hostmask), "%s!%s@%s", nick, ident, host);
      entry->is_op = is_op;
      c->roster_count++;
    }
  } else if (strcmp(command, "396") == 0) {
    char *hostname = strtok_r(params, " ", &saveptr_irc); // Nick
    hostname = strtok_r(NULL, " ", &saveptr_irc);         // Host

    if (hostname) {
      /* 396 gives only the host half, and a cloak can change the ident too.
       * Rather than splice a mask together — a guess about a string only the
       * server defines — treat it purely as a signal that our mask moved and
       * re-ask.  The 352 reply supplies the exact new value. */
      log_message(L_INFO, state, "[INFO] Displayed host changed to %s; "
                                 "re-checking my mask\n", hostname);
      request_own_hostmask(state);
    }
  } else if (strcmp(command, "315") == 0) {
    strtok_r(params, " ", &saveptr_irc);
    char *chan_name = strtok_r(NULL, " ", &saveptr_irc);
    if (!chan_name)
      return;

    chan_t *c = channel_find(state, chan_name);
    if (!c)
      return;

    log_message(L_INFO, state, "[INFO] Roster for %s updated with %d users.\n",
                c->name, c->roster_count);

    if (c->i_am_opped) {
      c->op_request_pending = false;
      c->op_request_retry_count = 0;
      return;
    }

    // Debug: only logged when we actually need op
    log_message(L_DEBUG, state, "[OP-REQ] trusted_bot_count=%d\n",
                state->trusted_bot_count);
    for (int i = 0; i < state->trusted_bot_count; i++) {
      log_message(L_DEBUG, state, "[OP-REQ] trusted_bots[%d]: %s\n", i,
                  state->trusted_bots[i]);
    }

    time_t now = time(NULL);
    if (c->op_request_pending && (now - c->last_op_request_time < 60)) {
      return;
    }
    // Reset retry counter after 5 minutes of no attempts
    if (c->op_request_retry_count >= 5 &&
        (now - c->last_op_request_time > 300)) {
      log_message(L_INFO, state,
                  "[INFO] Resetting retry counter for %s after timeout.\n",
                  c->name);
      c->op_request_retry_count = 0;
    }
    if (c->op_request_retry_count >= 5) {
      log_message(L_INFO, state,
                  "[INFO] Gave up requesting ops in %s after %d attempts.\n",
                  c->name, c->op_request_retry_count);
      return;
    }

    // Standard Polling Logic (runs if roster refresh happened naturally)
    roster_entry_t *helpers[MAX_ROSTER_SIZE];
    int helper_count = 0;

    log_message(L_DEBUG, state, "[OP-REQ] Scanning %d roster entries for trusted ops\n",
                c->roster_count);
    for (int i = 0; i < c->roster_count; i++) {
      roster_entry_t *entry = &c->roster[i];
      bool is_trusted = auth_is_trusted_bot(state, entry->hostmask, NULL, 0);
      log_message(L_DEBUG, state, "[OP-REQ] Roster[%d]: nick=%s hostmask=%s is_op=%d is_trusted=%d\n",
                  i, entry->nick, entry->hostmask, entry->is_op, is_trusted);
      if (entry->is_op && is_trusted) {
        if (helper_count < MAX_ROSTER_SIZE) {
          helpers[helper_count++] = entry;
        }
      }
    }

    if (helper_count > 0) {
      int random_index = rand() % helper_count;
      roster_entry_t *chosen_helper = helpers[random_index];

      log_message(L_INFO, state,
                  "[INFO] Found %d trusted ops. Randomly selected: %s. "
                  "Sending OPME request (attempt %d).\n",
                  helper_count, chosen_helper->nick,
                  c->op_request_retry_count + 1);

      c->last_op_request_time = now;
      c->op_request_pending = true;

      if (now - state->last_op_request_sent >= OP_REQUEST_MIN_INTERVAL) {
        // Try hub first - look up UUID for this helper
        bool sent_via_hub = false;
        log_message(L_DEBUG, state,
                    "[OP-REQ] Looking up UUID for helper: nick=%s hostmask=%s\n",
                    chosen_helper->nick, chosen_helper->hostmask);
        {
          char uuid[64];
          if (find_uuid_for_helper(state, chosen_helper, uuid, sizeof(uuid))) {
            log_message(L_DEBUG, state, "[OP-REQ] Found UUID, trying hub request\n");
            sent_via_hub = hub_client_request_op(state, uuid, c->name);
            log_message(L_DEBUG, state,
                        "[OP-REQ] hub_client_request_op returned: %d\n", sent_via_hub);
          }
        }

        // Fallback to PRIVMSG if hub unavailable
        if (!sent_via_hub) {
          log_message(L_DEBUG, state,
                      "[OP-REQ] Hub unavailable or no UUID match, falling back to PRIVMSG\n");
          bot_comms_send_command(state, chosen_helper->nick, "OPME %s", c->name);
        }
        state->last_op_request_sent = now;
        c->op_request_retry_count++;
      } else {
        log_message(L_DEBUG, state,
                    "[OP-REQ] Rate limited in %s; will retry (attempt %d pending)\n",
                    c->name, c->op_request_retry_count + 1);
      }
    } else {
      log_message(L_DEBUG, state,
                  "[OP-REQ] No trusted ops in roster. "
                  "trusted_bot_count=%d, roster_count=%d\n",
                  state->trusted_bot_count, c->roster_count);
      // Don't burn retry_count — no helper present yet isn't a failed attempt.
      // Set pending with a 30-second back-date so channel_manager retries
      // via WHO in ~30 seconds (the 60-second timeout fires after 30 more).
      c->op_request_pending = true;
      c->last_op_request_time = now - 30;
    }
  } else if (strcmp(command, "PRIVMSG") == 0 && prefix) {
    char *nick = strtok_r(prefix, "!", &saveptr_irc);
    char *user = strtok_r(NULL, "@", &saveptr_irc);
    char *host = strtok_r(NULL, "", &saveptr_irc);
    char *dest = strtok_r(params, " ", &saveptr_irc);
    char *message = strtok_r(NULL, "", &saveptr_irc);
    if (message && *message == ':')
      message++;

    if (nick && dest && message) {
      size_t msg_len = strlen(message);
      if (msg_len >= 2 && message[0] == '\001' && message[msg_len - 1] == '\001') {
        log_message(L_CTCP, state, "[CTCP] (%s) %s\n", nick, message);

        message[msg_len - 1] = '\0';
        char *ctcp_command = message + 1;

        if (strcasecmp(ctcp_command, "VERSION") == 0) {
          irc_printf(state, "NOTICE %s :\001VERSION %s\001\r\n", nick,
                     VERSION_RESPONSE);
        } else if (strncasecmp(ctcp_command, "PING ", 5) == 0) {
          irc_printf(state, "NOTICE %s :\001%s\001\r\n", nick, ctcp_command);
        }
      } else {
        commands_handle_private_message(state, nick, user, host, dest, message);
      }
    }
  } else if (strcmp(command, "JOIN") == 0 && prefix) {
    /* Our own JOIN echo carries, as its prefix, the server presenting our mask
     * to the channel — the identical string every other client in that channel
     * receives, and byte-for-byte the same as our 352 entry (verified against
     * ngircd, 2026-09-08).  Copy it before strtok_r splits prefix in place.
     * This is the earliest exact value available: it lands before the channel
     * WHO we are about to send comes back. */
    char join_mask[MAX_MASK_LEN];
    size_t prefix_len = strlen(prefix);
    /* Explicit length test, not a bounded copy: a prefix that does not fit a
     * mask buffer is not a mask we may store — publishing a truncated one is
     * worse than publishing none, and the 352 is still coming. */
    bool join_mask_ok = (prefix_len > 0 && prefix_len < sizeof(join_mask));
    if (join_mask_ok) {
      memcpy(join_mask, prefix, prefix_len);
      join_mask[prefix_len] = '\0';
    }

    char *nick = strtok_r(prefix, "!", &saveptr_irc);
    if (join_mask_ok && nick && strcasecmp(nick, state->current_nick) == 0 &&
        strchr(join_mask, '!') && strchr(join_mask, '@'))
      update_own_hostmask(state, join_mask);

    if (nick && (strcasecmp(nick, state->current_nick) == 0 ||
                 strcasecmp(nick, state->target_nick) == 0)) {
      char *chan_name = (*params == ':') ? params + 1 : params;
      chan_t *c = channel_find(state, chan_name);
      if (c) {
        c->status = C_IN;
        c->roster_count = 0;
        c->i_am_opped = false;
        snprintf(state->who_request_channel, sizeof(state->who_request_channel),
                 "%s", c->name);
        c->last_who_request = time(NULL);
        irc_printf(state, "WHO %s\r\n", c->name);
      }
    }
  } else if (strcmp(command, "PART") == 0 && prefix) {
    char *nick = strtok_r(prefix, "!", &saveptr_irc);
    if (nick && (strcasecmp(nick, state->current_nick) == 0 ||
                 strcasecmp(nick, state->target_nick) == 0)) {
      // Extract channel name (may have : prefix or trailing reason)
      char *chan_name = (*params == ':') ? params + 1 : params;
      char *space = strchr(chan_name, ' ');
      if (space) *space = '\0';  // Remove part reason if present
      chan_t *c = channel_find(state, chan_name);
      if (c) {
        c->status = C_OUT;
        c->roster_count = 0;
        c->i_am_opped = false;
        log_message(L_DEBUG, state, "[IRC] Parted channel %s\n", chan_name);
      }
    }
  } else if (strcmp(command, "KICK") == 0 && params) {
    char params_copy[MAX_BUFFER];
    snprintf(params_copy, sizeof(params_copy), "%s", params);

    char *chan_name = strtok_r(params_copy, " ", &saveptr_irc);
    char *kicked_nick = strtok_r(NULL, " ", &saveptr_irc);
    if (chan_name && kicked_nick &&
        strcasecmp(kicked_nick, state->current_nick) == 0) {
      chan_t *c = channel_find(state, chan_name);
      if (c) {
        c->status = C_OUT;
        c->i_am_opped = false;
      }
    }
  } else if (strcmp(command, "NICK") == 0 && prefix) {
    char *old_nick = strtok_r(prefix, "!", &saveptr_irc);
    char *new_nick = (*params == ':') ? params + 1 : params;
    if (old_nick && new_nick &&
        strcasecmp(old_nick, state->current_nick) == 0) {
      snprintf(state->current_nick, sizeof(state->current_nick), "%s", new_nick);
      state->current_nick_ts = time(NULL);

      /* Push nick change as a targeted delta immediately. */
      if (state->hub_connected && state->hub_authenticated) {
        hub_client_push_delta(state, "n", state->current_nick,
                              state->current_nick_ts);
      }

      /* Our mask just changed in its nick half, and some networks reassign
       * host/cloak on a nick change too.  No local re-splice: ask, and let the
       * 352 supply the exact string.  Until it arrives actual_hostname briefly
       * holds the previous nick — a stale-but-real mask the server did once
       * present, which is strictly safer to publish than a guessed one.  One
       * WHO per nick change is not sustained traffic. */
      request_own_hostmask(state);

      state->nick_change_pending = false;
      if (strcasecmp(state->current_nick, state->target_nick) == 0) {
        state->nick_generation_attempt = 0;
      }
    }
  }
}
