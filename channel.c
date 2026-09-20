#include "bot.h"
#include <stdlib.h>
#include <string.h>
#include <strings.h>

chan_t *channel_add(bot_state_t *state, const char *name) {
  if (channel_find(state, name)) {
    return NULL;
  }
  chan_t *new_chan = calloc(1, sizeof(chan_t));
  if (!new_chan)
    handle_fatal_error("calloc failed");

  snprintf(new_chan->name, MAX_CHAN, "%s", name);
  new_chan->status = C_OUT;
  new_chan->last_join_attempt = 0;
  new_chan->key[0] = '\0';
  new_chan->roster_count = 0;
  new_chan->op_request_pending = false;
  new_chan->last_op_request_time = 0;
  new_chan->op_request_retry_count = 0;
  new_chan->is_managed = true;      // Default to managed (add)
  new_chan->timestamp = time(NULL); // Default to current time
  new_chan->next = NULL;

  if (state->chanlist == NULL) {
    state->chanlist = new_chan;
  } else {
    chan_t *current = state->chanlist;
    while (current->next != NULL) {
      current = current->next;
    }
    current->next = new_chan;
  }
  state->chan_count++;
  return new_chan;
}

bool channel_remove(bot_state_t *state, const char *name) {
  chan_t *current = state->chanlist, *prev = NULL;
  while (current) {
    if (strcasecmp(current->name, name) == 0) {
      if (prev)
        prev->next = current->next;
      else
        state->chanlist = current->next;
      free(current);
      state->chan_count--;
      return true;
    }
    prev = current;
    current = current->next;
  }
  return false;
}

chan_t *channel_find(const bot_state_t *state, const char *name) {
  for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
    if (strcasecmp(c->name, name) == 0)
      return c;
  }
  return NULL;
}

void channel_list_destroy(bot_state_t *state) {
  chan_t *current = state->chanlist;
  while (current) {
    chan_t *next = current->next;
    free(current);
    current = next;
  }
  state->chanlist = NULL;
  state->chan_count = 0;
}

void channel_list_reset_status(bot_state_t *state) {
  for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
    c->status = C_OUT;
    c->last_join_attempt = 0;
    c->join_disabled = false;
    c->i_am_opped = false;
    c->op_request_pending = false;
    c->op_request_retry_count = 0;
    /* A reconnect may well have given us a new hostmask, so a ban or key that
     * locked us out before deserves a fresh set of attempts. */
    for (int k = 0; k < CHAN_REQ_KIND_COUNT; k++) {
      c->last_access_request[k] = 0;
      c->access_retry_count[k] = 0;
    }
  }
  for (int i = 0; i < MAX_UNBAN_JOBS; i++)
    state->unban_jobs[i].active = false;
}

void channel_manager_check_joins(bot_state_t *state) {
  if (!(state->status & S_AUTHED))
    return;

  time_t now = time(NULL);
  /* Close out ban-list walks whose 368 never arrived. */
  chan_unban_expire(state);

  for (chan_t *c = state->chanlist; c != NULL; c = c->next) {
    // Skip tombstoned/deleted channels and channels blocked by 405
    if (!c->is_managed || c->join_disabled)
      continue;

    if (c->status != C_IN && (now - c->last_join_attempt > JOIN_RETRY_TIME)) {
      if (c->key[0] != '\0') {
        irc_printf(state, "JOIN %s %s\r\n", c->name, c->key);
      } else {
        irc_printf(state, "JOIN %s\r\n", c->name);
      }
      c->last_join_attempt = now;
      continue;
    }
    if (c->status == C_IN) {
      if (c->i_am_opped) {
        c->op_request_pending = false;
        c->op_request_retry_count = 0;
        // No periodic WHO while opped: nothing reads the roster until we are
        // deopped, and the MODE -o handler re-reads the channel then.
        continue;
      }
      bool should_refresh = false;
      if (c->roster_count == 0 && (now - c->last_who_request > 30)) {
        log_message(L_DEBUG, state,
                    "[DEBUG] No roster for %s. Requesting WHO.\n", c->name);
        should_refresh = true;
      } else if (now - c->last_who_request > ROSTER_REFRESH_INTERVAL) {
        log_message(L_DEBUG, state,
                    "[DEBUG] Periodic roster refresh for %s (not opped).\n",
                    c->name);
        should_refresh = true;
      } else if (c->op_request_pending &&
                 (now - c->last_op_request_time > 60) &&
                 c->op_request_retry_count < 5) {
        log_message(L_DEBUG, state,
                    "[DEBUG] Op request timeout in %s. Refreshing to retry.\n",
                    c->name);
        should_refresh = true;
        c->op_request_pending = false;
      }
      if (should_refresh) {
        c->roster_count = 0;
        irc_printf(state, "WHO %s\r\n", c->name);
        c->last_who_request = now;
      }
    }
  }
}

/* ===================== Channel-access requests =============================
 * Getting back into a managed channel we are locked out of: 474 (banned),
 * 473 (invite-only) and 475 (bad key) each raise a request that the hub mesh
 * fans out to the other bots.  With no hub up we fall back to a sealed ~B2
 * PRIVMSG aimed at one trusted bot per attempt -- round-robin rather than a
 * broadcast, so a network of N bots does not answer every lockout N times.
 *
 * Nothing here trusts the requester for anything that matters: the hub fills
 * in the nick and hostmask from its own records, and a bot servicing an unban
 * removes only ban masks that actually match that hostmask.
 * ========================================================================= */

static const char *const chan_req_tokens[CHAN_REQ_KIND_COUNT] = {
    CHAN_REQ_TOK_UNBAN, CHAN_REQ_TOK_INVITE, CHAN_REQ_TOK_KEY};

const char *chan_req_kind_token(chan_req_kind_t kind) {
  if (kind < 0 || kind >= CHAN_REQ_KIND_COUNT)
    return "";
  return chan_req_tokens[kind];
}

chan_req_kind_t chan_req_kind_from_token(const char *tok) {
  if (!tok)
    return CHAN_REQ_KIND_COUNT;
  for (int i = 0; i < CHAN_REQ_KIND_COUNT; i++)
    if (strcasecmp(tok, chan_req_tokens[i]) == 0)
      return (chan_req_kind_t)i;
  return CHAN_REQ_KIND_COUNT;
}

/* One trusted bot per attempt, advancing each time so a bot that is offline
 * or unhelpful does not absorb every retry.  Returns false when the roster is
 * empty or none of the entries yields a usable nick. */
static bool chan_access_fallback(bot_state_t *state, chan_req_kind_t kind,
                                 const char *channel) {
  if (state->trusted_bot_count <= 0)
    return false;

  for (int tried = 0; tried < state->trusted_bot_count; tried++) {
    int idx = state->chan_req_fallback_idx % state->trusted_bot_count;
    state->chan_req_fallback_idx = (idx + 1) % state->trusted_bot_count;

    char tb_nick[MAX_NICK];
    auth_trusted_bot_nick(&state->trusted_bots[idx], tb_nick);
    if (tb_nick[0] == '\0')
      continue;
    /* Our own record may be in the roster; asking ourselves achieves nothing. */
    if (state->current_nick[0] != '\0' &&
        strcasecmp(tb_nick, state->current_nick) == 0)
      continue;

    switch (kind) {
    case CHAN_REQ_UNBAN:
      bot_comms_send_command(state, tb_nick, "UNBAN %s", channel);
      break;
    case CHAN_REQ_INVITE:
      /* Nothing to invite without a nick the server has accepted. */
      if (state->current_nick[0] == '\0')
        return false;
      bot_comms_send_command(state, tb_nick, "INVITE %s %s", channel,
                             state->current_nick);
      break;
    case CHAN_REQ_KEY:
      bot_comms_send_command(state, tb_nick, "KEY %s", channel);
      break;
    default:
      return false;
    }
    log_message(L_INFO, state, "[CHANREQ] %s for %s via %s (no hub)\n",
                chan_req_kind_token(kind), channel, tb_nick);
    return true;
  }
  return false;
}

bool chan_access_request(bot_state_t *state, chan_t *chan,
                         chan_req_kind_t kind) {
  if (!chan || kind < 0 || kind >= CHAN_REQ_KIND_COUNT)
    return false;
  if (!chan->is_managed || chan->join_disabled)
    return false;
  if (!(state->status & S_AUTHED))
    return false;

  time_t now = time(NULL);

  /* Long quiet spell clears the retry count so a channel that locked us out
   * hours ago is chased again rather than being written off for the session. */
  if (chan->access_retry_count[kind] >= CHAN_REQUEST_MAX_RETRIES) {
    if (now - chan->last_access_request[kind] > CHAN_REQUEST_COOLOFF) {
      chan->access_retry_count[kind] = 0;
    } else {
      return false;
    }
  }
  if (chan->last_access_request[kind] != 0 &&
      now - chan->last_access_request[kind] < CHAN_REQUEST_RETRY_TIME)
    return false;
  /* Global spacing: a bot rejoining after a netsplit can trip 473/474/475 on
   * many channels in the same second. */
  if (now - state->last_chan_request_sent < CHAN_REQUEST_MIN_INTERVAL)
    return false;

  bool sent = hub_client_send_chan_request(state, chan_req_kind_token(kind),
                                           chan->name);
  if (!sent)
    sent = chan_access_fallback(state, kind, chan->name);
  if (!sent)
    return false;

  chan->last_access_request[kind] = now;
  chan->access_retry_count[kind]++;
  state->last_chan_request_sent = now;
  return true;
}

/* ---- Servicing a request another bot made of us ------------------------- */

static unban_job_t *unban_job_find(bot_state_t *state, const char *channel) {
  for (int i = 0; i < MAX_UNBAN_JOBS; i++)
    if (state->unban_jobs[i].active &&
        strcasecmp(state->unban_jobs[i].channel, channel) == 0)
      return &state->unban_jobs[i];
  return NULL;
}

void chan_unban_expire(bot_state_t *state) {
  time_t now = time(NULL);
  for (int i = 0; i < MAX_UNBAN_JOBS; i++) {
    unban_job_t *j = &state->unban_jobs[i];
    if (j->active && now - j->started > UNBAN_JOB_TTL) {
      log_message(L_DEBUG, state,
                  "[DEBUG] [UNBAN] Ban list for %s never closed; job dropped\n",
                  j->channel);
      j->active = false;
    }
  }
}

/* Raise a job and ask the server for the ban list.  Collapsing onto an
 * existing job for the same channel keeps a burst of requests to one walk. */
static bool unban_job_start(bot_state_t *state, const char *channel,
                            const char *hostmask) {
  chan_unban_expire(state);
  if (unban_job_find(state, channel))
    return false;

  for (int i = 0; i < MAX_UNBAN_JOBS; i++) {
    unban_job_t *j = &state->unban_jobs[i];
    if (j->active)
      continue;
    snprintf(j->channel, sizeof(j->channel), "%s", channel);
    snprintf(j->hostmask, sizeof(j->hostmask), "%s", hostmask);
    j->started = time(NULL);
    j->removed = 0;
    j->active = true;
    irc_printf(state, "MODE %s +b\r\n", channel);
    log_message(L_INFO, state, "[UNBAN] Walking ban list of %s for %s\n",
                channel, hostmask);
    return true;
  }
  log_message(L_INFO, state, "[UNBAN] No free job slot for %s\n", channel);
  return false;
}

/* One 367 entry.  Only masks that actually match the requester come off, and
 * never more than UNBAN_MAX_REMOVALS of them: a channel whose ban list is
 * mostly wildcards must not be emptied on one bot's say-so. */
void chan_unban_note_ban(bot_state_t *state, const char *channel,
                         const char *ban_mask) {
  unban_job_t *j = unban_job_find(state, channel);
  if (!j || !ban_mask || ban_mask[0] == '\0')
    return;
  if (j->removed >= UNBAN_MAX_REMOVALS)
    return;
  if (!auth_wildcard_match(ban_mask, j->hostmask))
    return;

  chan_t *c = channel_find(state, channel);
  if (!c || c->status != C_IN || !c->i_am_opped)
    return;

  irc_printf(state, "MODE %s -b %s\r\n", channel, ban_mask);
  j->removed++;
  log_message(L_INFO, state, "[UNBAN] Removed %s from %s (matched %s)\n",
              ban_mask, channel, j->hostmask);
}

void chan_unban_finish(bot_state_t *state, const char *channel) {
  unban_job_t *j = unban_job_find(state, channel);
  if (!j)
    return;
  if (j->removed == 0)
    log_message(L_INFO, state, "[UNBAN] No ban in %s matched %s\n", channel,
                j->hostmask);
  j->active = false;
}

void chan_access_service(bot_state_t *state, const char *request_id,
                         chan_req_kind_t kind, const char *channel,
                         const char *req_uuid, const char *nick,
                         const char *hostmask, const char *reply_to) {
  (void)req_uuid;
  if (!channel || channel[0] == '\0' || kind >= CHAN_REQ_KIND_COUNT)
    return;

  chan_t *c = channel_find(state, channel);
  if (!c || c->status != C_IN) {
    log_message(L_DEBUG, state,
                "[DEBUG] [CHANREQ] %s for %s ignored: not in channel\n",
                chan_req_kind_token(kind), channel);
    return;
  }

  switch (kind) {
  case CHAN_REQ_UNBAN:
    if (!hostmask || hostmask[0] == '\0')
      return;
    if (!c->i_am_opped) {
      log_message(L_DEBUG, state,
                  "[DEBUG] [UNBAN] Not opped in %s; cannot help\n", channel);
      return;
    }
    unban_job_start(state, channel, hostmask);
    break;

  case CHAN_REQ_INVITE:
    if (!nick || nick[0] == '\0')
      return;
    if (!c->i_am_opped) {
      log_message(L_DEBUG, state,
                  "[DEBUG] [INVITE] Not opped in %s; cannot help\n", channel);
      return;
    }
    log_message(L_INFO, state, "[INVITE] Inviting %s into %s (mesh request)\n",
                nick, channel);
    irc_printf(state, "INVITE %s %s\r\n", nick, channel);
    break;

  case CHAN_REQ_KEY:
    /* Being in the channel is enough -- ops are not needed to know the key,
     * and only a bot actually sitting in it has the current one. */
    if (c->key[0] == '\0') {
      log_message(L_DEBUG, state,
                  "[DEBUG] [CHANREQ] No key held for %s; staying quiet\n",
                  channel);
      return;
    }
    if (reply_to && reply_to[0] != '\0') {
      bot_comms_send_command(state, reply_to, "KEYIS %s %s", channel, c->key);
      log_message(L_INFO, state, "[CHANREQ] Sent key for %s to %s (~B2)\n",
                  channel, reply_to);
    } else if (request_id && request_id[0] != '\0') {
      hub_client_send_chan_reply(state, request_id, chan_req_kind_token(kind),
                                 channel, "ok", c->key);
      log_message(L_INFO, state, "[CHANREQ] Sent key for %s via hub\n",
                  channel);
    }
    break;

  default:
    break;
  }
}

/* A key handed to us by another bot.  Accepted only for a managed channel we
 * are actually locked out of, so a stray reply cannot rewrite a good key. */
void chan_access_accept_key(bot_state_t *state, const char *channel,
                            const char *key) {
  if (!channel || !key || key[0] == '\0')
    return;
  if (strlen(key) >= MAX_KEY) {
    log_message(L_INFO, state, "[CHANREQ] Oversized key for %s ignored\n",
                channel);
    return;
  }
  chan_t *c = channel_find(state, channel);
  if (!c || !c->is_managed)
    return;
  if (c->status == C_IN)
    return; /* already in: our own key is the authoritative one */
  /* Only for a channel we actually asked about, and only while that request
   * is still live -- an unsolicited key must not rewrite a working one. */
  if (c->last_access_request[CHAN_REQ_KEY] == 0 ||
      time(NULL) - c->last_access_request[CHAN_REQ_KEY] > CHAN_REPLY_ACCEPT_WINDOW) {
    log_message(L_INFO, state,
                "[CHANREQ] Unsolicited key for %s ignored\n", channel);
    return;
  }
  if (strcmp(c->key, key) == 0)
    return;

  snprintf(c->key, sizeof(c->key), "%s", key);
  c->timestamp = lww_next_ts(c->timestamp);
  log_message(L_INFO, state, "[CHANREQ] Learned key for %s; retrying join\n",
              channel);
  hub_client_push_channel(state, c);
  config_write_with_state_pass(state);

  /* Go straight back in rather than waiting out JOIN_RETRY_TIME. */
  c->last_join_attempt = 0;
}
