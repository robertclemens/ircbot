#ifndef BOT_H
#define BOT_H

#ifdef HAVE_CURL
#include <curl/curl.h>
#endif
#include <errno.h>
#include <limits.h>
#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>

/* A non-blocking call with nothing to do.  POSIX lets EAGAIN and EWOULDBLOCK
 * differ; where they are one value (Linux) testing both trips -Wlogical-op. */
#if EAGAIN == EWOULDBLOCK
#define IO_WOULD_BLOCK(e) ((e) == EAGAIN)
#else
#define IO_WOULD_BLOCK(e) ((e) == EAGAIN || (e) == EWOULDBLOCK)
#endif

/* FD_ISSET for a descriptor already known to be >= 0.  musl does the macro's
 * index math in unsigned long, which -Wsign-conversion reports at every call;
 * the one conversion is spelled out here. */
static inline bool fd_isset(int fd, const fd_set *set) {
  return FD_ISSET((unsigned)fd, set) != 0;
}

#define BOT_NAME "ircbot.c by trojanman"
/* -D-overridable so a release build can stamp its own version without
 * editing the tree (the testnet builds a bumped-version artifact this
 * way).  This is the version the bot reports in CMD_BOT_PRESENCE, and the
 * one every upgrade comparison is made against. */
#ifndef BOT_VERSION
#define BOT_VERSION "2.5.0"
#endif

// Only edit this section
// #define DEFAULT_USER "ircbot"         // Default bot user
#define VHOST "NULL" // NULL for default host, set for alternate
#define PASS_FILE ".ircbot.pass"        // Machine-bound password file
/* PBKDF2-HMAC-SHA256 rounds for the .ircbot.cnf and .ircbot.pass keys.
 * 2.5.0 raised them from 100k (PBKDF2_ITERATIONS_LEGACY, OWASP's 2023 figure
 * is 600k).  A file still under the legacy count is read and rewritten once
 * (config_load / passfile_load); releases after 2.5.0 carry min_from 2.5.0 so
 * no node skips that rewrite. */
#define PBKDF2_ITERATIONS 600000
#define PBKDF2_ITERATIONS_LEGACY 100000
#define VERSION_RESPONSE                                                       \
  "A robot may not injure a human being" // This is the response to a CTCP
                                         // Version

// #define GECOS "ircbot"         // Gecos field storage
#define CONFIG_FILE ".ircbot.cnf" // Config file name
#define PID_FILE ".ircbot.pid"    // PID file name
/* Hand-off note written just before a hub-driven upgrade execs the new
 * binary: the restarted process has no memory of the run that replaced it,
 * so it reads the upgrade id from here and answers CMD_UPGRADE_RESULT. */
#define UPGRADE_MARKER_FILE ".ircbot.upgrade"
/* Retained previous binary/config, kept (not deleted) after a hub-driven
 * upgrade so CMD_UPGRADE_ABORT can put the node back. */
#define UPGRADE_PREV_SUFFIX ".prev"
#define PASS_PREV_FILE PASS_FILE UPGRADE_PREV_SUFFIX /* the pre-2.5.0 pass kept for a rollback */
/* How long a CMD_UPGRADE_PREPARE stays commitable.  A hub that stalls
 * mid-roll has to ask again rather than commit against a stale plan. */
#define UPGRADE_PREPARE_TTL 900
/* Updater transfer budgets (seconds).  A manifest read answered from the
 * event loop (a PREPARE check) gets the short one: the bot serves neither IRC
 * nor its hub link while curl blocks.  COMMIT's download gets the long one,
 * which still bounds it — an unbounded transfer would wedge the bot. */
#define UPGRADE_QUICK_TIMEOUT 8L
#define UPDATE_FETCH_TIMEOUT 300L
/* The upgrade script's startup watchdog: how long the new build's daemon has
 * to be up before the script keeps it (mirrors irchub). */
#define UPGRADE_WATCH_SECS 20
/* A pre-2.5.0 PASS_FILE found on the start a hub-driven upgrade made is
 * rewritten at PBKDF2_ITERATIONS this long after that start: past the old
 * build's watchdog, which restores <exe>.prev and the config but not this
 * file.  The old copy stays as PASS_FILE UPGRADE_PREV_SUFFIX until the next
 * ordinary start, for this process's own hub-ordered rollback to put back. */
#define UPGRADE_PASS_REWRITE_SECS 120
_Static_assert(UPGRADE_PASS_REWRITE_SECS > 3 * UPGRADE_WATCH_SECS,
               "the pass rewrite must wait out the old build's watchdog");
/* After an upgrade restart the bot holds its "ok" RESULT until it is back on
 * IRC and re-opped in every channel it was opped in before (the marker's ops
 * line), or this many seconds have passed — the hub refills its wave only
 * when a bot is done, so no channel loses its ops to a fast rolling run. */
#define UPGRADE_OPS_WAIT 180
/* The staged new binary's -selftest must finish within this many seconds. */
#define UPGRADE_SELFTEST_SECS 15
/* The first ircbot release that knows -selftest: an older target would take
 * the flag for a normal start, so its staged binary is never run. */
#define UPGRADE_SELFTEST_MIN "2.4.5"
/* Marker ops line capacity: channel names, space-separated. */
#define UPGRADE_OPS_MAX 1024
#define SALT_SIZE 16          // Modern standard: 128-bit entropy (matches hub)
/* The log FILE is off by default: a production bot writes nothing to disk
 * until 'setlog' (l| in the config) turns it on.  The in-memory ring that
 * 'getlog' reads is fed at every level. */
#define DEFAULT_LOG_LEVEL 0   // default log mask: 0 = none
#define LOG_LEVEL_MAX 63      // every log type (L_MSG..L_DEBUG)
#define LOGFILE ".ircbot.log" // Log file name. Only used if log level > 0
#define BOT_LOG_FILE_SIZE (10 * 1024 * 1024) // default cap; LOGFILE is truncated past it
/* Bounds on the per-bot cap (L|<bytes> in the config, set by 'setlog <level>
 * <maxbytes>'): same range the hub takes for CMD_ADMIN_SET_LOG_SIZE. */
#define BOT_LOG_SIZE_MIN 1024L
#define BOT_LOG_SIZE_MAX (1024L * 1024 * 1024)
// Signed-release channel (ircbot-releases).  All of these are -D-overridable
// (the testnet injects a throwaway signing key), and at RUNTIME the
// IRCBOT_UPDATE_BASE env var repoints the updater at a local ircbot-releases
// tree (see updater_env_base() in utils.c).  Empty pubkey DISABLES updates
// (fail-closed).
//
// BOT_UPDATE_BASE is the tree ROOT; one variant subdirectory below it holds
// that build's manifest.  Keeping the root separate is what lets a hub-driven
// upgrade flip a node between the C and Rust builds: updater_hub_commit()
// appends the variant it was told to install, so one network-wide run can
// leave each node on its own kind of build, or move it across.
#ifndef BOT_UPDATE_BASE
#define BOT_UPDATE_BASE                                                        \
  "https://raw.githubusercontent.com/robertclemens/ircbot-releases/main/"      \
  "ircbot"
#endif
// The variant THIS build is: the standalone 'update' command stays on it.
#ifndef BOT_UPDATE_VARIANT
#define BOT_UPDATE_VARIANT "c"
#endif
#ifndef BOT_UPDATE_URL
#define BOT_UPDATE_URL BOT_UPDATE_BASE "/" BOT_UPDATE_VARIANT "/releases.txt"
#endif
// Detached Ed25519 signature for releases.txt (raw 64-byte sig, base64-encoded).
#ifndef BOT_UPDATE_SIG_URL
#define BOT_UPDATE_SIG_URL BOT_UPDATE_BASE "/" BOT_UPDATE_VARIANT "/releases.sig"
#endif
// Base64 of the 32-byte raw Ed25519 PUBLIC key that signs releases.txt.
// MUST be set to enable the self-updater; an empty value DISABLES updates
// (fail-closed).  Same key signs ircbot-releases and irchub-releases.
// Full procedure: docs/security.md -> "Signed Release Process".
#ifndef BOT_UPDATE_PUBKEY_B64
#define BOT_UPDATE_PUBKEY_B64 "qkXMh/F8TC+cnKuIwrP5TJIynfrLBD+MDUwvkyh9lBU="
#endif
// End of edit section

// You should not edit below this line. While some of the macros may be
// editable, some macros may cause issues. Proceed at your own risk.

// Timeouts
#define JOIN_RETRY_TIME 10 // Time delay between trying to join a channel
#define NICK_TAKE_TIME                                                         \
  20 // Time delay for givenick to stop trying to take the nick back
#define NICK_RETRY_TIME                                                        \
  10 // Time delay for trying to gain the target nick (outside of givenick cmd)
#define DEAD_SERVER_TIMEOUT 120 // Server connection timeout
#define CHECK_LAG_TIMEOUT 60    // Lag timeout
#define IRC_REGISTER_TIMEOUT 90 // Connected but no 001 by then: drop, try the next server
#define ROSTER_REFRESH_INTERVAL 120 // WHO interval (s) when NOT opped (seeking ops); opped bots WHO only on deop
#define HUB_RECONNECT_DELAY 30 // [NEW] Delay between hub connection attempts
/* IRC server refusals (bans / throttles) -- see irc_note_refusal().  A server
 * that refuses the bot is skipped until its hold expires. */
#define IRC_RECONNECT_MIN_INTERVAL 10 // Floor between any two IRC connect attempts
#define IRC_THROTTLE_BACKOFF 60       // Throttled: first hold, doubling per strike...
#define IRC_THROTTLE_BACKOFF_MAX 1800 // ...capped at 30 min
#define IRC_BAN_BACKOFF 900           // Banned, no length stated: 15 min, doubling...
#define IRC_BAN_BACKOFF_MAX 86400     // ...capped at 24 h
#define IRC_BAN_STATED_MAX 2592000    // Clamp a server-stated ban length to 30 days
#define IRC_BAN_GRACE 30              // Added to a stated ban length (clock skew)

// Limits
#define MAX_SERVERS 10 // Max number of servers to store
#define MAX_MASKS 20   // Max number of admin masks to store (kept for migration)
#define MAX_USER_RECORDS 40   // max combined admin + oper records
#define MAX_USER_MASKS   200  // max total usermask records across all users
/* Admin flags and oper channel bindings (irchub docs/plans/
 * 2026-10-16_user_flags_plan.md §3.1), mirrored from irchub/hub.h: the
 * letters in canonical order (a full, b bots, c channels, h hub, o opers,
 * u upgrades), one uf| per user, uc| live + tombstones, the migration stamp. */
#define USER_FLAG_LETTERS   "abchou"
#define USER_FLAGS_MAX      6
#define MAX_USER_FLAGS      MAX_USER_RECORDS
#define MAX_CHAN_BINDS      400
#define USER_ACCESS_MIGRATE_TS 1
#define MAX_CHAN 65    // Max length of channel name. Do not change
#define MAX_BUFFER                                                             \
  16384 // Size of RAW IRC message. Do not change (Matched to Hub size)
#define MAX_NICK 10  // Max nick length 9 + NULL terminator = 10. Do not change
#define OP_GRANT_HOLD_MAX 8   // OP_GRANTs held per channel until our own +o
#define OP_GRANT_HOLD_SECS 15 // ...and for at most this long
/* Other people's nicks (roster, flood tracking): the server's NICKLEN, which
 * is 30 and more on today's networks, not this bot's own 9-character limit. */
#define MAX_MEMBER_NICK 32
#define MAX_PASS 128 // Max password length.
#define MAX_KEY 31   // Max length for a channel key
#define MAX_MASK_LEN 256    // Max usermask length
#define MAX_OP_MASKS 20     // Max number of operators
#define MAX_TRUSTED_BOTS 200 // Max number of trusted bots

/* ==========================================================================
 * Bulk config-payload ceiling (Change 5) — shared contract with irchub/hub.h.
 * MAX_BUFFER (16 KB) stays the wire-frame size for small messages (deltas, op
 * requests, pings).  A full CMD_CONFIG_DATA from the hub can be much larger, so
 * its receive/decrypt/parse buffers size to MAX_CONFIG_PAYLOAD instead.  This
 * must be >= the hub's MAX_CONFIG_PAYLOAD so the bot can always receive what the
 * hub sends; the counts match (records 40, masks 200) and MAX_TRUSTED_BOTS (200)
 * >= the hub's MAX_BOTS, so this formula yields >= the hub's ceiling.
 * ========================================================================== */
#define CFG_GLOBAL_LINE_MAX 1088  /* key[32]+value[1024]+ts+seps */
#define CFG_BOT_FIELD_LINE  320   /* per-bot line: capped value */
#define CFG_USER_LINE_MAX   384   /* a|/o|: uuid+name+pubkey (legacy: +password) */
#define CFG_MASK_LINE_MAX   352   /* m|: uuid+MAX_MASK_LEN */
#define CFG_UF_LINE_MAX     96    /* uf|<uuid>|<flags>|<ts> */
#define CFG_UC_LINE_MAX     160   /* uc|<uuid>|<chan>|add/del|<ts> */
#define CFG_BLINE_MAX       448   /* b|<mask>|<uuid>|<pubkey>|<ts> */
#define CFG_MAX_GLOBALS     64    /* mirrors hub MAX_BOT_ENTRIES */
/* hl|<addr>/<fp>,...: the hubs this bot dials, in every config push, for the
 * hub console's hub del preview.  Mirrors irchub's hub.h. */
#define HL_ADDR_MAX         80
#define HL_FP_LEN           16    /* hex of SHA-256(hub Ed25519 key)[0..8] */
#define HL_VALUE_MAX        (MAX_SERVERS * (HL_ADDR_MAX + 1 + HL_FP_LEN + 1))
#define CFG_BOT_SYNC_FIELDS 8
#define CFG_PAYLOAD_SLACK   8192
/* modes.md §2: C| (per channel), D| (one) and B| (bans) lines.  The ceiling
 * stays derived from these macros, so the C| / D| / B| ingest caps below are
 * what make it a hard bound. */
#define C_MODES_MAX         64    /* modes field of C| / D| */
#define C_SETTINGS_MAX      512   /* settings field of C| */
#define D_SETTINGS_MAX      512   /* settings field of D| */
#define BAN_REASON_MAX      120
#define BAN_MASK_MAX        120
#define BAN_SETTER_MAX      63    /* admin name or bot uuid */
#define MAX_BANS_PER_CHAN   100
#define MAX_GLOBAL_BANS     100   /* bans with channel "*" */
#define CFG_MAX_CHANNELS    CFG_MAX_GLOBALS
#define C_LINE_MAX          (2 + MAX_CHAN + 1 + C_MODES_MAX + 1 + C_SETTINGS_MAX + 24)
#define D_LINE_MAX          (2 + C_MODES_MAX + 1 + D_SETTINGS_MAX + 24)
#define B_LINE_MAX          (2 + MAX_CHAN + 1 + BAN_MASK_MAX + 1 + 24 + 8 + \
                             BAN_SETTER_MAX + 1 + BAN_REASON_MAX + 40)
#define CFG_MAX_BANS        (MAX_GLOBAL_BANS + CFG_MAX_CHANNELS * MAX_BANS_PER_CHAN)
#define MAX_CONFIG_PAYLOAD \
  ( CFG_MAX_GLOBALS     * CFG_GLOBAL_LINE_MAX + \
    CFG_MAX_CHANNELS    * C_LINE_MAX          + \
    D_LINE_MAX                                + \
    CFG_MAX_BANS        * B_LINE_MAX          + \
    MAX_USER_RECORDS    * CFG_USER_LINE_MAX   + \
    MAX_USER_MASKS      * CFG_MASK_LINE_MAX   + \
    MAX_USER_FLAGS      * CFG_UF_LINE_MAX     + \
    MAX_CHAN_BINDS      * CFG_UC_LINE_MAX     + \
    CFG_BOT_SYNC_FIELDS * CFG_BOT_FIELD_LINE  + \
    MAX_TRUSTED_BOTS    * CFG_BLINE_MAX       + \
    CFG_PAYLOAD_SLACK )
/* Largest inbound hub frame = envelope(5) + payload + GCM tag, plus margin. */
#define MAX_HUB_FRAME (MAX_CONFIG_PAYLOAD + 64)
/* Members tracked per channel (heap, inside chan_t: ~270 bytes each).  Every
 * protection acts only on tracked members, so a channel larger than this
 * fails closed for the members beyond it (modes.md §12.1). */
#define MAX_ROSTER_SIZE 500
#define MAX_SEEN_HASHES                                                        \
  4096 // Stores admin request hashes to protect against anti-replay attacks
#define NONCE_CACHE_SIZE                                                       \
  4096 // Nonce cache for secure communication. Prevents replay attacks
#define NONCE_TTL_SECONDS 60 // Entries older than this are treated as empty
typedef struct { uint64_t nonce; time_t ts; } nonce_entry_t;
/* Config-write debounce.  auth_mark_used() bumps last_seen/last_used on every
 * successful admin auth, which would otherwise mean a full config rewrite --
 * including a PBKDF2 key derivation -- per admin command.  The main loop
 * flushes at most once every CONFIG_WRITE_DEBOUNCE_S seconds instead.
 * Mirrors irchub's hub.h:564 / hub_main.c:435. */
#define CONFIG_WRITE_DEBOUNCE_S 5

/* Passwordless admin/oper and bot-to-bot transport (irchub/docs/passwordless.md).
 * The labels are domain separators baked into signatures, KDF info and GCM
 * AAD.  They are shared with the client scripts in utils/ and irchub; change
 * one only by bumping its -vN suffix everywhere. */
#define A2A_LABEL "ircbot-A2A-v1"  /* ~A2A auth request (Ed25519 signature) */
#define A2K_LABEL "ircbot-A2K-v1"  /* ~A2K lockbox: bot pubkey sealed to the user */
#define A2_LABEL  "ircbot-A2-v1"   /* ~A2  sealed admin/oper command */
#define A2S_LABEL "ircbot-A2S-v1"  /* ~A2S the same, asking for sealed replies */
#define A2R_LABEL "ircbot-A2R-v1"  /* ~A2R sealed reply to a ~A2S command */
#define B2_LABEL  "ircbot-B2-v1"   /* ~B2  sealed bot-to-bot command */
#define A2_TS_SKEW 30              /* +/- seconds accepted on ~A2A / ~A2 */
#define B2_TS_SKEW 60              /* +/- seconds accepted on ~B2 */
#define A2_AUTH_REPLY_MIN_INTERVAL 3    /* per user: seconds between lockboxes */
#define A2_AUTH_REPLY_GLOBAL_INTERVAL 1 /* all users: seconds between lockboxes */
#define SEAL_OVERHEAD (32 + 12 + 16)    /* eph_pub || iv(GCM_IV_LEN) || .. || tag */
#define SEAL_MAX_PLAINTEXT 1024         /* bound on any ~A2 / ~B2 plaintext */
#define KEY_FP_LEN 19                   /* "ab12:cd34:ef56:7890" */
#define A2_NICK_MAX 64                  /* longest nick a ~A2 context accepts */
/* Base64 of a maximal sealed frame, and the longest "~A2S <b64>" line. */
#define A2_B64_MAX (4 * ((SEAL_MAX_PLAINTEXT + SEAL_OVERHEAD + 2) / 3))
#define A2_LINE_MAX (5 + A2_B64_MAX)
/* ~A2R reply frame: iv(12) || ct || tag(16), plaintext "<seq>:<more>:<text>".
 * A reply line longer than A2R_TEXT_MAX bytes goes out as several frames
 * (more = 1 on all but the last) so that "~A2R <b64>" stays inside the ~400
 * chars an IRC line leaves after a worst-case prefix (passwordless.md §4.7). */
#define A2R_OVERHEAD (12 + 16)
#define A2R_TEXT_MAX 240
#define A2R_PT_MAX (A2R_TEXT_MAX + 24)   /* + "<seq>:<more>:" */

/* DCC CHAT (dcc.c).  Outbound only: the bot never listens.  The admin command
 * `dcc` answers with a passive offer, the admin's client opens a port from its
 * own DCC range and replies with it, and the bot connects out.  Every line on
 * the chat must still be a sealed ~A2 frame from the user who asked. */
#define DCC_MAX_SESSIONS 4        /* offered + connecting + open, all users */
#define DCC_OFFER_TIMEOUT 120     /* s for the client to answer the offer */
#define DCC_CONNECT_TIMEOUT 20    /* s for the outbound TCP connect */
#define DCC_IDLE_TIMEOUT 3600     /* s without a command before the chat closes */
#define DCC_MIN_PORT 1024         /* never connect to a privileged port */
#define DCC_OUTBUF_MAX (512 * 1024) /* unsent reply bytes before the chat is dropped */
/* Protocol version this bot advertises to the hub as "v|N|<ts>".  A hub sends
 * the new a|/o|/b| record shapes only to bots at >= 2; older bots get records
 * with an empty password slot so they refuse admin commands (fail closed).
 * 3 = knows admin flags / oper channel bindings (uf| / uc|): below that the
 * hub never sends a restricted user (user_flags plan §3.2). */
#define BOT_PROTO_VERSION 3

#define GCM_IV_LEN 12 // 12 bytes (96 bits) is industry standard. Do not change
#define GCM_TAG_LEN                                                            \
  16 // 16 bytes (128 bits) is industry standard. Do not change
#define NUM_LOG_LEVELS 6     // For L_MSG, L_CTCP, L_INFO, L_CMD, L_RAW, L_DEBUG
#define LOG_BUFFER_LINES 50  // Store the last 50 log lines for each log level
#define MAX_LOG_LINE_LEN 256 // Max length of a single log line
#define DEFAULT_LOG_LINES                                                      \
  10 // Default number of getlog lines to display to admin when requested if not
     // provided
#define MAX_LOG_LINES                                                          \
  20 // Max number of lines to cap getlog request to help prevent flooding
#define BOT_STATUS_MAX_LINES 30 // Max trusted-bot lines in status output (anti-flood)
/* Keepalive traffic (IRC PING/PONG and the hub's CMD_PING) is pure noise in
 * the RAW log: at one exchange every 30-60s it buries the lines that matter.
 * true  = never log it; false = log it like any other line.  Only the logging
 * is suppressed -- the keepalives themselves still run. */
#define HIDEPINGPONG true
#define MAX_IRC_CHANNELS 10     // Realistic per-bot IRC channel ceiling (server CHANLIMIT)
#define OP_REQUEST_MIN_INTERVAL 5 // Minimum seconds between any OP-REQ sent by this bot
#define MAX_CONFIG_SIZE                                                        \
  (1024 * 1024) // Limit config file size to 1MB to provent OOM
#define MAX_HUB_KEY_SIZE  128  // 88 chars base64 + null + headroom (Curve25519)
#define HUB_KEY_RAW_LEN   64  // 32-byte Ed25519 + 32-byte X25519
#define COMBINED_KEY_B64  88  // base64 of 64-byte combined key
#define MAX_OPT_FLAGS     32  // characters in opt| string (alnum letters)

/* Network-controlled options synced from hub via the 'opt|' record.
 * Each option is a single letter [a-zA-Z0-9].  See is_opt_set() helper. */
#define OPT_HUB_ONLY_MUTATIONS 'h'   // refuse local mutations of hub-authoritative records

#define CMD_PING 0x01
#define CMD_CONFIG_PUSH 0x02
#define CMD_CONFIG_PULL 0x03
#define CMD_CONFIG_DATA 0x04
#define CMD_UPDATE_PUBKEY 0x05
#define CMD_PEER_SYNC 0x06
#define CMD_MESH_STATE 0x07
#define CMD_INVITE_REQUEST 0x09 // Bot -> Hub: Request invite for nick into channel

#define CMD_ADMIN_AUTH 0x10
#define CMD_ADMIN_LIST_FULL 0x11
#define CMD_ADMIN_ADD 0x12 // RETIRED (bot authorize); never reuse
#define CMD_ADMIN_DEL 0x13
#define CMD_ADMIN_REGEN_KEYS 0x14
#define CMD_ADMIN_LIST_SUMMARY 0x15
#define CMD_ADMIN_GET_PENDING 0x16 // RETIRED (bot pending)
#define CMD_ADMIN_APPROVE 0x17 // RETIRED (bot approve)
#define CMD_ADMIN_ADD_PEER 0x18
#define CMD_ADMIN_LIST_PEERS 0x19
#define CMD_ADMIN_DEL_PEER 0x1A
#define CMD_ADMIN_GET_PUBKEY 0x1B
#define CMD_ADMIN_SET_PRIVKEY 0x1C
#define CMD_ADMIN_GET_PRIVKEY 0x1D
#define CMD_ADMIN_SET_PUBKEY 0x1E
#define CMD_ADMIN_SYNC_MESH 0x1F
#define CMD_ADMIN_CREATE_BOT 0x32     // 50 decimal
#define CMD_ADMIN_REKEY_BOT 0x20      // Generate new bot keypair
#define CMD_ADMIN_DISCONNECT_BOT 0x21 // Force disconnect bot
#define CMD_ADMIN_BOT_STATUS 0x22     // Get bot connection info
#define CMD_BOT_KEY_UPDATE 0x40       // Hub -> Bot: New private key update
#define CMD_BOT_DELTA      0x45       // Bot -> Hub: single-key delta (mesh.md Phase 4)

// Named Admin/Oper/Usermask Commands (v2) — must match hub.h
#define CMD_ADMIN_ADD_ADMIN      0x46
#define CMD_ADMIN_DEL_ADMIN      0x47
#define CMD_ADMIN_ADD_OPER_RECORD 0x48
#define CMD_ADMIN_DEL_OPER_RECORD 0x49
#define CMD_ADMIN_ADD_USERMASK   0x4A
#define CMD_ADMIN_DEL_USERMASK   0x4B
/* 0x4C was CMD_ADMIN_SET_USERPASS — retired (passwordless), never reuse. */
#define CMD_ADMIN_SET_USERKEY    0x55   /* payload: name|pubkey_b64 */
#define CMD_ADMIN_MATCH          0x4D
#define CMD_ADMIN_LIST_ADMINS    0x4E
#define CMD_ADMIN_LIST_OPERS_V2  0x4F

// Global Config Management Commands
#define CMD_ADMIN_LIST_CHANNELS 0x23  // List all channels
#define CMD_ADMIN_ADD_CHANNEL 0x24    // Add channel
#define CMD_ADMIN_DEL_CHANNEL 0x25    // Remove channel
#define CMD_ADMIN_LIST_MASKS 0x26     // List admin masks
#define CMD_ADMIN_ADD_MASK 0x27       // Add admin mask
#define CMD_ADMIN_DEL_MASK 0x2B       // Remove admin mask
#define CMD_ADMIN_LIST_OPERS 0x2C     // List oper masks
#define CMD_ADMIN_ADD_OPER 0x2D       // Add oper mask
#define CMD_ADMIN_DEL_OPER 0x2E       // Remove oper mask
/* 0x2F (SET_ADMIN_PASS) and 0x30 (SET_BOT_PASS) are retired — passwordless;
 * never reuse them. */
#define CMD_ADMIN_OP_USER 0x31        // Op a user in a channel

// Bot-to-Bot Op Commands (via Hub)
#define CMD_OP_REQUEST 0x28 // Bot -> Hub: Request ops from another bot
#define CMD_OP_GRANT 0x29   // Hub -> Bot: Grant ops to requesting bot
#define CMD_OP_FAILED 0x2A  // Hub -> Bot: Op request failed

// Bot-to-Bot Relay Commands (via Hub)
#define CMD_BOT_RELAY 0x50  // Bot -> Hub: relay encrypted bot command to target bot by UUID
#define CMD_BOT_MSG   0x51  // Hub -> Bot: relayed encrypted bot command payload

/* ---- Bot presence (the 'bots' tree) -- mirrors irchub/hub.h ---------------
 * Volatile by design: version / IRC server / uptime never enter the config on
 * either side.  We report ours with CMD_BOT_PRESENCE; the hub gossips its own
 * bots to its peers and pushes the assembled tree back with CMD_BOT_TREE.  The
 * cache below is display-only and is never consulted for trust -- the b|
 * trusted-bot records remain the sole authority for that. */
#define CMD_BOT_PRESENCE 0x56  // Bot -> Hub: version|server|started|variant
#define CMD_BOT_TREE     0x58  // Hub -> Bot: rendered tree rows

/* ---- Channel-access requests (unban / invite / key) ----------------------
 * A bot locked out of a managed channel -- 474 banned, 473 invite-only, 475
 * bad key -- asks the mesh to let it back in.  Hub-side the request routes
 * exactly like CMD_OP_REQUEST: the hub stamps a request id, broadcasts the
 * action to its own bots, forwards it to its peers under the same id (dropped
 * on the second sighting), and routes any reply back down the fd the request
 * arrived on.  With no hub reachable the bot falls back to a sealed ~B2
 * PRIVMSG to one trusted bot at a time -- see bot_comms.c.
 *
 * The requester never supplies its own hostmask or nick: the hub fills both in
 * from the authenticated bot's own `h` and `n` records, so a bot cannot ask
 * for an unban of a mask that is not its own, nor have a third party invited.
 * Only `key` produces a reply.  Mirrors irchub/hub.h. */
#define CMD_CHAN_REQUEST 0x59 // Bot -> Hub: kind|channel
#define CMD_CHAN_ACTION  0x5A // Hub -> Bot: id|kind|chan|uuid|nick|hostmask
#define CMD_CHAN_REPLY   0x5B // Bot <-> Hub: id|kind|chan|status|data

/* Channel-request election (irchub docs/plans/2026-10-07_chan_election_plan.md).
 * The hub asks whether we could do a channel request right now (PROBE; we
 * answer at once from our own state), then hands it to ONE bot that said yes
 * (DO), which reports back (DONE).  A hub that predates this never sends
 * PROBE and keeps using CMD_OP_GRANT / CMD_CHAN_ACTION.  Mirrors irchub/hub.h.
 *   PROBE      hub->bot  eid|kind|channel
 *   PROBE_ACK  bot->hub  eid|1| or eid|0|reason
 *   DO         hub->bot  eid|kind|channel|requester|nick|hostmask
 *   DONE       bot->hub  eid|ok|detail or eid|fail|detail
 * kind = op / invite / unban / key. */
#define CMD_CHAN_PROBE     0x6D
#define CMD_CHAN_PROBE_ACK 0x6E
#define CMD_CHAN_DO        0x6F
#define CMD_CHAN_DONE      0x70
#define CHAN_DO_NICK_MAX   30   /* a nick the hub hands us, any network     */

/* ---- Network-wide upgrade coordination (console-initiated rolling upgrade).
 * The bot answers PREPARE with READY/UNABLE, runs the updater on COMMIT (the
 * standalone in-place 'update' gate does NOT block this hub path), rolls back
 * to <exe>.prev on ABORT, and reports RESULT after it restarts.  Mirrors
 * irchub/hub.h. */
#define CMD_UPGRADE_PREPARE 0x5E // Hub -> Bot: id|ver|variant|kind|min_from|base
#define CMD_UPGRADE_READY   0x5F // Bot -> Hub: id|uuid|cur|variant|arch|libc|ok|reason
#define CMD_UPGRADE_COMMIT  0x60 // Hub -> Bot: id|ver|variant
#define CMD_UPGRADE_RESULT  0x61 // Bot -> Hub: id|uuid|status|new_ver|detail
#define CMD_UPGRADE_ABORT   0x62 // Hub -> Bot: id|reason

/* ---- Activity (last seen / last used).  Mirrors irchub/hub.h.
 * last_seen / last_used are max-merged outside LWW.  auth_mark_used() stores
 * the exact time and, on a record's first use within an ACTIVITY_BUCKET (a
 * clock hour), reports that time to the hub as CMD_ACTIVITY; with no hub
 * link the latest such time waits per record and goes out after the next hub
 * authentication.  admins / opers / match ask the hub for the network-wide
 * times (CMD_ACTIVITY_QUERY), park the command for up to
 * ACTIVITY_QUERY_TIMEOUT seconds, and show max(hub, local) per row; with no
 * hub or no answer they show the local times.  A listed, non-sticky ban's
 * last use (an unauthorised member matched it in the ban sweep) is stamped
 * and reported the same way by chancfg_ban_mark_used(); bots keep it in
 * memory only, the hub stores it (console `ban list` LAST USED).
 *   CMD_ACTIVITY        a|<user_uuid>|<ts>  /  m|<user_uuid>|<mask>|<ts>
 *                       B|<#chan|*>|<mask>|<ts>
 *   CMD_ACTIVITY_QUERY  <req_id>|users  /  <req_id>|masks|<user_uuid or *>
 *   CMD_ACTIVITY_REPLY  <req_id>|<more>, then a|/m| lines; more=0 last */
#define CMD_ACTIVITY       0x69 // Bot -> Hub
#define CMD_ACTIVITY_QUERY 0x6A // Bot -> Hub
#define CMD_ACTIVITY_REPLY 0x6B // Hub -> Bot
#define ACTIVITY_BUCKET        3600
#define ACTIVITY_MAX_FUTURE    300  /* hub times further ahead are refused */
#define ACTIVITY_QUERY_TIMEOUT 3
#define MAX_ACTIVITY_QUERIES   4
#define ACTIVITY_REQ_ID_MAX    32

/* ---- Channel modes / settings / bans / floods (irchub docs/modes.md).
 * The 0x76-0x7A ops are console->hub only; a bot never sends or handles them
 * and they are defined here so the numbers stay reserved on both sides.
 * CMD_CHAN_EVENT is the one bot-originated frame: one enforcement action
 * (D42), `#chan|<action>|<target>|<detail>`, rate-limited by the bot
 * (hub_client_chan_event) and logged by the hub.  Mirrors irchub/hub.h. */
#define CMD_ADMIN_CHAN_MODE 0x76 // console -> hub: channel mode
#define CMD_ADMIN_CHAN_SET  0x77 // console -> hub: channel set
#define CMD_ADMIN_BAN       0x78 // console -> hub: ban list / add / del
#define CMD_ADMIN_NET_SET   0x79 // console -> hub: network set
#define CMD_ADMIN_SET_SSH   0x7A // console -> hub: hub set ssh / conn
#define CMD_CHAN_EVENT      0x7B // bot -> hub: #chan|action|target|detail
#define CMD_ADMIN_USER_ACCESS 0x7C // console -> hub only (reserved here)
/* A person's channel request (irchub user_flags plan §5): when this bot
 * cannot op / invite / unban an admin or oper itself it asks the hub, which
 * re-checks the user and runs the channel-request election.
 *   CMD_USER_CHAN_REQUEST bot->hub  rid|kind|#chan|user_uuid|nick|nick!user@host
 *   CMD_USER_CHAN_RESULT  hub->bot  rid|ok|detail  or  rid|fail|detail
 * No answer within USER_CHAN_REPLY_WAIT (an older hub ignores the frame) and
 * the bot asks its trusted bots directly over ~B2 instead.  Mirrors
 * irchub/hub.h. */
#define CMD_USER_CHAN_REQUEST 0x7D
#define CMD_USER_CHAN_RESULT  0x7E
/* Revoked bots (irchub docs/plans/2026-10-17_bot_revoke_plan.md).  A bot
 * deleted on the hub is told to wipe its config and exit:
 *   CMD_BOT_RETIRE      hub->bot  empty; a sealed frame in session, or the
 *                                 handshake's 1-byte sealed ACK is 0x7F
 *   CMD_BOT_RETIRE_ACK  bot->hub  "1" config wiped, "0" wipe failed
 * Mirrors irchub/hub.h (0x81 CMD_ADMIN_LIST_REVOKED is console->hub only). */
#define CMD_BOT_RETIRE        0x7F
#define CMD_BOT_RETIRE_ACK    0x80
#define CMD_ADMIN_LIST_REVOKED 0x81
#define USER_CHAN_RID_MAX     32
#define USER_CHAN_PENDING     8
#define USER_CHAN_REPLY_WAIT  45  /* s: the hub's CHAN_ELECT_TTL (40) + margin */
#define CHAN_EVENT_TARGET_MAX   120
#define CHAN_EVENT_DETAIL_MAX   160
#define CHAN_EVENT_DEDUPE_SECS   10  /* per (chan, action, target) */
#define CHAN_EVENT_WINDOW_SECS   60  /* total-rate window */
#define CHAN_EVENT_WINDOW_MAX    20  /* events per window */
#define CHAN_EVENT_TRACK         32  /* dedupe slots (oldest replaced) */

/* Wire tokens for the `kind` field, and the bot-side index that tracks one
 * in-flight request per kind per channel. */
#define CHAN_REQ_TOK_UNBAN  "unban"
#define CHAN_REQ_TOK_INVITE "invite"
#define CHAN_REQ_TOK_KEY    "key"

typedef enum {
  CHAN_REQ_UNBAN = 0,
  CHAN_REQ_INVITE,
  CHAN_REQ_KEY,
  CHAN_REQ_KIND_COUNT
} chan_req_kind_t;

#define CHAN_REQUEST_MIN_INTERVAL 5  // Seconds between any two requests we send
#define CHAN_REQUEST_RETRY_TIME  60  // Before re-asking for the same chan+kind
#define CHAN_REQUEST_MAX_RETRIES  5  // Then back off until CHAN_REQUEST_COOLOFF
#define CHAN_REQUEST_COOLOFF    300  // Idle time that clears the retry count
/* How long after asking we will still adopt a key someone sends us.  Mirrors
 * the hub's CHAN_REQUEST_TIMEOUT, which reaps the pending slot at the same
 * age, so a reply the hub would no longer route is one we no longer accept. */
#define CHAN_REPLY_ACCEPT_WINDOW 45

/* Servicing an unban means asking the server for the ban list and matching it
 * ourselves, so a job outlives the request frame until 368 closes the list. */
#define MAX_UNBAN_JOBS        8
#define UNBAN_JOB_TTL        30  // Give up on a ban list that never arrives
#define UNBAN_MAX_REMOVALS    6  // Per job -- never blanket-clear a ban list

extern volatile bool g_shutdown_flag;

// Enums
typedef enum {
  S_NONE = 0,
  S_CONNECTED = 1 << 0,
  S_AUTHED = 1 << 1,
  S_DIE = 1 << 2
} bot_status_t;
typedef enum {
  L_NONE = 0,
  L_MSG = 1,
  L_CTCP = 2,
  L_INFO = 4,
  L_CMD = 8,
  L_RAW = 16,
  L_DEBUG = 32
} log_type_t;

typedef enum {
  HUB_AUTH_NONE,
  HUB_AUTH_SENT_UUID,
  HUB_AUTH_SENT_SIGNATURE,
  HUB_AUTH_COMPLETE
} hub_auth_state_t;

typedef enum { C_NONE = 0, C_OUT = 1 << 0, C_IN = 1 << 1 } chan_status_t;
typedef enum { M_NONE = 0, M_K = 64, M_I = 128 } chan_mode_t;
typedef enum { LS_NONE = 0, LS_LISTEN = 1, LS_CONNECTED = 2 } listen_status_t;

// Struct Forward Declarations
typedef struct bot_state bot_state_t;
typedef struct chan_t chan_t;


typedef struct {
  char   uuid[37];
  char   name[64];
  /* Per-user Curve25519 combined pubkey (Ed25519 + X25519), base64-encoded
   * (88 chars + NUL) — the user's only credential: ~A2A signatures verify
   * against the Ed25519 half, ~A2 commands open with the X25519 half.  Empty
   * (has_pubkey false) for a legacy record that has not been given a key yet;
   * such a user can authenticate nowhere. */
  char   pubkey_b64[COMBINED_KEY_B64 + 1];
  bool   has_pubkey;
  char   type;         /* 'a' = admin, 'o' = oper */
  bool   is_active;    /* false when action == "del" */
  time_t last_seen;
  time_t timestamp;
  time_t last_auth_reply; /* runtime only: ~A2K rate limit, never persisted */
  time_t act_pending;     /* runtime only: CMD_ACTIVITY time not yet sent */
} user_record_t;

/* Parsed a|/o| line body (config file, hub sync, bot push).  legacy is true
 * when the line carried a password in field 3 — it has already been wiped. */
typedef struct {
  char   uuid[37];
  char   name[64];
  char   pubkey_b64[COMBINED_KEY_B64 + 1];
  bool   has_pubkey;
  bool   is_active;
  bool   legacy;
  time_t last_seen;
  time_t timestamp;
} user_line_t;

/* One trusted peer bot (b| line).  pub is the peer's combined Curve25519 key
 * (Ed25519 || X25519) used for ~B2; has_pub is false for entries that arrived
 * without one (a pre-passwordless hub, or a bare hand-typed mask). */
typedef struct {
  char   mask[MAX_MASK_LEN];
  char   uuid[37];
  unsigned char pub[HUB_KEY_RAW_LEN];
  bool   has_pub;
  time_t ts;
} trusted_bot_t;

typedef struct {
  char   uuid[37];     /* matches user_record_t.uuid */
  char   mask[MAX_MASK_LEN];
  bool   is_active;    /* false when action == "del" */
  time_t last_used;    /* 0 = never used */
  time_t timestamp;
  time_t act_pending;  /* runtime only: CMD_ACTIVITY time not yet sent */
} mask_record_t;

/* A person's channel request this bot sent the hub (CMD_USER_CHAN_REQUEST),
 * waiting for its CMD_USER_CHAN_RESULT; rid[0] == 0 = free slot. */
typedef struct {
  char   rid[USER_CHAN_RID_MAX + 1];
  char   kind[8];
  char   chan[MAX_CHAN];
  char   nick[MAX_MEMBER_NICK];
  char   mask[MAX_MASK_LEN];
  time_t sent;
} user_chan_pending_t;

/* Admin flags, uf|<user_uuid>|<flags>|<ts> (irchub hub_uflag_record_t). */
typedef struct {
  char   uuid[37];
  char   flags[USER_FLAGS_MAX + 1];
  time_t timestamp;
} uflag_record_t;

/* Oper channel binding, uc|<user_uuid>|<#chan|*>|add/del|<ts>
 * (irchub hub_uchan_record_t). */
typedef struct {
  char   uuid[37];
  char   chan[MAX_CHAN];
  bool   is_active;
  time_t timestamp;
} uchan_record_t;

typedef struct {
  char nick[MAX_MEMBER_NICK];
  char hostmask[MAX_MASK_LEN];
  bool is_op;
  bool is_halfop;  /* PREFIX 'h' (D41); false on a server without it */
  bool is_voice;
  /* chanenf.c: cached "authorised" verdict for hostmask, valid while
   * auth_gen equals state->auth_gen (0 = never computed). */
  bool authorised;
  unsigned auth_gen;
} roster_entry_t;

typedef struct {
  char line[MAX_LOG_LINE_LEN];
} log_entry_t;

typedef struct {
  log_entry_t entries[LOG_BUFFER_LINES];
  int log_idx;
} log_buffer_t;

typedef struct {
  char *buffer;
  size_t size;
} http_response_t;

/* ---- modes.md: settings, live modes, ban lists ------------------------- */

/* Settings that live in a C| / D| `settings` field as name=value.  The first
 * ten are flags (0/1), the rest numbers with the ranges in chancfg.c.
 * CS_IGNORETIME is network-only (D|). */
typedef enum {
  CS_ENFORCEMODES = 0, CS_BITCH, CS_PROTECTOPS, CS_REVENGE, CS_STOPNETHACK,
  CS_ENFORCEBANS, CS_DYNAMICBANS, CS_DONTKICKOPS, CS_CYCLE, CS_DYNAMICLIMIT,
  CS_BANTIME, CS_BANTYPE, CS_BANIDLE, CS_LIMITGAP, CS_LIMITDELAY,
  CS_IGNORETIME, CS_COUNT
} cset_id_t;

/* Flood settings: the seven channel types (`flood <type>`), then the three
 * bot floods (`bflood cmd|msg|ctcp`, D| only), then `sendq` (D| only; n =
 * burst 1..100, s = interval ms 0..10000, never `off`). */
typedef enum {
  FL_CHAN = 0, FL_CTCP, FL_JOIN, FL_NICK, FL_DEOP, FL_KICK, FL_BAN,
  FL_BOT_CMD, FL_BOT_MSG, FL_BOT_CTCP, FL_SENDQ, FL_COUNT
} flood_kind_t;
#define FL_CHAN_COUNT 7  /* FL_CHAN..FL_BAN are per-channel */

typedef struct {
  bool present;  /* an override is set */
  bool off;      /* `off` */
  int  n, s;     /* more than n events in s seconds trips it */
} flood_spec_t;

/* A parsed settings field: only the overrides it names. */
typedef struct {
  unsigned present;            /* bit per cset_id_t */
  long     val[CS_COUNT];
  flood_spec_t fl[FL_COUNT];
  bool     bad_sendq;          /* a sendq=... token was present but invalid */
} chan_settings_t;

/* ---- chanflood.c / botflood.c: flood counters (modes.md §8, §9.1) ------- */
#define MAX_FLOOD_TRACK  64   /* sources tracked per channel, oldest replaced */
#define MAX_IGNORES      64   /* bot ignore table (runtime only) */
#define MAX_HOST_TRACK   64   /* hosts tracked for the bot msg / ctcp floods */
#define FLOOD_HOST_MAX   128  /* a tracked host (cut, lower-cased) */
#define IGNORE_KEY_MAX   (FLOOD_HOST_MAX + 4) /* host, or "u:<uuid>" */
#define QUIET_FILL_MS    60000 /* a table full within this -> quiet mode */

/* One counting window: the first event opens it, more than n events before
 * s seconds have passed from its start trips it.  Checked on arrival only. */
typedef struct {
  long long start_ms;   /* monotonic; 0 = no window open */
  int       count;
} flood_window_t;

/* One source host in one channel: a window per channel flood type. */
typedef struct {
  char           host[FLOOD_HOST_MAX]; /* lower-cased; "" = free slot */
  long long      last_ms;              /* last counted event (oldest = out) */
  flood_window_t w[FL_CHAN_COUNT];
  uint8_t        victim_auth;          /* bit per kind: a victim was authorised */
} flood_src_t;

typedef struct {
  char      key[IGNORE_KEY_MAX]; /* "" = free */
  long long since_ms, until_ms;
} ignore_ent_t;

typedef struct {
  char           host[FLOOD_HOST_MAX]; /* "" = free */
  long long      last_ms;
  flood_window_t msg, ctcp;
} host_flood_t;

typedef struct {
  char           uuid[37];             /* "" = free */
  long long      last_ms;
  flood_window_t w;
  bool           notified;             /* the "slow down" notice went out */
} cmd_flood_t;

/* One server-side ban in a channel's ban list (367 + MODE +b/-b). */
typedef struct {
  char  *mask;                 /* heap, NUL-terminated */
  char   setter[MAX_MEMBER_NICK + 32]; /* setter as the server printed it, cut */
  time_t when;                 /* server's ts, 0 if unknown */
} live_ban_t;

/* One B| record (a network ban).  chan "*" = every managed channel. */
typedef struct {
  char   chan[MAX_CHAN];
  char   mask[BAN_MASK_MAX + 1];
  char   flags[8];             /* "s" sticky, "" none */
  char   setter[BAN_SETTER_MAX + 1];
  char   reason[BAN_REASON_MAX + 1];
  time_t expires;              /* absolute unix time, 0 = permanent */
  time_t ts;
  bool   active;               /* false = tombstone (op "del") */
  bool   push_pending;         /* bot-written, not yet pushed to a hub */
  time_t last_used;            /* runtime only: last unauthorised match */
  time_t act_pending;          /* runtime only: CMD_ACTIVITY time not yet sent */
} cfg_ban_t;

/* 005 (RPL_ISUPPORT) values this bot uses; reset on every disconnect. */
#define ISUPPORT_MODES_DEFAULT 3
#define ISUPPORT_MODES_MAX     12
#define NICKLEN_DEFAULT        30
#define MAXLIST_DEFAULT        100
#define BAN_LIST_CAP           200   /* our own ceiling on a stored list */
typedef struct {
  int  modes;                  /* MODES=: changes per MODE line */
  int  maxlist_b;              /* MAXLIST for 'b' (or MAXBANS), 0 = unknown */
  char prefix_modes[9];        /* PREFIX=(ohv)@%+ -> "ohv" */
  char prefix_syms[9];         /*                    "@%+" */
  int  nicklen;                /* NICKLEN=, default 30 */
  char cm_a[64], cm_b[64], cm_c[64], cm_d[64]; /* CHANMODES=A,B,C,D */
} isupport_t;

/* Output send queue (sendq.c): three lanes, drained by pacing. */
#define MAX_SENDQ        256   /* lines held, all lanes together */
#define SENDQ_LANES      3
#define SENDQ_LANE_PROTO 0     /* PONG, registration */
#define SENDQ_LANE_PROT  1     /* MODE / KICK */
#define SENDQ_LANE_REST  2     /* everything else (dropped first) */
#define SENDQ_DEF_BURST  10    /* lines sent back to back (D| sendq B) */
#define SENDQ_DEF_INTERVAL_MS 100 /* then one line per this (D| sendq I) */
#define SENDQ_MIN_BURST  1
#define SENDQ_MAX_BURST  100
#define SENDQ_MIN_INTERVAL_MS 0     /* 0 = unpaced */
#define SENDQ_MAX_INTERVAL_MS 10000
#define SENDQ_LINE_MAX   510   /* IRC line body; CR LF is added after */
typedef struct {
  char *q[SENDQ_LANES][MAX_SENDQ]; /* ring per lane, heap lines w/ CRLF */
  int   head[SENDQ_LANES];
  int   count[SENDQ_LANES];
  int   total;
  int   burst;                 /* live D| sendq burst (lines) */
  int   interval_ms;           /* live D| sendq interval; 0 = unpaced */
  long long credit_ms;         /* send credit, capped at burst * interval */
  long long last_ms;           /* monotonic ms of the last refill */
  unsigned long dropped;       /* lines dropped because the queue was full */
  int   hold;                  /* sendq_hold depth: >0 queues without draining */
} sendq_t;

/* Rate-limit memory for CMD_CHAN_EVENT (hub_client_chan_event). */
typedef struct {
  char   key[MAX_CHAN + 16 + CHAN_EVENT_TARGET_MAX + 4];
  time_t when;
} chan_event_seen_t;
typedef struct {
  chan_event_seen_t seen[CHAN_EVENT_TRACK];
  time_t window[CHAN_EVENT_WINDOW_MAX]; /* send times, ring */
  int    widx;
  unsigned suppressed;         /* dropped since the last summary */
  char   sup_chan[MAX_CHAN];   /* channel of the latest suppressed event */
  char   sup_action[16];
} chan_event_lim_t;

/* ---- chanenf.c: in-channel elections and set-option enforcement ------- */
#define JOB_KICK   0   /* the five jobs, in deal order (modes.md §7.1) */
#define JOB_BAN    1
#define JOB_OP     2
#define JOB_MODE   3
#define JOB_LIMIT  4
#define JOB_COUNT  5
#define JOB_STEP_MS        1500   /* backup delay = backup index x this */
#define MAX_PENDING_JOBS   32
#define JOB_MIN_VERSION    "2.4.7" /* older bots are left out of the deal */
#define JOB_MAX_AGE_MS     30000   /* a pending job older than this is dropped */
#define ENF_SWEEP_SECS     5       /* per-channel state sweep when nothing happened */
/* Idle clocks (ban_track, heap): one per channel x listed ban, so a network
 * ban on "*" costs one per channel.  The ceiling covers every channel's own
 * bans plus every global ban in every channel; the table is pruned by
 * minute_sweep and only the oldest-matched clock goes if it is ever full. */
#define MAX_BAN_TRACK      (CFG_MAX_BANS + MAX_GLOBAL_BANS * CFG_MAX_CHANNELS)
#define ENF_RESWEEP_MS     2000    /* a dirty channel is swept at most this often */
#define ENF_KICKS_PER_SWEEP 4      /* kicks queued per channel per ban sweep */
#define MAX_OFFENCES       64
#define ENF_RECENT         32
#define ENF_CYCLE_MIN_SECS 600     /* +cycle: at most one part/rejoin per this */

/* What a pending job does when it falls due (each is re-checked first). */
typedef enum {
  JA_DEOP = 0, JA_DEHALF, JA_REOP, JA_KICK, JA_BAN_NUH, JA_BAN_MASK,
  JA_UNBAN, JA_MODE, JA_LIMIT, JA_COUNT
} job_act_t;

typedef struct {
  bool      used;
  uint8_t   act;                       /* job_act_t */
  char      chan[MAX_CHAN];
  char      target[MAX_MASK_LEN];      /* nick, nick!user@host or ban mask */
  char      reason[BAN_REASON_MAX + 1];
  long long created_ms;                /* monotonic */
} pending_job_t;

/* Idle clock of a listed ban on a channel (+dynamicbans / banidle). */
typedef struct {
  char   chan[MAX_CHAN];
  char   mask[BAN_MASK_MAX + 1];
  time_t last_match;                   /* last time an unauthorised member matched */
  time_t set_at;                       /* when this bot last sent +b for it */
  time_t checked_at;                   /* last §6.2 overlap check (cached 60 s) */
  bool   overlap_ok;                   /* its result */
} ban_track_t;

/* Repeat-offence memory for +revenge and the flood ladder (runtime only). */
typedef struct {
  char   key[MAX_CHAN + 128];          /* lower(chan) '|' lower(host) */
  time_t when;
  unsigned count;
} offence_t;

typedef struct { char key[MAX_CHAN + 8 + MAX_MASK_LEN]; long long when_ms; } enf_recent_t;

struct chan_t {
  char name[MAX_CHAN];
  char key[MAX_KEY];
  chan_status_t status;
  chan_mode_t modes;
  bool is_managed;
  time_t timestamp;
  time_t last_who_request;
  roster_entry_t roster[MAX_ROSTER_SIZE];
  int roster_count;
  time_t last_join_attempt;
  bool join_disabled;  // 405 received: stop retrying this channel this session
  bool i_am_opped;
  bool op_request_pending;
  time_t last_op_request_time;
  int op_request_retry_count;
  /* OP_GRANTs that came in before our own +o (a channel just created, every
   * bot joining at once): granted when the +o lands, dropped after
   * OP_GRANT_HOLD_SECS.  Without it the asker waits out its 60 s timeout. */
  struct {
    char nick[MAX_NICK];
    time_t at;
  } op_grant_held[OP_GRANT_HOLD_MAX];
  int op_grant_held_count;
  /* Channel-access chasing, one slot per chan_req_kind_t: a channel we are
   * both banned from and that is +i is chased on both counts independently. */
  time_t last_access_request[CHAN_REQ_KIND_COUNT];
  int access_retry_count[CHAN_REQ_KIND_COUNT];
  /* C| record (modes.md §2): the stored modes string, the raw settings field
   * (unknown names kept verbatim) and its parse.  Written only by the
   * console; cfg_ts 0 = never seen. */
  char cfg_modes[C_MODES_MAX + 1];
  char cfg_settings[C_SETTINGS_MAX + 1];
  chan_settings_t cfg_set;
  time_t cfg_ts;
  bool cfg_active;
  /* Live state (never persisted, §5.4): modes from 324 + MODE, the ban list
   * from 367 + MODE.  live_flags has a bit per mode letter (chan_live_bit). */
  uint64_t live_flags;
  char   live_key[MAX_KEY];
  long   live_limit;           /* 0 = none */
  bool   live_known;           /* a 324 (or our own MODE echo) was seen */
  time_t live_created;         /* 329 */
  live_ban_t *bans;
  int    ban_count, ban_cap;
  bool   ban_list_open;        /* between the first 367 and the 368 */
  bool   ban_list_known;       /* a full list was received */
  bool   ban_overflow_logged;
  bool   who_done;             /* the channel WHO finished (315) this stay */
  /* A key / mode this bot learned and has not yet got to a hub: pushed in a
   * full config push even under opt 'h' (D43). */
  bool   enf_pending;
  /* chanflood.c: per-source flood windows, heap, MAX_FLOOD_TRACK slots,
   * allocated on the first counted event and freed by channel_live_reset. */
  flood_src_t *flood;
  /* chanenf.c runtime */
  bool   enf_dirty;            /* sweep at the next tick */
  bool   enf_ops_check;        /* gained ops / settings changed: +bitch sweep */
  bool   ban_cap_warned;       /* -dynamicbans overflow warning logged */
  long long enf_last_sweep_ms; /* monotonic */
  time_t enf_last_limit, enf_last_cycle;
  chan_t *next;
};

/* An unban we are servicing for another bot: raised when its CMD_CHAN_ACTION
 * (or ~B2 UNBAN) arrives, closed by 368 or by UNBAN_JOB_TTL.  The mask is the
 * requester's, as the hub resolved it; 367 entries are matched against it and
 * only matching bans come off. */
typedef struct {
  char channel[MAX_CHAN];
  char hostmask[MAX_MASK_LEN];
  time_t started;
  int removed;
  bool active;
} unban_job_t;

/* One row of the bot tree the hub pushed us (CMD_BOT_TREE).  Rows arrive in
 * DFS pre-order and carry their depth, which is all the renderer needs: a node
 * is the last child at its level when no later row shares its depth before a
 * shallower one appears.  Purely for display -- nothing here grants trust. */
#define MAX_BOT_TREE_ROWS  256
/* Deepest row we draw.  A hub hangs every hub further out beneath the hub
 * that links to it, so a chain of N hubs is N levels deep (plus its bots);
 * a deeper row is drawn at this depth rather than dropped. */
#define MAX_TREE_DEPTH     32
#define TREE_VERSION_MAX   15
#define TREE_VARIANT_MAX   7    /* "c" / "rs" -- the code base a node runs */
#define TREE_SERVER_MAX    63
#define TREE_NAME_MAX      64   /* hub friendly name; a nick is far shorter */
/* A tree older than this is shown with a staleness note: the hub refreshes
 * every BOT_TREE_REFRESH (300s) even when nothing changed, so silence past
 * twice that means the hub link, not a quiet network. */
#define BOT_TREE_STALE_AFTER 660
/* How often we re-report presence when nothing changed, so a hub that
 * restarted relearns us without waiting on the bot to do something. */
#define BOT_PRESENCE_REPORT_INTERVAL 120

typedef struct {
  char   kind;                        /* 'h' hub, 'b' bot, 'd' disconnected */
  int    depth;
  char   name[TREE_NAME_MAX];         /* hub name, or the bot's nick        */
  char   uuid[64];
  char   version[TREE_VERSION_MAX + 1];
  char   variant[TREE_VARIANT_MAX + 1]; /* "" when the hub did not say     */
  char   server[TREE_SERVER_MAX + 1];
  time_t uptime;                      /* seconds; last-seen epoch when 'd'  */
  time_t started;                     /* absolute start time, 0 = unknown   */
  bool   has_started;                 /* the hub sent started: the uptime  */
                                      /* is ours to work out                */
  bool   online;
} bot_tree_row_t;

/* One configured hub: its "host:port" address plus the hub's pinned
 * long-term Ed25519 public key (32 raw bytes). Per-hub pinning replaced the
 * old single global hub pubkey: each hub now has its own keypair, so the
 * pinned key must travel with the address it authenticates. Set via
 * '+hub <host:port> <pubkey-b64>' (or the -setup wizard). */
typedef struct {
  char addr[256];               /* "host:port" */
  unsigned char ed_pub[32];     /* hub's pinned Ed25519 public key */
  bool ed_pub_set;
} hub_entry_t;

typedef enum {
  DCC_FREE = 0,    /* slot unused */
  DCC_OFFERED,     /* passive offer sent; waiting for the client's address */
  DCC_CONNECTING,  /* non-blocking connect() to that address in progress */
  DCC_OPEN         /* chat established */
} dcc_phase_t;

/* One DCC chat (dcc.c).  All of it is fixed when the admin asks: the
 * client's reply must come from user_host, and only uuid's key opens a frame
 * on the chat, with nick and botnick as the ~A2 context's nicks -- a nick
 * change on either side during the chat does not break it. */
typedef struct {
  dcc_phase_t phase;
  int fd;                        /* -1 unless CONNECTING or OPEN */
  uint32_t token;                /* passive-DCC id sent in the offer */
  time_t phase_since;            /* when the current phase began */
  time_t last_active;            /* last valid command (OPEN) */
  bool failed;                   /* write error or overflow: close at next check */
  char nick[A2_NICK_MAX];
  char botnick[MAX_NICK];        /* our nick when the chat was offered */
  char user_host[MAX_MASK_LEN];
  char uuid[37];
  char name[64];                 /* the user record's name, for logs */
  char peer[64];                 /* "addr port", for logs and replies */
  char inbuf[A2_LINE_MAX + 2];   /* one partial inbound line */
  size_t inlen;
  char *outbuf;                  /* unsent replies (heap, <= DCC_OUTBUF_MAX) */
  size_t outlen, outcap;
} dcc_session_t;

/* The ~A2R reply context of one ~A2S command (state->a2r). */
typedef struct {
  bool active;
  unsigned char key[32];
  unsigned char aad[A2_NICK_MAX * 2 + 16];
  size_t aad_len;
  char nick[A2_NICK_MAX];
  unsigned long seq;
} a2r_ctx_t;

typedef enum { ACTQ_ADMINS = 0, ACTQ_OPERS, ACTQ_MATCH } actq_kind_t;

/* One admins / opers / match command parked on CMD_ACTIVITY_QUERY, with
 * everything needed to answer it later: the asker, the DCC chat it came in
 * on (slot + token, so a reused slot is not mistaken for it) and a ~A2S
 * command's reply key (wiped as soon as the command is answered). */
typedef struct {
  bool active;
  char id[ACTIVITY_REQ_ID_MAX + 1];
  actq_kind_t kind;
  char arg[64];                  /* match: the name, or "*" */
  char nick[A2_NICK_MAX];
  dcc_session_t *dcc;
  uint32_t dcc_token;
  a2r_ctx_t a2r;
  time_t deadline;
} activity_query_t;

/* Why a server_list[] slot is being skipped (irc_client.c). */
typedef enum {
  SB_NONE = 0,    /* eligible */
  SB_THROTTLED,   /* "reconnecting too fast" / connection limits */
  SB_BANNED,      /* banned, no length stated: escalating backoff */
  SB_BANNED_TEMP, /* banned for a length the server stated */
  SB_BANNED_PERM  /* server said permanent: never retried automatically */
} server_block_kind_t;

#define IRC_REFUSAL_LEN 256 /* stored server refusal text, sanitized */

/* Per-server hold, parallel to server_list[].  Runtime only (not in the
 * config): a restart, +server/-server, or 'jump <server>' clears it. */
typedef struct {
  server_block_kind_t kind;
  time_t until;                 /* not retried before this (0 for PERM) */
  int strikes;                  /* consecutive refusals since the last 001 */
  char reason[IRC_REFUSAL_LEN]; /* what the server said, sanitized */
} server_block_t;

struct bot_state {
  int server_fd;
  int pid_fd;
  char executable_path[PATH_MAX];
  bot_status_t status;
  char current_nick[MAX_NICK];
  char target_nick[MAX_NICK];
  char user[64];
  char gecos[128];
  char vhost[128];
  char *server_list[MAX_SERVERS + 1];
  char actual_server_name[256];
  char actual_hostname[MAX_MASK_LEN];
  time_t actual_hostname_ts;
  time_t current_nick_ts;
  int server_count;
  int current_server_index;
  server_block_t server_blocks[MAX_SERVERS]; // ban/throttle holds, per slot
  int irc_server_idx;          // server_list[] slot of the current/last attempt
  time_t last_irc_attempt;     // enforces IRC_RECONNECT_MIN_INTERVAL
  bool irc_refusal_ban;        // this link got 465 / 463
  char irc_refusal[IRC_REFUSAL_LEN]; // this link's 465/463/ERROR text
  bool irc_blocked_logged;     // "every server refusing" logged this episode
  int nick_generation_attempt;
  time_t bot_start_time;
  time_t connection_time;
  time_t last_pong_time;
  time_t nick_release_time;
  time_t last_nick_attempt;
  /* Runtime only: target nick this server answered with 432 (erroneous).  The
   * server keeps our current nick, so it is not retried until the target
   * changes or the bot reconnects. */
  char nick_refused[MAX_NICK];
  bool pong_pending;
  bool nick_change_pending;
  bool default_server_ignored;
  bool is_ssl;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  log_type_t log_type;
  long log_max_size;  /* LOGFILE cap in bytes (BOT_LOG_FILE_SIZE unless L| set) */
  chan_t *chanlist;
  char ignored_default_channel[MAX_CHAN];
  char ignored_default_mask[MAX_MASK_LEN];
  int ignored_chan_count;
  int chan_count;
  /* startup_password holds the plaintext config-file password for the
   * lifetime of the process (needed on every config write).  It is mlock'd
   * so the OS cannot page it to swap, and OPENSSL_cleanse'd at shutdown.
   *
   * Threat model: mlock prevents swap-file / hibernate leaks.  Root with
   * ptrace or /proc/<pid>/mem CAN still read this while the bot is running —
   * that is unavoidable without hardware-backed key storage.  Real defences
   * are OS-level (ptrace_scope, process isolation, 0600 file permissions). */
  char startup_password[MAX_PASS];
  trusted_bot_t trusted_bots[MAX_TRUSTED_BOTS];
  int trusted_bot_count;
  time_t last_auth_reply_any; // ~A2K global rate limit (runtime only)
  /* A local user/mask change (+admin, -oper, chkey, ...) could not be pushed
   * because the hub link was down.  Pushed right after the next hub
   * authentication — otherwise that connect's config would rebuild the user
   * table and silently undo it (a revoked key coming back).  Persisted as the
   * config line "D|1" so a restart before that push does not drop it. */
  bool admin_delta_pending;
  /* DCC chats (dcc.c).  dcc_reply is set only while a command that arrived
   * over a chat is being dispatched: irc_printf then sends that command's
   * PRIVMSG replies down the chat instead of to the server. */
  dcc_session_t dcc[DCC_MAX_SESSIONS];
  dcc_session_t *dcc_reply;
  /* Set only while a ~A2S command is dispatched: irc_printf then seals that
   * command's replies to the asker into ~A2R frames.  Wiped right after, so
   * the bot keeps no session state (passwordless.md §4.7). */
  a2r_ctx_t a2r;
  /* admins / opers / match waiting on a CMD_ACTIVITY_REPLY (commands.c). */
  activity_query_t activity_queries[MAX_ACTIVITY_QUERIES];
  roster_entry_t channel_roster[MAX_ROSTER_SIZE];
  char who_request_channel[MAX_CHAN];
  nonce_entry_t recent_nonces[NONCE_CACHE_SIZE];
  int nonce_idx;
  nonce_entry_t admin_nonces[MAX_SEEN_HASHES];
  int admin_nonce_idx;
  log_buffer_t in_memory_logs[NUM_LOG_LEVELS];

  // Named admin/oper records and their usermasks (v2)
  user_record_t user_records[MAX_USER_RECORDS];
  int user_record_count;
  mask_record_t mask_records[MAX_USER_MASKS];
  int mask_record_count;
  /* Admin flags (uf|) and oper channel bindings (uc|), access.c */
  uflag_record_t uflag_records[MAX_USER_FLAGS];
  int uflag_record_count;
  uchan_record_t uchan_records[MAX_CHAN_BINDS];
  int uchan_record_count;
  user_chan_pending_t user_chan_pending[USER_CHAN_PENDING];
  bool config_dirty;   // true when last_used/last_seen needs flushing
  time_t last_config_write; // last debounced flush (CONFIG_WRITE_DEBOUNCE_S)

  // Network options (opt| record, hub-pushed)
  char opt_flags[MAX_OPT_FLAGS + 1];
  time_t opt_flags_ts;

  // Hub Management
  char bot_uuid[64];
  char hub_key[MAX_HUB_KEY_SIZE];    // 88-char base64 — used for config serialization only
  unsigned char hub_key_raw[HUB_KEY_RAW_LEN]; // decoded key; mlock'd and cleansed on exit
  /* Public half of the identity key (ed_pub || x_pub), derived from hub_key_raw
   * by bot_self_pub_refresh() on load/wizard/rekey.  ~A2 and ~B2 need x_pub for
   * their KDF; status/-setup display it. */
  unsigned char self_pub[HUB_KEY_RAW_LEN];
  bool          self_pub_set;
  /* hub_remote_ed_pub holds the pinned pubkey of the hub currently being
   * connected to: it is copied from hubs[idx].ed_pub at connect time so the
   * handshake-verification code has a single place to read from. The
   * authoritative per-hub keys live in hubs[]. */
  unsigned char hub_remote_ed_pub[32];
  bool          hub_remote_ed_pub_set;
  hub_entry_t hubs[MAX_SERVERS];
  int hub_count;
  int hub_fd;
  char current_hub[256]; // Track currently connected hub (ip:port)
  bool hub_connecting;
  bool hub_connected;
  bool hub_authenticated;
  /* Deleted on the hub (CMD_BOT_RETIRE): the config files are wiped and
   * config_write_file never writes them again before the bot exits. */
  bool retired;
  unsigned char hub_session_key[32];
  time_t last_hub_connect_attempt;
  time_t last_hub_ping_time;    // Last time we sent a PING to the hub
  time_t last_hub_activity;     // Last time we received a valid PONG/Data from hub
  time_t last_op_request_sent;  // Global rate-limit: last OP-REQ sent across all channels
  time_t op_request_next_slot;  // Next free retry slot for a channel the rate
                                // limit held back (315 handler)
  time_t last_chan_request_sent; // Global rate-limit: last channel-access request
  int chan_req_fallback_idx;    // Round-robin cursor over trusted bots for the
                                // hubless ~B2 fallback: one bot per attempt,
                                // never a broadcast to the whole roster
  unban_job_t unban_jobs[MAX_UNBAN_JOBS]; // Ban lists we are currently walking
  time_t hub_connect_time;      // When current hub connection was authenticated

  /* Bot tree pushed by the hub (CMD_BOT_TREE), for the 'bots' command.
   * Volatile and display-only: never written to the config, never consulted
   * for trust.  bot_tree_ts is 0 until the first push arrives. */
  bot_tree_row_t bot_tree[MAX_BOT_TREE_ROWS];
  int    bot_tree_count;
  time_t bot_tree_ts;
  /* Last presence we reported, so a reconnect or server change re-reports and
   * an idle bot does not spam the hub with identical frames. */
  char   presence_server[TREE_SERVER_MAX + 1];
  time_t last_presence_sent;
  /* The hub-driven upgrade this bot has acknowledged (CMD_UPGRADE_PREPARE).
   * COMMIT carries only the id and the version, so the release base the hub
   * named at PREPARE time is remembered here; an id that never went through
   * PREPARE, or one older than UPGRADE_PREPARE_TTL, is refused.  Volatile:
   * never written to the config, and the upgrade itself hands over through
   * UPGRADE_MARKER_FILE because exec() takes all of this with it. */
  char   upgrade_id[64];
  char   upgrade_target[64];
  char   upgrade_variant[8];
  char   upgrade_base[512];
  time_t upgrade_prepared;
  /* The run whose build this process IS: read from UPGRADE_MARKER_FILE when
   * the upgraded binary first reports in.  An ABORT rolls back to <exe>.prev
   * only for this run — .prev otherwise holds the build from before some
   * earlier, completed run, and a bot that refused a COMMIT never moved. */
  char   upgrade_installed_id[64];
  /* UPGRADE_PASS_REWRITE_SECS: when the deferred pass rewrite is due (0 =
   * none), and whether this process saved PASS_FILE UPGRADE_PREV_SUFFIX —
   * updater_hub_rollback() restores it only then, never a stale copy. */
  time_t pass_rewrite_due;
  bool   pass_prev_saved;
  /* The "ok" RESULT this restarted build owes its hub, held until it is back
   * where it was (see UPGRADE_OPS_WAIT): "" = nothing owed. */
  char   upgrade_report_id[64];
  char   upgrade_report_ops[UPGRADE_OPS_MAX];
  time_t upgrade_report_since;

  /* ---- modes.md ---- */
  sendq_t sendq;                /* output queue (sendq.c) */
  isupport_t isup;              /* this server's 005 (chanlive.c) */
  /* D| network defaults: stored modes, raw settings, parse. */
  char   net_modes[C_MODES_MAX + 1];
  char   net_settings[D_SETTINGS_MAX + 1];
  chan_settings_t net_set;
  time_t net_ts;
  /* B| records, heap, grown on demand up to CFG_MAX_BANS. */
  cfg_ban_t *cfg_bans;
  int    cfg_ban_count, cfg_ban_cap;
  chan_event_lim_t chan_event;
  /* chanenf.c: pending in-channel jobs, ban idle clocks, offences. */
  unsigned cfg_gen;            /* bumped when a C| / D| / B| record changes */
  unsigned enf_seen_gen;
  pending_job_t jobs[MAX_PENDING_JOBS];
  ban_track_t *ban_track;      /* heap, ban_track_count of ban_track_cap */
  int    ban_track_count, ban_track_cap;
  unsigned auth_gen;           /* bumped when cfg_gen or the auth records change */
  unsigned auth_seen_cfg_gen;
  uint64_t auth_fp;            /* fingerprint of trusted bots / users / masks */
  long long auth_fp_ms;        /* monotonic time of the last fingerprint */
  offence_t offences[MAX_OFFENCES];
  enf_recent_t enf_recent[ENF_RECENT];
  int    enf_recent_idx;
  time_t enf_last_minute;
  /* botflood.c: ignore table, quiet mode, host and per-user windows. */
  ignore_ent_t ignores[MAX_IGNORES];
  long long    quiet_until_ms;    /* 0 / past = not quiet */
  bool         quiet_logged;      /* the episode's one log line went out */
  host_flood_t host_flood[MAX_HOST_TRACK];
  cmd_flood_t  cmd_flood[MAX_USER_RECORDS];
};

// ... [Function Prototypes same as before] ...
void ssl_init_openssl(void);
/* Active user records that have a key and own an active mask matching
 * user_host; mask_idx[i] is the matching mask.  No side effects — call
 * auth_mark_used() once one of them has actually authenticated. */
int auth_user_candidates(bot_state_t *state, const char *user_host,
                         user_record_t **out, int *mask_idx, int max);
void auth_mark_used(bot_state_t *state, user_record_t *u, int mask_idx,
                    time_t now);
bool auth_is_trusted_bot(const bot_state_t *state, const char *user_host,
                         char *uuid_out, size_t uuid_out_size);
trusted_bot_t *auth_trusted_bot_by_host(bot_state_t *state,
                                        const char *user_host);
trusted_bot_t *auth_trusted_bot_by_uuid(bot_state_t *state, const char *uuid);
trusted_bot_t *auth_trusted_bot_by_nick(bot_state_t *state, const char *nick);
/* Nick part of a trusted bot's mask (up to '!'), bounded to MAX_NICK. */
void auth_trusted_bot_nick(const trusted_bot_t *tb, char out[MAX_NICK]);
/* Case-insensitive IRC-style glob ('*', '?').  Used for usermasks and for
 * matching a requester's hostmask against channel ban masks. */
bool auth_wildcard_match(const char *pattern, const char *text);
/* modes.md §1: true when nick!user@host matches a trusted-bot mask or an
 * active usermask of an active admin/oper -- "authorised".  Everyone else is
 * unauthorised.  The one test all channel protection is built on. */
bool auth_is_authorised(const bot_state_t *state, const char *nuh, const char *chan);
/* modes.md §6.2 step 2: true when ban mask `mask` could also match a
 * trusted-bot mask or an active usermask (glob overlap).  `who`, if given,
 * receives a label for the first conflict. */
bool auth_mask_overlaps_authorised(const bot_state_t *state, const char *mask,
                                   const char *chan,
                                   char *who, size_t who_size);
/* a|/o| and b| record codec shared by config.c and hub_client.c. */
bool config_parse_user_line(const char *data, user_line_t *out);
int config_format_user_line(const user_record_t *u, char *buf, size_t len);
bool config_parse_bot_line(const char *data, trusted_bot_t *out);
int config_format_bot_line(const trusted_bot_t *tb, char *buf, size_t len);
void setup_signals(void);
void daemonize(void);
void change_proc_name(int argc, char *argv[]);
void handle_signal(int signum);
void config_read(bot_state_t *state, const char *filename);
bool config_load(bot_state_t *state, const char *password,
                 const char *filename);
void config_write(bot_state_t *state, const char *password);
void config_write_local(const bot_state_t *state, const char *password);
void config_notify_hub_if_changed(bot_state_t *state);
chan_t *channel_add(bot_state_t *state, const char *name);
bool channel_remove(bot_state_t *state, const char *name);
chan_t *channel_find(const bot_state_t *state, const char *name);
void channel_list_destroy(bot_state_t *state);
void channel_list_reset_status(bot_state_t *state);
void channel_manager_check_joins(bot_state_t *state);
/* channel.c: free a channel's live ban list and reset its live state. */
void channel_live_reset(chan_t *c);

/* ---- chanlive.c: 005, live modes, ban lists (modes.md §5.4) ---- */
void isupport_reset(bot_state_t *state);
/* 005 parameters: "<me> TOKEN[=v] ... :are supported by this server". */
void isupport_parse(bot_state_t *state, char *params);
/* Does MODE letter `m` take an argument when set (adding) / cleared? */
bool isupport_mode_has_arg(const bot_state_t *state, char m, bool adding);
bool isupport_is_prefix_mode(const bot_state_t *state, char m);
int  isupport_ban_cap(const bot_state_t *state);   /* min(MAXLIST, 200) */
int  isupport_nicklen(const bot_state_t *state);   /* NICKLEN, <= MAX_MEMBER_NICK-1 */
uint64_t chan_live_bit(char letter);               /* 0 if not a letter */
bool chan_live_has(const chan_t *c, char letter);
/* Apply "<modes> [args...]" (a 324 or a MODE) to c's live state; args is
 * modified.  from_324 resets the live modes first. */
void chanlive_apply(bot_state_t *state, chan_t *c, const char *modes,
                    char *args, bool from_324);
void chanlive_ban_add(bot_state_t *state, chan_t *c, const char *mask,
                      const char *setter, time_t when);
void chanlive_ban_del(chan_t *c, const char *mask);
void chanlive_ban_list_end(chan_t *c);
/* 324 / 329 / 367 / 368 numerics: params after the command word. */
void chanlive_numeric(bot_state_t *state, const char *command, char *params);
/* Ask the server for a channel's modes and ban list (own JOIN). */
void chanlive_request(bot_state_t *state, chan_t *c);
/* Election kind `mode` (CMD_CHAN_DO): queue the MODE lines that move the live
 * modes to the stored C| modes + c| key.  Returns lines queued, -1 = no
 * stored/known state to act on.  *summary gets a short note. */
int  chanmode_apply_stored(bot_state_t *state, chan_t *c, char *summary,
                           size_t summary_size);
/* The same diff for the mode job: skip_limit leaves +l to the dynamic limit,
 * dry only counts, require_known refuses to act without a received 324. */
int  chanmode_sync(bot_state_t *state, chan_t *c, bool skip_limit, bool dry,
                   bool require_known, char *summary, size_t summary_size);
/* True when `nick` is in c's roster and authorised; *found says whether the
 * nick was in the roster at all. */
bool chan_member_authorised(const bot_state_t *state, const chan_t *c,
                            const char *nick, bool *found);

/* ---- chancfg.c: C| / D| / B| records and effective settings ---- */
bool chancfg_parse_settings(const char *s, bool net, chan_settings_t *out);
/* Each takes the line body after "X|" and applies it under LWW.  True when
 * the stored record changed. */
bool chancfg_apply_c_line(bot_state_t *state, const char *data);
bool chancfg_apply_d_line(bot_state_t *state, const char *data);
bool chancfg_apply_b_line(bot_state_t *state, const char *data);
/* A listed ban (chan, mask) matched an unauthorised member: stamp its last
 * use; the first in an ACTIVITY_BUCKET goes to the hub.  Sticky: ignored. */
void chancfg_ban_mark_used(bot_state_t *state, const char *chan, const char *mask,
                           time_t now);
/* Line writers ("C|...\n" with the newline).  Return length, <0 on overflow. */
int  chancfg_format_c_line(const chan_t *c, char *buf, size_t len);
int  chancfg_format_d_line(const bot_state_t *state, char *buf, size_t len);
int  chancfg_format_b_line(const cfg_ban_t *b, char *buf, size_t len);
/* Effective values: channel override -> D| -> built-in.  c may be NULL (net
 * level only).  Flags return 0/1. */
long chancfg_get(const bot_state_t *state, const chan_t *c, cset_id_t id);
/* Flood limits; false when the flood is off.  FL_BOT_* ignore c. */
bool chancfg_get_flood(const bot_state_t *state, const chan_t *c,
                       flood_kind_t kind, int *n, int *s);
/* Stored modes string: C| -> D| -> "+nt". */
const char *chancfg_get_modes(const bot_state_t *state, const chan_t *c);
/* Drop B| tombstones stamped before cutoff (0 = all); returns count. */
int  chancfg_purge_bans(bot_state_t *state, time_t cutoff);
/* Active bans for `chan` (its own and "*"), at most max; returns count. */
int  chancfg_bans_for(const bot_state_t *state, const char *chan,
                      const cfg_ban_t **out, int max);
/* Bot-written B| (an automatic ban): stored here, pushed to the hub; a
 * timed ban only (expires > now).  del=true writes the "del" for a ban this
 * bot wrote.  Pushed regardless of opt 'h' (D43). */
bool chancfg_bot_ban(bot_state_t *state, const char *chan, const char *mask,
                     time_t expires, const char *flags, const char *reason,
                     bool del);
/* Local (bot command) writes, same line formats as the hub, LWW-stamped past
 * the stored record, applied at once, pushed to a connected hub and saved.
 * Not gated here: the caller checks admin_change_refused. */
bool chancfg_local_c(bot_state_t *state, chan_t *c, const char *modes,
                     const char *settings);
bool chancfg_local_d(bot_state_t *state, const char *modes,
                     const char *settings);
bool chancfg_local_ban(bot_state_t *state, const char *chan, const char *mask,
                       time_t expires, const char *flags, const char *setter,
                       const char *reason, bool del);
/* Active network ban for chan+mask, or NULL. */
const cfg_ban_t *chancfg_ban_get(const bot_state_t *state, const char *chan,
                                 const char *mask);
/* Edit a settings field in place: set name=value or (value "default") drop it.
 * name is "bitch", "bantime", "flood join", "bflood cmd", ...  net allows the
 * D|-only names.  False with `why` filled when the name or value is bad. */
bool chancfg_settings_edit(char *settings, size_t cap, bool net,
                           const char *name, const char *value, char *why,
                           size_t why_size);
bool chancfg_setting_is_flag(const char *name);
/* Listing support: index 0..CS_COUNT-1 are the cset_id_t settings, then the
 * FL_COUNT floods.  name is NULL past the end or for a hidden one. */
const char *chancfg_item_name(int idx, bool net);
bool chancfg_item_help(int idx, char *def, size_t def_size, const char **what);
/* 2 = channel override, 1 = network default, 0 = built-in. */
int  chancfg_item_source(const bot_state_t *state, const chan_t *c, int idx);
void chancfg_free(bot_state_t *state);
/* Opt 'h' (D43): true when an ADMIN-initiated change to hub records must be
 * refused.  Enforcement writes (learned keys, modes, auto bans) never ask. */
bool admin_change_refused(const bot_state_t *state);
/* ---- chanenf.c: in-channel elections + set options (modes.md §4, §6, §7) -- */
/* Parser hooks, called after the live state is updated.  `prefix` is the
 * message source ("nick!user@host", or a server name with no '!'). */
void chanenf_on_join(bot_state_t *state, const char *chan, const char *nuh);
void chanenf_on_part(bot_state_t *state, const char *chan, const char *nick);
void chanenf_on_quit(bot_state_t *state, const char *nick);
void chanenf_on_kick(bot_state_t *state, const char *chan, const char *prefix,
                     const char *victim);
void chanenf_on_nick(bot_state_t *state, const char *old_nick,
                     const char *new_nick);
void chanenf_on_mode(bot_state_t *state, const char *chan, const char *prefix,
                     const char *modes, char *args);
/* Add or replace a roster entry (WHO reply, JOIN); false when full. */
bool chanenf_roster_set(chan_t *c, const char *nick, const char *hostmask,
                        bool op, bool halfop, bool voice);
/* Main-loop tick (<= 1 s): sweeps, pending jobs, 60 s ban expiry. */
void chanenf_tick(bot_state_t *state);
/* The deal: this bot's backup index (0 = holds the job now) for job JOB_*
 * in channel c, or -1 when it takes no part (not opped, not in the deal). */
int  chanenf_deal_rank(bot_state_t *state, const chan_t *c, int job);
/* Pure helpers (also what bot commands / the console path will use). */
bool chanenf_ban_mask(int type, const char *nuh, char *out, size_t out_size);
bool chanenf_ban_allowed(bot_state_t *state, const chan_t *c, const char *mask,
                         char *who, size_t who_size);
bool chanenf_auto_ban_mask(bot_state_t *state, const chan_t *c, const char *nuh,
                           char *out, size_t out_size);
/* Hooks for the flood / ladder lane.  Each queues a job in the channel
 * election (executed at once by the job holder, after backup delay by the
 * others, re-checked first).  true = queued/ran, false = not eligible. */
bool chanenf_request_kick(bot_state_t *state, const char *chan,
                          const char *nick, const char *reason);
bool chanenf_request_deop(bot_state_t *state, const char *chan,
                          const char *nick, const char *reason);
/* Automatic ban of the host in `nuh` (bantype, bantime, §6.2 narrowing
 * retry, bot-written B|); kick_too also requests the kick for that nick. */
bool chanenf_request_ban(bot_state_t *state, const char *chan, const char *nuh,
                         const char *reason, bool kick_too);
/* Repeat-offence memory keyed by channel + host: counts this one, forgets
 * after bantime; returns the count (1 = first offence). */
unsigned chanenf_offence(bot_state_t *state, const char *chan, const char *nuh);
/* True for this bot itself or an authorised user/bot (nick!user@host). */
bool chanenf_nuh_authorised(const bot_state_t *state, const char *nuh);
/* Same, using the roster's cached verdict when nuh is a member of c. */
bool chanenf_chan_nuh_authorised(bot_state_t *state, const chan_t *c,
                                 const char *nuh);
/* ---- chanflood.c: channel floods (modes.md §8) ---- */
/* Pure window step: true when this event is the N+1th inside the window (the
 * window is then reset, so one trip is reported once).  n/s from the setting. */
bool flood_window_hit(flood_window_t *w, int n, int s, long long now_ms);
/* Count one event of `kind` from nick!user@host in `chan`; trips run the §8.3
 * ladder.  victim_auth: the event hurt an authorised member (+revenge). */
void chanflood_event(bot_state_t *state, const char *chan, const char *nuh,
                     flood_kind_t kind, bool victim_auth);
/* Testable core: true when the event tripped its flood (no ladder run). */
bool chanflood_count_at(bot_state_t *state, chan_t *c, const char *nuh,
                        flood_kind_t kind, bool victim_auth, long long now_ms,
                        bool *auth_victim_out);
long long flood_now_ms(void);
/* PRIVMSG / NOTICE to a channel: counts as chan, or ctcp for a non-ACTION CTCP. */
void chanflood_on_text(bot_state_t *state, const char *chan, const char *nick,
                       const char *user, const char *host, const char *msg);

/* ---- botflood.c: bot floods, ignore table, quiet mode (modes.md §9.1) ---- */
#define BF_OK     0   /* carry on */
#define BF_DROP   1   /* drop this one (a command over its limit) */
#define BF_IGNORE 2   /* source ignored: drop silently */
#define BF_IGNORE_NEW 3 /* cmd: ignored from now on (also an ignore) */
/* Per-host floods for non-command PRIVMSG / NOTICE (msg) and CTCP (ctcp) to
 * the bot.  Authorised sources are never counted.  BF_IGNORE = answer nothing. */
int  botflood_msg(bot_state_t *state, const char *nuh);
int  botflood_ctcp(bot_state_t *state, const char *nuh);
/* Is this source host ignored right now (no count)? */
bool botflood_host_ignored(bot_state_t *state, const char *nuh);
/* `flood cmd` for one user record, called for every sealed command about to
 * run.  BF_DROP also sends the one "slow down" notice per window to `nick`. */
int  botflood_cmd(bot_state_t *state, const user_record_t *who, const char *nick);
/* Quiet mode: unauthorised sources get no reply at all. */
bool botflood_quiet(bot_state_t *state);
/* Testable cores (now_ms injected). */
int  botflood_msg_at(bot_state_t *state, const char *nuh, bool authorised,
                     long long now_ms);
int  botflood_ctcp_at(bot_state_t *state, const char *nuh, bool authorised,
                      long long now_ms);
int  botflood_cmd_at(bot_state_t *state, const user_record_t *who,
                     long long now_ms, bool *notice);

/* ---- chancmd.c: bot commands for hubless networks (modes.md §5.2) ---- */
void chancmd_chanmode(bot_state_t *state, const char *nick,
                      const user_record_t *who, char *args);
void chancmd_chanset(bot_state_t *state, const char *nick,
                     const user_record_t *who, char *args);
void chancmd_ban_add(bot_state_t *state, const char *nick,
                     const user_record_t *who, char *args);
void chancmd_ban_del(bot_state_t *state, const char *nick,
                     const user_record_t *who, char *args);
void chancmd_bans(bot_state_t *state, const char *nick, char *args);

/* enforcemodes with a k in the stored modes: the key is the bots', so a key
 * someone else sets or clears is not learned (§3.3). */
bool chanenf_key_managed(const bot_state_t *state, const chan_t *c);

void irc_connect(bot_state_t *state);
void irc_disconnect(bot_state_t *state);
int irc_printf(bot_state_t *state, const char *format, ...)
    __attribute__((format(printf, 2, 3)));
/* The actual write of one finished line to the server socket (the send
 * queue calls it when pacing allows).  A write error disconnects. */
int irc_write_raw(bot_state_t *state, const char *buffer, int len);

/* ---- sendq.c: paced output queue (modes.md §10) ---- */
void sendq_init(bot_state_t *state);
void sendq_set_limits(bot_state_t *state, int burst, int interval_ms);
int  sendq_next_ms(bot_state_t *state);          /* ms to next line, -1 none */
void sendq_clear(bot_state_t *state);            /* link gone: drop it all */
/* Queue one finished line (ends in CRLF).  Lane by verb: PONG / registration
 * -> proto, MODE changes / KICK -> protection, the rest -> other.  Drains at
 * once while credit lasts.  Returns len, or -1 when it had to be dropped. */
int  sendq_enqueue(bot_state_t *state, const char *line, int len);
int  sendq_drain(bot_state_t *state);            /* lines written now */
void sendq_hold(bot_state_t *state);             /* queue only, so MODEs pack */
void sendq_release(bot_state_t *state);          /* undo one hold; drain at 0 */
bool sendq_pending(const bot_state_t *state);
/* True when lines wait AND credit allows one now (select write-set hint). */
bool sendq_ready(bot_state_t *state);
int  sendq_lane_of(const char *line);            /* SENDQ_LANE_* for a line */

void irc_handle_read(bot_state_t *state);
void irc_check_status(bot_state_t *state);
void irc_attempt_nick_change(bot_state_t *state, const char *new_nick);
void irc_generate_new_nick(bot_state_t *state);
/* Server refusal handling (irc_client.c) */
void irc_note_refusal(bot_state_t *state, const char *text, bool ban_numeric);
void irc_note_registered(bot_state_t *state);
void irc_server_block_clear(bot_state_t *state, int idx);
void irc_server_block_remove(bot_state_t *state, int idx);
void irc_server_block_desc(const bot_state_t *state, int idx, char *buf,
                           size_t len);
void parser_handle_line(bot_state_t *state, char *line);
void commands_handle_private_message(bot_state_t *state, const char *nick,
                                     const char *user, const char *host,
                                     const char *dest, char *message);
/* One line from an open DCC chat.  Only a sealed ~A2 frame from the admin who
 * opened the chat is run; false means the chat must be closed. */
bool commands_handle_dcc_line(bot_state_t *state, dcc_session_t *s,
                              char *line);
/* DCC CHAT (dcc.c) */
void dcc_init(bot_state_t *state);
void dcc_offer(bot_state_t *state, const char *nick, const char *user_host,
               const user_record_t *who);
/* A "DCC ..." CTCP to us: completes this bot's own pending offer, if it is
 * the reply to one; every other DCC request is ignored. */
void dcc_handle_ctcp(bot_state_t *state, const char *user_host,
                     const char *ctcp);
void dcc_fill_fds(bot_state_t *state, fd_set *rfds, fd_set *wfds, int *max_fd);
void dcc_process(bot_state_t *state, const fd_set *rfds, const fd_set *wfds);
void dcc_check_timeouts(bot_state_t *state);
bool dcc_divert_reply(bot_state_t *state, const char *line, int len);
void dcc_close_all(bot_state_t *state, const char *reason);
void bot_comms_send_command(bot_state_t *state, const char *target_nick,
                            const char *format, ...)
    __attribute__((format(printf, 3, 4)));
void bot_comms_send_to_host(bot_state_t *state, const char *hostmask,
                            const char *target_nick, const char *format, ...)
    __attribute__((format(printf, 4, 5)));
_Noreturn void handle_fatal_error(const char *message);
void updater_check_for_updates(bot_state_t *state, const char *nick);
int updater_check_cli(const char *variant);
void updater_perform_upgrade(bot_state_t *state, const char *nick,
                             const char *version);
/* Hub-driven upgrade (CMD_UPGRADE_COMMIT).  Returns false with *err set and
 * nothing touched; on success it does not return -- the process is replaced
 * and reports the outcome after the restart. */
bool updater_hub_commit(bot_state_t *state, const char *upgrade_id,
                        const char *target_ver, const char *variant,
                        const char *base, const char **err);
/* CMD_UPGRADE_ABORT: restore <exe>.prev / <config>.prev and restart onto
 * them.  Returns false when there is nothing retained to go back to. */
bool updater_hub_rollback(bot_state_t *state, const char *reason);
/* CMD_UPGRADE_PREPARE: could this bot take target_ver as `variant`?  Checks
 * everything COMMIT will need short of the download (signed manifest, host
 * artifact, min_from, unattended restart).  False with `reason` filled in. */
bool updater_hub_prepare_check(bot_state_t *state, const char *target_ver,
                               const char *variant, const char *min_from,
                               const char *base, char *reason,
                               size_t reason_size);
bool upgrade_marker_write(const char *upgrade_id, const char *target_ver,
                          const char *variant, const char *ops);
/* Reads and removes the hand-off marker left by updater_hub_commit():
 * id|version|variant ("" variant from an older build's two-field marker). */
bool updater_take_pending_upgrade(char *id_out, size_t id_size, char *ver_out,
                                  size_t ver_size, char *variant_out,
                                  size_t variant_size, char *ops_out,
                                  size_t ops_size);
/* config_load() never rewrites the config while this is set (-selftest). */
extern bool g_config_readonly;
/* Compare two version strings, tolerating a leading 'v' on either side. */
int updater_version_cmp(const char *a, const char *b);
/* Host capability probe answered in CMD_UPGRADE_READY. */
void updater_host_arch(char *out, size_t out_size);
void updater_host_libc(char *out, size_t out_size);
const char *updater_host_variant(void);
bool util_download_file(const char *url, const char *path);
bool util_sha256_file(const char *path, char *output_hash_hex);
void log_message(log_type_t log_type_flag, const bot_state_t *state,
                 const char *format, ...)
    __attribute__((format(printf, 3, 4)));
int crypto_aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                           const unsigned char *key, unsigned char *ciphertext,
                           unsigned char *tag);
int crypto_aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                           const unsigned char *key, unsigned char *plaintext,
                           unsigned char *tag);
int crypto_aes_gcm_encrypt_aad(const unsigned char *plaintext, int plaintext_len,
                                const unsigned char *aad, int aad_len,
                                const unsigned char *key,
                                unsigned char *output_buffer,
                                unsigned char *tag);
int crypto_aes_gcm_decrypt_aad(const unsigned char *input_buffer, int input_len,
                                const unsigned char *aad, int aad_len,
                                const unsigned char *key,
                                unsigned char *plaintext,
                                unsigned char *tag);
int crypto_hkdf_sha256(const unsigned char *ikm, size_t ikm_len,
                       const unsigned char *salt, size_t salt_len,
                       const unsigned char *info, size_t info_len,
                       unsigned char *out, size_t out_len);
/* Derive a 32-byte AES-256-GCM key from a password using PBKDF2-HMAC-SHA256
 * with the given rounds (PBKDF2_ITERATIONS, or PBKDF2_ITERATIONS_LEGACY to
 * read a pre-2.5.0 file). Returns true on success. */
bool crypto_derive_config_key(const char *password, const unsigned char *salt,
                              int iterations, unsigned char out_key[32]);
bool crypto_generate_combined_keypair(unsigned char priv_out[HUB_KEY_RAW_LEN],
                                       unsigned char pub_out[HUB_KEY_RAW_LEN]);
/* Verify a 64-byte detached Ed25519 signature over msg with a 32-byte pubkey. */
bool crypto_ed25519_verify(const unsigned char pub[32],
                           const unsigned char *msg, size_t msg_len,
                           const unsigned char sig[64]);
/* X25519; false on failure or an all-zero (low-order point) result. */
bool crypto_x25519_derive(const unsigned char priv[32],
                          const unsigned char peer_pub[32],
                          unsigned char out[32]);
bool crypto_combined_pub_from_priv(const unsigned char priv[HUB_KEY_RAW_LEN],
                                   unsigned char pub[HUB_KEY_RAW_LEN]);
/* Strict: canonical base64 of exactly 64 bytes, neither half all zero. */
bool crypto_pubkey_b64_decode(const char *b64, unsigned char out[HUB_KEY_RAW_LEN]);
void crypto_key_fingerprint(const unsigned char pub[HUB_KEY_RAW_LEN],
                            char out[KEY_FP_LEN + 1]);
/* Sealed frame eph_pub(32) || iv(12) || ct || tag(16).  s_x_priv/s_x_pub add
 * the static sender term (both NULL = anonymous).  Return length or -1. */
int crypto_seal(const unsigned char *s_x_priv, const unsigned char *s_x_pub,
                const unsigned char r_x_pub[32], const char *label,
                const unsigned char *aad, size_t aad_len,
                const unsigned char *pt, size_t pt_len,
                unsigned char *out, size_t out_cap);
int crypto_open(const unsigned char r_x_priv[32], const unsigned char r_x_pub[32],
                const unsigned char *s_x_pub, const char *label,
                const unsigned char *aad, size_t aad_len,
                const unsigned char *frame, size_t frame_len,
                unsigned char *pt_out, size_t pt_cap);
/* crypto_open that, when the frame opens, also derives rk_out = HKDF(ikm,
 * salt = eph_pub, info = rk_label || s_x_pub || r_x_pub) from the same
 * exchange: the ~A2S reply key, which the sender can derive too.  Needs
 * s_x_pub (a static term); rk_out is untouched on failure. */
int crypto_open_rk(const unsigned char r_x_priv[32], const unsigned char r_x_pub[32],
                   const unsigned char *s_x_pub, const char *label,
                   const unsigned char *aad, size_t aad_len,
                   const unsigned char *frame, size_t frame_len,
                   unsigned char *pt_out, size_t pt_cap,
                   const char *rk_label, unsigned char rk_out[32]);
/* ~A2R frame under a reply key: iv(12, random) || ct || tag(16).  Seal returns
 * the frame length, open the plaintext length; -1 on any failure. */
int crypto_reply_seal(const unsigned char key[32], const unsigned char *aad,
                      size_t aad_len, const unsigned char *pt, size_t pt_len,
                      unsigned char *out, size_t out_cap);
int crypto_reply_open(const unsigned char key[32], const unsigned char *aad,
                      size_t aad_len, const unsigned char *frame,
                      size_t frame_len, unsigned char *pt_out, size_t pt_cap);
/* Volatile-pointer secure zero. Compiler may NOT elide. */
void secure_wipe(void *ptr, size_t len);
char *base64_encode(const unsigned char *input, int length);
unsigned char *base64_decode(const char *input, int *out_len);
void hub_client_init(bot_state_t *state);
void hub_client_connect(bot_state_t *state);
void hub_client_process(bot_state_t *state);
void hub_client_promote_local_config(bot_state_t *state);
void hub_client_push_config(bot_state_t *state);
void hub_client_push_admin_delta(bot_state_t *state);
bool hub_client_push_delta(bot_state_t *state, const char *key,
                           const char *value, time_t ts);
void hub_client_push_channel(bot_state_t *state, chan_t *chan);
/* Send complete record lines ("B|...\n", "c|...\n") to the hub as one
 * CMD_CONFIG_PUSH, whatever opt 'h' says (D43).  False when no hub link. */
bool hub_client_push_lines(bot_state_t *state, const char *lines, size_t len);
/* CMD_CHAN_EVENT (D42): one enforcement action, bot-side rate limited
 * (CHAN_EVENT_*).  action: deop reop kick ban unban moderevert limit
 * floodtrip ignore.  True when a frame was sent. */
bool hub_client_chan_event(bot_state_t *state, const char *chan,
                           const char *action, const char *target,
                           const char *detail);
void hub_client_sync_hostmask(bot_state_t *state);
void hub_client_heartbeat(bot_state_t *state);
/* Report version / IRC server / start time to the hub for the 'bots' tree.
 * force re-sends even when nothing changed (used right after authenticating,
 * when the hub has no presence for us at all). */
void hub_client_send_presence(bot_state_t *state, bool force);
void hub_client_disconnect(bot_state_t *state);
/* Network-upgrade reporting (CMD_UPGRADE_RESULT).  report_upgrade_result()
 * is a no-op unless this process is a hub-driven upgrade's restart. */
void hub_client_send_upgrade_result(bot_state_t *state, const char *id,
                                    const char *status, const char *detail);
void hub_client_report_upgrade_result(bot_state_t *state);
/* Main-loop tick: send the held "ok" RESULT once this bot is back and
 * re-opped where it was, or UPGRADE_OPS_WAIT has passed. */
void hub_client_upgrade_report_tick(bot_state_t *state);
void hub_client_send_activity(bot_state_t *state);
bool hub_client_send_activity_query(bot_state_t *state, const char *payload);
void commands_activity_reply(bot_state_t *state, char *payload);
void commands_activity_tick(bot_state_t *state, time_t now);
void hub_client_on_connect(bot_state_t *state);
void hub_client_grant_held_ops(bot_state_t *state, chan_t *c);
bool hub_client_request_op(bot_state_t *state, const char *target_uuid,
                           const char *channel);
/* Ask the mesh to let us into `chan`: CMD_CHAN_REQUEST when a hub is up,
 * otherwise a sealed ~B2 to one trusted bot.  Rate-limited per chan+kind and
 * globally; returns true when a request actually left the bot. */
bool chan_access_request(bot_state_t *state, chan_t *chan,
                         chan_req_kind_t kind);
/* Service a request another bot made of us.  `hostmask` and `nick` are the
 * requester's as the hub resolved them; both may be empty for kinds that do
 * not need them.  Replies (key) go back via `reply_to`, which is NULL for the
 * hub path and the requester's nick for the ~B2 fallback. */
void chan_access_service(bot_state_t *state, const char *request_id,
                         chan_req_kind_t kind, const char *channel,
                         const char *req_uuid, const char *nick,
                         const char *hostmask, const char *reply_to);
/* Ban-list plumbing for an unban we are servicing (367 entry / 368 end). */
void chan_unban_note_ban(bot_state_t *state, const char *channel,
                         const char *ban_mask);
void chan_unban_finish(bot_state_t *state, const char *channel);
void chan_unban_expire(bot_state_t *state);
/* Wire token <-> kind.  Returns CHAN_REQ_KIND_COUNT for an unknown token. */
chan_req_kind_t chan_req_kind_from_token(const char *tok);
const char *chan_req_kind_token(chan_req_kind_t kind);
/* Adopt a key another bot sent us, then re-try the join immediately. */
void chan_access_accept_key(bot_state_t *state, const char *channel,
                            const char *key);
/* Frame a channel-access request / reply to the hub.  False when no hub link
 * is usable, which is the caller's cue to fall back to ~B2. */
bool hub_client_send_chan_request(bot_state_t *state, const char *kind,
                                  const char *channel);
bool hub_client_send_chan_reply(bot_state_t *state, const char *request_id,
                                const char *kind, const char *channel,
                                const char *status, const char *data);
bool hub_client_relay_bot_command(bot_state_t *state, const char *target_uuid,
                                  const char *frame_line);
/* Split the mlock'd identity key into its halves (caller wipes). */
bool bot_key_decode(bot_state_t *state, unsigned char ed_priv[32],
                    unsigned char x_priv[32]);
/* Recompute self_pub from the identity key; false if there is no usable key. */
bool bot_self_pub_refresh(bot_state_t *state);
/* Strict "<ts>:<nonce16hex>:<command>" parser shared by ~A2 and ~B2. */
bool envelope_parse(char *pt, time_t *ts, uint64_t *nonce, char **cmd);
/* Hub-relayed CMD_BOT_MSG: "<sender_uuid>|~B2 <b64>". */
void bot_comms_process_payload(bot_state_t *state, const char *payload);
/* Direct PRIVMSG from a trusted bot.  Returns true if message was a ~B2
 * frame (handled or dropped) so the caller stops processing it. */
bool bot_comms_handle_privmsg(bot_state_t *state, const char *nick,
                              const char *user_host, const char *message);
void bot_set_startup_pass(bot_state_t *s, const char *pass);
void bot_get_startup_pass(const bot_state_t *s, char out[MAX_PASS]);
bool bot_has_startup_pass(const bot_state_t *s);
void config_write_with_state_pass(bot_state_t *s);
void config_write_local_with_state_pass(bot_state_t *s);

/* Timestamp for changing an EXISTING replicated record: now, but always past
 * its previous stamp.  Hubs and bots accept only a strictly newer timestamp,
 * so an add and a remove in the same second would tie and the remove would
 * never replicate (a removed admin staying active elsewhere). */
static inline time_t lww_next_ts(time_t prev) {
  time_t now = time(NULL);
  return now > prev ? now : prev + 1;
}

/* LWW acceptance for a replicated add/del record: a strictly newer stamp wins,
 * and on an exact tie a delete beats an add.  lww_next_ts only separates
 * writes made on ONE node; two nodes stamping the same second tie, and with a
 * plain "newer wins" each keeps its own copy and refuses the other's forever
 * (a parted channel staying joined on some bots).  Delete-over-add is
 * deterministic, so every node converges.  Mirrors irchub hub.h
 * hub_lww_accepts -- the rule must match on both. */
static inline bool lww_accepts(time_t in_ts, bool in_active, time_t cur_ts,
                               bool cur_active) {
  return in_ts > cur_ts || (in_ts == cur_ts && cur_active && !in_active);
}

/* LWW acceptance for the network opt flags pushed by the hub.  Newer stamp
 * wins; on a tie the byte-wise greater flag string wins (a set beats a clear).
 * ">=" used to let whichever push arrived last win, so bots on different hubs
 * settled on different flags for the same stamp.  Mirrors irchub hub.h
 * hub_opt_accepts. */
static inline bool opt_accepts(time_t in_ts, const char *in_flags,
                               time_t cur_ts, const char *cur_flags) {
  return in_ts > cur_ts ||
         (in_ts == cur_ts && strcmp(in_flags, cur_flags) > 0);
}

static inline bool is_valid_bot_nick(const char *nick) {
  return nick && strlen(nick) > 0 && strlen(nick) < MAX_NICK &&
         strchr(nick, '|') == NULL;
}

/* A nick every ircd accepts (RFC 2812): a letter or one of []\`_^{} first,
 * then letters, digits, those or '-', within is_valid_bot_nick's length.
 * '|' is an RFC special too but stays out: it is the record delimiter.
 * Checked wherever a bot's nick is set or changed (wizard, chnick, SETNICK);
 * a nick already in a config still loads. */
static inline bool is_rfc_nick(const char *nick) {
  if (!is_valid_bot_nick(nick))
    return false;
  for (const char *p = nick; *p; p++) {
    unsigned char c = (unsigned char)*p;
    bool letter = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z');
    bool special = strchr("[]\\`_^{}", c) != NULL;
    bool later = (c >= '0' && c <= '9') || c == '-';
    if (!letter && !special && !(later && p != nick))
      return false;
  }
  return true;
}

/* True if buf[0..len) holds a C0 control byte (NUL, CR, LF, ...) or DEL.
 * Decrypted admin/oper/bot commands that match are dropped whole: a CR/LF in
 * an argument would otherwise split into a second IRC command. */
static inline bool has_control_bytes(const void *buf, size_t len) {
  const unsigned char *p = (const unsigned char *)buf;
  for (size_t i = 0; i < len; i++)
    if (p[i] < 0x20 || p[i] == 0x7f)
      return true;
  return false;
}

/* Returns true if option letter `c` is present in the network-pushed
 * opt_flags string.  `c` is matched as-is; flag letters are case-sensitive
 * (uppercase and lowercase are independent options). */
static inline bool is_opt_set(const bot_state_t *state, char c) {
  if (!state || !state->opt_flags[0]) return false;
  return strchr(state->opt_flags, c) != NULL;
}

#ifdef DEBUG
static inline void debug_hex_dump(const char *label, const unsigned char *data,
                                  int len) {
  printf("[DEBUG] %s (%d bytes): ", label, len);
  for (int i = 0; i < len; i++)
    printf("%02x", data[i]);
  printf("\n");
}
#endif
/* access.c — admin flags (uf|) and oper channel bindings (uc|), irchub
 * docs/plans/2026-10-16_user_flags_plan.md */
bool access_flags_canon(const char *in, char *out, size_t cap);
bool access_flags_edit(const char *cur, const char *spec, char *out, size_t cap);
bool access_flags_accepts(time_t in_ts, const char *in, time_t cur_ts, const char *cur);
bool access_chan_name_ok(const char *chan);
uflag_record_t *access_uflag_find(bot_state_t *state, const char *uuid);
uchan_record_t *access_uchan_find(bot_state_t *state, const char *uuid, const char *chan);
bool access_uflag_put(bot_state_t *state, const char *uuid, const char *flags, time_t ts);
bool access_uchan_put(bot_state_t *state, const char *uuid, const char *chan, bool active,
                      time_t ts);
const char *access_user_flags(const bot_state_t *state, const char *uuid);
bool access_user_has_flag(const bot_state_t *state, const char *uuid, char flag);
bool access_user_chan_ok(const bot_state_t *state, const char *uuid, const char *chan);
int access_user_chan_count(const bot_state_t *state, const char *uuid, bool *global);
int access_format_uflag(const uflag_record_t *r, char *buf, size_t cap);
int access_format_uchan(const uchan_record_t *r, char *buf, size_t cap);
bool access_ingest(bot_state_t *state, char kind, const char *body, bool need_user,
                   bool *changed);
int access_migrate(bot_state_t *state);
void access_prune(bot_state_t *state);
int access_purge(bot_state_t *state, time_t cutoff);
void access_user_chans(const bot_state_t *state, const char *uuid, char *out, size_t cap);
time_t access_next_ts(bot_state_t *state, const char *uuid);
int access_chan_change(bot_state_t *state, const char *uuid, bool add, const char *chan);
int access_chan_cascade(bot_state_t *state, const char *chan, time_t ts);

/* hub_client.c: a person's channel request (user_flags plan §5) */
bool hub_client_send_user_chan_request(bot_state_t *state, const char *kind, const char *chan,
                                       const char *user_uuid, const char *nick,
                                       const char *mask);
void hub_client_user_chan_tick(bot_state_t *state);
/* bot_comms.c: the hubless path -- ask every trusted bot over ~B2 */
void bot_comms_user_chan_fallback(bot_state_t *state, const char *kind, const char *chan,
                                  const char *nick, const char *mask);

#endif
