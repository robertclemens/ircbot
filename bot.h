#ifndef BOT_H
#define BOT_H

#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <curl/curl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>
#include <limits.h>

#define BOT_NAME "ircbot.c by trojanman"
#define BOT_VERSION "2.0.0"

// Only edit this section
#define DEFAULT_USER "ircbot"         // Default bot user
#define VHOST "NULL"  // NULL for default host, set for alternate
#define CONFIG_PASS_ENV_VAR "BOT_PASS"  // ENV variable for config password
#define VERSION_RESPONSE "A robot may not injure a human being" // This is the response to a CTCP Version

#define GECOS "ircbot"         // Gecos field storage
#define CONFIG_FILE ".ircbot.cnf"  // Config file name
#define PID_FILE ".ircbot.pid" // PID file name
#define SALT_SIZE 8            // You do not need to change this
#define DEFAULT_LOG_LEVEL 0 // Set the default log level. 0=none
#define LOGFILE ".ircbot.log"  // Log file name. Only used if log level > 0
#define BOT_UPDATE_URL "https://raw.githubusercontent.com/robertclemens/ircbot/main/releases/releases.txt"
// End of edit section

// You should not edit below this line. While some of the macros may be editable, some macros may cause issues.
// Proceed at your own risk.

// Timeouts
#define JOIN_RETRY_TIME 10 // Time delay between trying to join a channel
#define NICK_TAKE_TIME 20 // Time delay for givenick to stop trying to take the nick back
#define NICK_RETRY_TIME 10 // Time delay for trying to gain the target nick (outside of givenick cmd)
#define DEAD_SERVER_TIMEOUT 120 // Server connection timeout
#define CHECK_LAG_TIMEOUT 60 // Lag timeout
#define ROSTER_REFRESH_INTERVAL 120 // How often should a /who #channel be performed to look for known bots that are ops

// Limits
#define MAX_SERVERS 10 // Max number of servers to store
#define MAX_MASKS 20 // Max number of admin masks to store
#define MAX_CHAN 65 // Max length of channel name. Do not change
#define MAX_BUFFER 512 // Size of RAW IRC message. Do not change
#define MAX_NICK 10 // Max nick length 9 + NULL terminator = 10. Do not change
#define MAX_PASS 128 // Max password length.
#define MAX_KEY 31 // Max length for a channel key
#define MAX_MASK_LEN 128 // Max usermask length
#define MAX_OP_MASKS 20 // Max number of operators
#define MAX_TRUSTED_BOTS 20 // Max number of trusted bots
#define MAX_ROSTER_SIZE 50 // Max channel roster size to store. Increase if in very large channels.
#define NONCE_CACHE_SIZE 32 // Nonce cache for secure communication. Prevents replay attacks
#define GCM_IV_LEN 12 // 12 bytes (96 bits) is industry standard. Do not change
#define GCM_TAG_LEN 16 // 16 bytes (128 bits) is industry standard. Do not change
#define NUM_LOG_LEVELS 6 // For L_MSG, L_CTCP, L_INFO, L_CMD, L_RAW, L_DEBUG
#define LOG_BUFFER_LINES 50   // Store the last 50 log lines for each log level
#define MAX_LOG_LINE_LEN 256 // Max length of a single log line
#define DEFAULT_LOG_LINES 10 // Default number of getlog lines to display to admin when requested if not provided
#define MAX_LOG_LINES 20     // Max number of lines to cap getlog request to help prevent flooding

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
typedef enum { C_NONE = 0, C_OUT = 1 << 0, C_IN = 1 << 1 } chan_status_t;
typedef enum { M_NONE = 0, M_K = 64 } chan_mode_t;
typedef enum { LS_NONE = 0, LS_LISTEN = 1, LS_CONNECTED = 2 } listen_status_t;

// Struct Forward Declarations
typedef struct bot_state bot_state_t;
typedef struct chan_t chan_t;
typedef struct {
  char mask[MAX_MASK_LEN];
  char password[MAX_PASS];
} op_mask_t;

// Struct Definitions
typedef struct {
  char nick[MAX_NICK];
  char hostmask[MAX_MASK_LEN];
  bool is_op;
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

struct chan_t {
  char name[MAX_CHAN];
  char key[MAX_KEY];
  chan_status_t status;
  chan_mode_t modes;
  time_t last_who_request;
  roster_entry_t roster[MAX_ROSTER_SIZE];
  int roster_count;
  time_t last_join_attempt;
  chan_t *next;
};

struct bot_state {
  int server_fd;
  int pid_fd;
  char executable_path[PATH_MAX];
  bot_status_t status;
  char current_nick[MAX_NICK];
  char target_nick[MAX_NICK];
  char bot_pass[MAX_PASS];
  op_mask_t op_masks[MAX_OP_MASKS];
  int op_mask_count;
  char *server_list[MAX_SERVERS + 1];
  char actual_server_name[256];
  int server_count;
  int current_server_index;
  int nick_generation_attempt;
  char *auth_masks[MAX_MASKS + 1];
  int mask_count;
  unsigned long local_ip_long;
  time_t connection_time;
  time_t last_pong_time;
  time_t nick_release_time;
  time_t last_nick_attempt;
  bool pong_pending;
  bool nick_change_pending;
  bool default_server_ignored;
  bool op_request_pending;
  time_t last_op_request_time;
  bool is_ssl;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  log_type_t log_type;
  chan_t *chanlist;
  char ignored_default_channel[MAX_CHAN];
  char ignored_default_mask[MAX_MASK_LEN];
  int ignored_chan_count;
  int chan_count;
  char startup_password[MAX_PASS];
  char bot_comm_pass[MAX_PASS];
  char *trusted_bots[MAX_TRUSTED_BOTS + 1];
  int trusted_bot_count;
  roster_entry_t channel_roster[MAX_ROSTER_SIZE];
  char who_request_channel[MAX_CHAN];
  uint64_t recent_nonces[NONCE_CACHE_SIZE];
  int nonce_idx;
  log_buffer_t in_memory_logs[NUM_LOG_LEVELS];
};

// --- Function Prototypes ---
// main.c
void ssl_init_openssl();
// auth.c
bool auth_verify_password(const char *hash_attempt,
                          const char *stored_password);
bool auth_check_hostmask(const bot_state_t *state, const char *user_host);
bool auth_verify_op_command(const bot_state_t *state, const char *user_host,
                            const char *hash_attempt);
bool auth_is_trusted_bot(const bot_state_t *state, const char *user_host);
// bot.c
void setup_signals(void);
void daemonize(void);
void change_proc_name(int argc, char *argv[]);
void handle_signal(int signum);
// config.c
void config_read(bot_state_t *state, const char *filename);
bool config_load(bot_state_t *state, const char *password,
                 const char *filename);
void config_write(const bot_state_t *state, const char *password);
// channel.c
chan_t *channel_add(bot_state_t *state, const char *name);
bool channel_remove(bot_state_t *state, const char *name);
chan_t *channel_find(const bot_state_t *state, const char *name);
void channel_list_destroy(bot_state_t *state);
void channel_list_reset_status(bot_state_t *state);
void channel_manager_check_joins(bot_state_t *state);
// irc_client.c
void irc_connect(bot_state_t *state);
void irc_disconnect(bot_state_t *state);
int irc_printf(bot_state_t *state, const char *format, ...);
void irc_handle_read(bot_state_t *state);
void irc_check_status(bot_state_t *state);
void irc_attempt_nick_change(bot_state_t *state, const char *new_nick);
void irc_generate_new_nick(bot_state_t *state);
// irc_parser.c
void parser_handle_line(bot_state_t *state, char *line);
// commands.c
void commands_handle_private_message(bot_state_t *state, const char *nick,
                                     const char *user, const char *host,
                                     const char *dest, char *message);
// In bot_comms.c
void bot_comms_send_command(bot_state_t *state, const char *target_nick,
                            const char *format, ...);
// utils.c
void handle_fatal_error(const char *message);
void get_local_ip(bot_state_t *state);
void updater_check_for_updates(bot_state_t *state, const char *nick);
void updater_perform_upgrade(bot_state_t *state, const char *nick, const char *version);
// Function to download the file from the given URL
bool util_download_file(const char *url, const char *path);
// Function to compute the SHA256 hash of a local file
bool util_sha256_file(const char *path, char *output_hash_hex);
// logging.c
void log_message(log_type_t log_type_flag, const bot_state_t *state,
                 const char *format, ...);
// crypto.c
int crypto_aes_gcm_encrypt(const unsigned char *plaintext, int plaintext_len,
                           const unsigned char *key, unsigned char *ciphertext,
                           unsigned char *tag);
int crypto_aes_gcm_decrypt(const unsigned char *ciphertext, int ciphertext_len,
                           const unsigned char *key, unsigned char *plaintext,
                           unsigned char *tag);
#endif  // BOT_H
