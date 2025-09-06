#ifndef BOT_H
#define BOT_H

#include <netinet/in.h>
#include <openssl/err.h>
#include <openssl/ssl.h>
#include <stdbool.h>
#include <stdio.h>
#include <sys/socket.h>
#include <time.h>

#define BOT_NAME "ircbot.c by trojanman"
#define BOT_VERSION "1.0.0"

// Only edit this section
#define DEFAULT_NICK "ircbot"           // Default bot nick
#define DEFAULT_USER "ircbot"           // Default bot user
#define DEFAULT_IRCNAME "ircbot"        // Default bot ircname
#define DEFAULT_BOT_PASS "adminpass"    // Administration password
#define DEFAULT_SERVER "irc.efnet.org"  // Default irc server
#define DEFAULT_CHANNEL "#ircbot"       // Default channel to join
#define DEFAULT_USERMASK "*!*@yourhostmask.com"  // Your hostmask (admin)


// #define OS "Linux"
#define GECOS "ircbot"         // Gecos field storage
#define FAKE_PS "ircbot"       // Renames the process name in "ps" output.
#define CONFIG_FILE ".ircbot"  // Do not change this
#define SALT_SIZE 8            // Do not change this
#define LOGFILE "msg.log"      // Log file name.
// End of edit section

// Timeouts
#define JOIN_RETRY_TIME 10
#define NICK_TAKE_TIME 20
#define NICK_RETRY_TIME 10
#define DEAD_SERVER_TIMEOUT 120
#define CHECK_LAG_TIMEOUT 60
// #define DCC_TIMEOUT 30

// Limits
#define MAX_SERVERS 10
#define MAX_MASKS 20
#define MAX_CHAN 65
#define MAX_BUFFER 512
#define MAX_NICK 10
#define MAX_PASS 128
#define MAX_KEY 31
#define MAX_IGNORED_CHANS 20
#define MAX_MASK_LEN 128
#define MAX_OP_MASKS 20

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
// typedef struct dcc_state_t dcc_state_t;
typedef struct {
  char mask[MAX_MASK_LEN];
  char password[MAX_PASS];
} op_mask_t;

// Struct Definitions
struct chan_t {
  char name[MAX_CHAN];
  char key[MAX_KEY];
  chan_status_t status;
  chan_mode_t modes;
  time_t last_join_attempt;
  chan_t *next;
};

// struct dcc_state_t {
//   int listen_fd;
//   int client_fd;
//   struct sockaddr_in addr;
//   listen_status_t status;
//   char *recv_buffer;
//   time_t last_activity;
// };

struct bot_state {
  int server_fd;
  bot_status_t status;
  char current_nick[MAX_NICK];
  char target_nick[MAX_NICK];
  char bot_pass[MAX_PASS];
  op_mask_t op_masks[MAX_OP_MASKS];
  int op_mask_count;
  //    char snoopy_pass[MAX_PASS];
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
  bool is_ssl;
  SSL_CTX *ssl_ctx;
  SSL *ssl;
  log_type_t log_type;
  chan_t *chanlist;
  char ignored_default_channel[MAX_CHAN];
  char ignored_default_mask[MAX_MASK_LEN];
  int ignored_chan_count;
  int chan_count;
  // dcc_state_t dcc;
  char startup_password[MAX_PASS];
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
// bot.c
void setup_signals(void);
void daemonize(void);
void change_proc_name(int argc, char *argv[]);
void handle_signal(int signum);
// config.c
// non-encrypted: void config_read(bot_state_t *state, const char *filename);
// non-encrypted: void config_write(const bot_state_t *state);
void config_read(bot_state_t *state, const char *filename);
void config_load(bot_state_t *state, const char *password,
                 const char *filename);
void config_write(const bot_state_t *state, const char *password);
// channel.c
chan_t *channel_add(bot_state_t *state, const char *name);
bool channel_remove(bot_state_t *state, const char *name);
chan_t *channel_find(const bot_state_t *state, const char *name);
void channel_list_destroy(bot_state_t *state);
void channel_list_reset_status(bot_state_t *state);
void channel_manager_check_joins(bot_state_t *state);
// dcc.c
// void dcc_init(bot_state_t *state);
// void dcc_kill(bot_state_t *state);
// void dcc_check(bot_state_t *state);
// void dcc_handle_input(bot_state_t *state);
// int dcc_start_listen(bot_state_t *state);
// int dcc_printf(bot_state_t *state, const char *format, ...);
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
// utils.c
void handle_fatal_error(const char *message);
void get_local_ip(bot_state_t *state);
// logging.c
// void log_message(log_type_t log_type_flag, bot_state_t *state, const char
// *format, ...);
void log_message(log_type_t log_type_flag, const bot_state_t *state,
                 const char *format, ...);
#endif  // BOT_H
