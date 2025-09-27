#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "bot.h"

// Include the source files directly to provide their functions to the test
// program. This is only for testing and is not standard practice for a final
// application.
#include "auth.c"
#include "bot.c"  // Needed for signal setup, etc.
#include "channel.c"
#include "commands.c"
#include "dcc.c"  // Needed for dcc_start_listen
#include "irc_client.c"
#include "irc_parser.c"  // Needed for NICK changes
#include "logging.c"
#include "utils.c"

int main(int argc, char *argv[]) {
  if (argc != 4) {
    fprintf(stderr,
            "Usage: %s \"<nick!user@host>\" \"<password>\" \"<command>\"\n",
            argv[0]);
    fprintf(stderr,
            "Example: %s \"trojanc_!~user@host.com\" \"test1\" \"help\"\n",
            argv[0]);
    return 1;
  }

  char *full_host = argv[1];
  char *password = argv[2];
  char *command_str = argv[3];

  // --- Setup a fake bot state ---
  bot_state_t state;
  memset(&state, 0, sizeof(state));
  strncpy(state.current_nick, "trojanc_", MAX_NICK - 1);
  strncpy(state.bot_pass, "test1", MAX_PASS - 1);

  // Add a permissive hostmask for the test
  state.mask_count = 1;
  state.auth_masks[0] = strdup("*!*@*");

  // --- Simulate the incoming message ---
  char incoming_message[MAX_BUFFER];
  // Generate the time-based hash for the given password
  char to_hash[256];
  char hex_hash[65];
  unsigned char raw_hash[SHA256_DIGEST_LENGTH];
  long min = time(NULL) / 60;
  snprintf(to_hash, sizeof(to_hash), "%s:%ld", password, min);
  SHA256((unsigned char *)to_hash, strlen(to_hash), raw_hash);
  for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
    sprintf(hex_hash + (i * 2), "%02x", raw_hash[i]);
  }

  // Construct the full command string as it would be received on IRC
  snprintf(incoming_message, sizeof(incoming_message), "%s %s", hex_hash,
           command_str);

  printf("--- Test Parameters ---\n");
  printf("Bot's Current Nick: %s\n", state.current_nick);
  printf("Testing Hostmask:   %s\n", full_host);
  printf("Input Password:     %s\n", password);
  printf("Input Command:      %s\n", command_str);
  printf("Generated Hash:     %s\n", hex_hash);
  printf("Full Simulated Msg: \"%s\"\n", incoming_message);
  printf("-----------------------\n\n");

  // --- Run the actual command handler ---
  // We need to break up the hostmask to pass to the function
  char *nick = strtok(full_host, "!");
  char *user = strtok(NULL, "@");
  char *host = strtok(NULL, "");

  printf("Calling commands_handle_private_message...\n");
  commands_handle_private_message(&state, nick, user, host, state.current_nick,
                                  incoming_message);
  printf("\nTest complete. Check for log output above this line.\n");

  free(state.auth_masks[0]);
  return 0;
}
