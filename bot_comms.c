#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <string.h>

#include "bot.h"

static char *base64_encode(const unsigned char *input, int length) {
  BIO *b64 = BIO_new(BIO_f_base64());
  BIO *bio = BIO_new(BIO_s_mem());
  bio = BIO_push(b64, bio);
  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bio, input, length);
  BIO_flush(bio);
  BUF_MEM *bufferPtr;
  BIO_get_mem_ptr(bio, &bufferPtr);
  char *buff = (char *)malloc(bufferPtr->length + 1);
  memcpy(buff, bufferPtr->data, bufferPtr->length);
  buff[bufferPtr->length] = 0;
  BIO_free_all(bio);
  return buff;
}

void bot_comms_send_command(bot_state_t *state, const char *target_nick,
                            const char *format, ...) {
  if (!target_nick || !format || state->bot_comm_pass[0] == '\0') {
    return;
  }

  char command_part[256];
  va_list args;
  va_start(args, format);
  vsnprintf(command_part, sizeof(command_part), format, args);
  va_end(args);

  char plaintext_message[512];
  time_t current_time = time(NULL);
  uint64_t nonce;
  RAND_bytes((unsigned char *)&nonce, sizeof(nonce));

  snprintf(plaintext_message, sizeof(plaintext_message), "%ld:%llu:%s",
           current_time, (unsigned long long)nonce, command_part);

  unsigned char *encrypted_data = NULL;
  int encrypted_len = crypto_aes_encrypt_decrypt(
      true, state->bot_comm_pass, (const unsigned char *)plaintext_message,
      strlen(plaintext_message), &encrypted_data);

  if (encrypted_len > 0) {
    char *encoded_data = base64_encode(encrypted_data, encrypted_len);
    if (encoded_data) {
      irc_printf(state, "PRIVMSG %s :%s\r\n", target_nick, encoded_data);
      free(encoded_data);
    }
    free(encrypted_data);
  }
}

void bot_comms_send_command_bak(bot_state_t *state, const char *target_nick,
                                const char *command, const char *channel) {
  if (!target_nick || !command || !channel || state->bot_comm_pass[0] == '\0') {
    return;
  }

  char plaintext_command[256];
  time_t current_time = time(NULL);
  uint64_t nonce;
  RAND_bytes((unsigned char *)&nonce, sizeof(nonce));

  snprintf(plaintext_command, sizeof(plaintext_command), "%ld:%llu:%s %s",
           current_time, (unsigned long long)nonce, command, channel);

  unsigned char *encrypted_data = NULL;
  int encrypted_len = crypto_aes_encrypt_decrypt(
      true, state->bot_comm_pass, (const unsigned char *)plaintext_command,
      strlen(plaintext_command), &encrypted_data);

  if (encrypted_len > 0) {
    char *encoded_data = base64_encode(encrypted_data, encrypted_len);
    if (encoded_data) {
      irc_printf(state, "PRIVMSG %s :%s\r\n", target_nick, encoded_data);
      free(encoded_data);
    }
    free(encrypted_data);
  }
}
