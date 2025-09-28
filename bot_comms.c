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
  if (!target_nick || !format || state->bot_comm_pass[0] == '\0') return;

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

  unsigned char key[32];
  EVP_BytesToKey(EVP_aes_256_gcm(), EVP_sha256(), NULL,
                 (const unsigned char *)state->bot_comm_pass,
                 strlen(state->bot_comm_pass), 1, key, NULL);

  int plaintext_len = strlen(plaintext_message);
  unsigned char ciphertext[512 + GCM_IV_LEN];
  unsigned char tag[GCM_TAG_LEN];

  int encrypted_len =
      crypto_aes_gcm_encrypt((unsigned char *)plaintext_message, plaintext_len,
                             key, ciphertext + GCM_IV_LEN, tag);

  if (encrypted_len > 0) {
    char *encoded_ciphertext = base64_encode(ciphertext, encrypted_len);
    char *encoded_tag = base64_encode(tag, GCM_TAG_LEN);

    irc_printf(state, "PRIVMSG %s :%s:%s\r\n", target_nick, encoded_ciphertext,
               encoded_tag);

    free(encoded_ciphertext);
    free(encoded_tag);
  }
}
