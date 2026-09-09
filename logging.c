#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

#include "bot.h"

static int get_log_index(log_type_t flag) {
  switch (flag) {
    case L_MSG:
      return 0;
    case L_CTCP:
      return 1;
    case L_INFO:
      return 2;
    case L_CMD:
      return 3;
    case L_RAW:
      return 4;
    case L_DEBUG:
      return 5;
    default:
      return -1;
  }
}

void log_message(log_type_t flag, const bot_state_t *state, const char *format,
                 ...) {
  char time_buf[32];
  time_t now = time(NULL);
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));

  char base_message[MAX_LOG_LINE_LEN - 40];
  va_list args;
  va_start(args, format);
  vsnprintf(base_message, sizeof(base_message), format, args);
  va_end(args);

  /* Callers end their format strings with "\n"; strip it so the trailing
   * newline is added exactly once here (and never lands in the ring buffer,
   * where an embedded newline would split the PRIVMSG the .log command sends). */
  for (size_t i = strlen(base_message); i > 0; i--) {
    if (base_message[i - 1] != '\n' && base_message[i - 1] != '\r') break;
    base_message[i - 1] = '\0';
  }

  char full_log_line[MAX_LOG_LINE_LEN];
  snprintf(full_log_line, sizeof(full_log_line), "[%s] %s", time_buf,
           base_message);

  bot_state_t *mutable_state = (bot_state_t *)state;

  int buffer_index = get_log_index(flag);
  if (buffer_index != -1) {
    log_buffer_t *buffer = &mutable_state->in_memory_logs[buffer_index];

    snprintf(buffer->entries[buffer->log_idx].line, MAX_LOG_LINE_LEN, "%s",
             full_log_line);

    buffer->log_idx = (buffer->log_idx + 1) % LOG_BUFFER_LINES;
  }

  if (!(state->log_type & flag)) {
    return;
  }

#ifdef DEBUG
  printf("%s\n", full_log_line);
#endif

  /* Enforce the BOT_LOG_FILE_SIZE ceiling before appending: past the cap the
   * file is truncated rather than allowed to grow without bound. */
  struct stat log_stat;
  if (stat(LOGFILE, &log_stat) == 0 &&
      log_stat.st_size >= (off_t)BOT_LOG_FILE_SIZE) {
    int trunc_fd = open(LOGFILE, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (trunc_fd >= 0) {
      FILE *trunc_stream = fdopen(trunc_fd, "a");
      if (trunc_stream) {
        fprintf(trunc_stream, "[%s] Log file truncated (size limit reached)\n",
                time_buf);
        fclose(trunc_stream);
      } else {
        close(trunc_fd);
      }
    }
  }

  int log_fd = open(LOGFILE, O_WRONLY | O_CREAT | O_APPEND, 0600);
  FILE *stream = (log_fd >= 0) ? fdopen(log_fd, "a") : NULL;
  if (!stream) {
    if (log_fd >= 0) close(log_fd);
    perror("Failed to open log file");
  } else {
    fprintf(stream, "%s\n", full_log_line);
    fclose(stream);
  }
}
