#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <time.h>

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
  printf("%s", full_log_line);
#endif

  FILE *stream = fopen(LOGFILE, "a+");
  if (!stream) {
    perror("Failed to open log file");
  } else {
    fprintf(stream, "%s\n", full_log_line);
    fclose(stream);
  }
}
