#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#include "bot.h"

void log_message(log_type_t flag, const bot_state_t *state, const char *format,
                 ...) {
  if (!(state->log_type & flag)) {
    return;
  }
#ifdef DEBUG
  va_list debug_args;
  va_start(debug_args, format);
  vprintf(format, debug_args);
  va_end(debug_args);
#endif

  FILE *stream = fopen(LOGFILE, "a+");
  if (!stream) {
    perror("Failed to open log file");
    return;
  }

  char time_buf[32];
  time_t now = time(NULL);
  strftime(time_buf, sizeof(time_buf), "%Y-%m-%d %H:%M:%S", localtime(&now));
  fprintf(stream, "[%s] ", time_buf);

  va_list file_args;
  va_start(file_args, format);
  vfprintf(stream, format, file_args);
  va_end(file_args);

  fclose(stream);
}
