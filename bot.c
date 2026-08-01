#include "bot.h"

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

volatile bool g_shutdown_flag = false;

void handle_signal(int signum) {
  (void)signum;
  g_shutdown_flag = true;
}

/* Fatal signals (segfault, abort, etc.) otherwise kill the process via the
 * default action with zero application-level log output, leaving no trail
 * of why the bot went down. Record the signal number with only
 * async-signal-safe calls (open/write/close) - log_message() is unsafe here
 * since it uses vsnprintf/fopen/localtime, which could deadlock if the
 * signal landed while the crashing thread held an internal libc lock (e.g.
 * malloc's) - then restore the default handler and re-raise so the OS still
 * produces its normal core-dump/exit behavior. */
static void handle_fatal_signal(int signum) {
  char msg[64];
  int i = 0;
  const char prefix[] = "[FATAL] Caught signal ";
  for (const char *c = prefix; *c; c++) msg[i++] = *c;
  char digits[8];
  int d = 0;
  int n = signum;
  if (n == 0) digits[d++] = '0';
  while (n > 0) {
    digits[d++] = (char)('0' + (n % 10));
    n /= 10;
  }
  while (d > 0) msg[i++] = digits[--d];
  msg[i++] = ' ';
  msg[i++] = '-';
  msg[i++] = ' ';
  const char suffix[] = "bot terminating.\n";
  for (const char *c = suffix; *c; c++) msg[i++] = *c;

  int fd = open(LOGFILE, O_WRONLY | O_CREAT | O_APPEND, 0600);
  if (fd >= 0) {
    ssize_t written = write(fd, msg, (size_t)i);
    (void)written;
    close(fd);
  }
  signal(signum, SIG_DFL);
  raise(signum);
}

void setup_signals(void) {
  struct sigaction sa;
  memset(&sa, 0, sizeof(sa));
  sa.sa_handler = handle_signal;
  sigemptyset(&sa.sa_mask);
  sa.sa_flags = 0;
  sigaction(SIGINT, &sa, NULL);
  sigaction(SIGTERM, &sa, NULL);
  sa.sa_handler = SIG_IGN;
  sigaction(SIGPIPE, &sa, NULL);

  struct sigaction fsa;
  memset(&fsa, 0, sizeof(fsa));
  fsa.sa_handler = handle_fatal_signal;
  sigemptyset(&fsa.sa_mask);
  fsa.sa_flags = 0;
  sigaction(SIGSEGV, &fsa, NULL);
  sigaction(SIGABRT, &fsa, NULL);
  sigaction(SIGFPE, &fsa, NULL);
  sigaction(SIGBUS, &fsa, NULL);
  sigaction(SIGILL, &fsa, NULL);
}
