#include "bot.h"

#include <fcntl.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

volatile bool g_shutdown_flag = false;

/* Whatever was installed for each fatal signal before we get here - e.g. a
 * sanitizer runtime (ASan/UBSan installs its own SIGSEGV/SIGABRT handler as
 * a constructor, before main() runs) or a debugger. We chain to it after
 * logging so tools like that still get to produce their own diagnostics
 * instead of being silently replaced. */
static struct sigaction g_prev_segv, g_prev_abrt, g_prev_fpe, g_prev_bus,
    g_prev_ill;

void handle_signal(int signum) {
  (void)signum;
  g_shutdown_flag = true;
}

static struct sigaction *prev_action_for(int signum) {
  switch (signum) {
    case SIGSEGV: return &g_prev_segv;
    case SIGABRT: return &g_prev_abrt;
    case SIGFPE:  return &g_prev_fpe;
    case SIGBUS:  return &g_prev_bus;
    case SIGILL:  return &g_prev_ill;
    default:      return NULL;
  }
}

/* Fatal signals (segfault, abort, etc.) otherwise kill the process via the
 * default action with zero application-level log output, leaving no trail
 * of why the bot went down. Record the signal number with only
 * async-signal-safe calls (open/write/close) - log_message() is unsafe here
 * since it uses vsnprintf/fopen/localtime, which could deadlock if the
 * signal landed while the crashing thread held an internal libc lock (e.g.
 * malloc's) - then chain to whatever handler was previously installed (see
 * prev_action_for() above), falling back to the default action so the OS
 * still produces its normal core-dump/exit behavior if nothing else claims
 * the signal. */
static void handle_fatal_signal(int signum, siginfo_t *info, void *ucontext) {
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

  struct sigaction *prev = prev_action_for(signum);
  if (prev) {
    if ((prev->sa_flags & SA_SIGINFO) && prev->sa_sigaction) {
      prev->sa_sigaction(signum, info, ucontext);
    } else if (prev->sa_handler != SIG_DFL && prev->sa_handler != SIG_IGN &&
               prev->sa_handler != NULL) {
      prev->sa_handler(signum);
    }
  }
  /* Still here? Whatever was chained above didn't terminate us (or nothing
   * was chained - the normal case for a production build). Fall back to the
   * default action. */
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
  fsa.sa_sigaction = handle_fatal_signal;
  sigemptyset(&fsa.sa_mask);
  fsa.sa_flags = SA_SIGINFO;
  sigaction(SIGSEGV, &fsa, &g_prev_segv);
  sigaction(SIGABRT, &fsa, &g_prev_abrt);
  sigaction(SIGFPE, &fsa, &g_prev_fpe);
  sigaction(SIGBUS, &fsa, &g_prev_bus);
  sigaction(SIGILL, &fsa, &g_prev_ill);
}
