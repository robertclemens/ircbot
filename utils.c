#include <arpa/inet.h>
#include <ctype.h>
#ifdef HAVE_CURL
#include <curl/curl.h>
#include <dirent.h>
#endif
#include <netdb.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/sha.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <errno.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/utsname.h>
#include <sys/wait.h>
#include <signal.h>
#include <time.h>
#include <fcntl.h>
#include <unistd.h>

#include "bot.h"

void bot_set_startup_pass(bot_state_t *s, const char *pass) {
  /* Store plaintext and lock the page into RAM so it cannot be swapped.
   * See the threat-model comment on bot_state_t.startup_password in bot.h. */
  size_t n = pass ? strlen(pass) : 0;
  if (n >= MAX_PASS) n = MAX_PASS - 1;
  memcpy(s->startup_password, pass ? pass : "", n);
  memset(s->startup_password + n, 0, MAX_PASS - n);
  mlock(s->startup_password, MAX_PASS);
}

void bot_get_startup_pass(const bot_state_t *s, char out[MAX_PASS]) {
  memcpy(out, s->startup_password, MAX_PASS);
  out[MAX_PASS - 1] = '\0';
}

bool bot_has_startup_pass(const bot_state_t *s) {
  return s->startup_password[0] != '\0';
}

void config_write_with_state_pass(bot_state_t *s) {
  char pass[MAX_PASS];
  bot_get_startup_pass(s, pass);
  config_write(s, pass);
  OPENSSL_cleanse(pass, MAX_PASS);
}

void config_write_local_with_state_pass(bot_state_t *s) {
  char pass[MAX_PASS];
  bot_get_startup_pass(s, pass);
  config_write_local(s, pass);
  OPENSSL_cleanse(pass, MAX_PASS);
}

_Noreturn void handle_fatal_error(const char *message) {
  perror(message);
  exit(EXIT_FAILURE);
}


/* ---- Host capability probe (used by the hub-driven upgrade path) --------
 * Both answers describe the RUNNING binary, not the machine's capabilities in
 * the abstract: a bot reports what it can be replaced with.  The arch comes
 * from uname(2) so it matches the manifest's `uname -m` spelling; the libc is
 * decided at compile time because the binary is already linked against one and
 * musl publishes no runtime identifier. */
void updater_host_arch(char *out, size_t out_size) {
  if (!out || out_size == 0) return;
  struct utsname u;
  if (uname(&u) == 0 && u.machine[0]) {
    size_t n = strnlen(u.machine, out_size - 1);
    memcpy(out, u.machine, n);
    out[n] = '\0';
  } else {
    snprintf(out, out_size, "unknown");
  }
}

void updater_host_libc(char *out, size_t out_size) {
  if (!out || out_size == 0) return;
#if defined(__GLIBC__)
  snprintf(out, out_size, "gnu");
#elif defined(__linux__)
  snprintf(out, out_size, "musl");
#else
  snprintf(out, out_size, "unknown");
#endif
}

/* The variant this binary was built from.  The Rust twin answers "rs"; both
 * are wire- and config-compatible, so a node may be flipped either way. */
const char *updater_host_variant(void) { return "c"; }

static int local_strverscmp(const char *s1, const char *s2) {
  const unsigned char *p1 = (const unsigned char *)s1;
  const unsigned char *p2 = (const unsigned char *)s2;
  int state;
  unsigned char c1, c2;

  while ((c1 = *p1++) == (c2 = *p2++)) {
    if (c1 == '\0') return 0;
  }
  p1--;
  p2--;

  if (isdigit(c1) && isdigit(c2)) {
    state = 0;
    while (1) {
      if (state == 0) {
        if (c1 > c2)
          state = 1;
        else if (c1 < c2)
          state = -1;
      }
      if (!isdigit(*p1))
        c1 = 0;
      else
        c1 = *p1++;
      if (!isdigit(*p2))
        c2 = 0;
      else
        c2 = *p2++;
      if (!c1 && !c2) break;
      if (c1 == 0 && c2 != 0) return -1;
      if (c1 != 0 && c2 == 0) return 1;
    }
    return state;
  }
  return (int)p1[0] - (int)p2[0];
}

/* Release manifests spell versions with a leading 'v' ("v2.3.0") while
 * BOT_VERSION does not ("2.3.0"), and an admin may type either.  Compare them
 * on the numeric part alone: local_strverscmp("v0.0.1", "2.3.0") would
 * otherwise compare 'v' against '2' and report a downgrade as an upgrade,
 * which is exactly what the downgrade guard exists to stop. */
static const char *version_strip_v(const char *v) {
  if (!v) return "";
  return (*v == 'v' || *v == 'V') ? v + 1 : v;
}

/* Exported: the hub-upgrade handlers in hub_client.c compare the target
 * and min_from versions the hub sends against BOT_VERSION. */
int updater_version_cmp(const char *a, const char *b) {
  return local_strverscmp(version_strip_v(a), version_strip_v(b));
}

#ifdef HAVE_CURL /* only the curl-based updater compares for equality */
static bool version_eq(const char *a, const char *b) {
  return strcasecmp(version_strip_v(a), version_strip_v(b)) == 0;
}
#endif

/* ---- Upgrade hand-off marker -------------------------------------------
 * exec() throws away everything the old process knew, so the upgrade id and
 * the version we were aiming at are left in a file for the new binary to
 * find.  It is read exactly once, on the first authenticated hub link after
 * the restart, and removed there — see hub_client_report_upgrade_result(). */
bool upgrade_marker_write(const char *upgrade_id, const char *target_ver,
                          const char *variant, const char *ops) {
  if (!upgrade_id || !target_ver || !variant || !ops) return false;
  int fd = open(UPGRADE_MARKER_FILE, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC,
                0600);
  if (fd < 0) return false;
  char line[256 + UPGRADE_OPS_MAX];
  /* Line 1: id|version|variant.  The variant is what makes a C<->Rust switch
   * at the same version checkable: without it the old build, restored by the
   * script's watchdog, would read the marker and report "ok".
   * Line 2: "ops #a #b" — the channels this bot is opped in now; the new
   * build reports done only once it is re-opped in each.  Older builds read
   * line 1 only. */
  int n = snprintf(line, sizeof(line), "%s|%s|%s\nops%s%s\n", upgrade_id,
                   target_ver, variant, ops[0] ? " " : "", ops);
  bool ok = (n > 0 && n < (int)sizeof(line) && write(fd, line, (size_t)n) == n);
  if (close(fd) != 0) ok = false;
  if (!ok) remove(UPGRADE_MARKER_FILE);
  return ok;
}

/* Read and consume the marker.  Returns false when no upgrade is pending,
 * which is the normal case for every ordinary start. */
bool updater_take_pending_upgrade(char *id_out, size_t id_size, char *ver_out,
                                  size_t ver_size, char *variant_out,
                                  size_t variant_size, char *ops_out,
                                  size_t ops_size) {
  if (!id_out || !ver_out || !variant_out || !ops_out || id_size == 0 ||
      ver_size == 0 || variant_size == 0 || ops_size == 0)
    return false;
  id_out[0] = ver_out[0] = variant_out[0] = ops_out[0] = '\0';

  FILE *f = fopen(UPGRADE_MARKER_FILE, "r");
  if (!f) return false;
  char line[256] = "";
  char ops_line[UPGRADE_OPS_MAX + 8] = "";
  bool got = (fgets(line, sizeof(line), f) != NULL);
  if (got && fgets(ops_line, sizeof(ops_line), f) &&
      strncmp(ops_line, "ops", 3) == 0 &&
      (ops_line[3] == ' ' || ops_line[3] == '\r' || ops_line[3] == '\n' ||
       ops_line[3] == '\0')) {
    /* "ops" alone (nothing opped) or "ops #a #b"; the Rust twin writes the
     * same, so a C<->Rust switch reads either. */
    ops_line[strcspn(ops_line, "\r\n")] = '\0';
    const char *p = ops_line + 3;
    while (*p == ' ') p++;
    snprintf(ops_out, ops_size, "%s", p);
  }
  fclose(f);
  /* Consumed whatever it said: a marker we cannot parse must not be retried
   * on every reconnect for the rest of this process's life. */
  remove(UPGRADE_MARKER_FILE);
  if (!got) return false;

  char id[64] = "", ver[64] = "", variant[16] = "";
  if (sscanf(line, "%63[^|\r\n]|%63[^|\r\n]|%15[^|\r\n]", id, ver,
             variant) < 2)
    return false;
  if (!id[0] || !ver[0]) return false;
  snprintf(id_out, id_size, "%s", id);
  snprintf(ver_out, ver_size, "%s", ver);
  snprintf(variant_out, variant_size, "%s", variant);
  return true;
}

/* ---- Failback ----------------------------------------------------------
 * A node must recover by itself: its admin may have no shell on the host.  One
 * script decides, called from two places: the upgrade script's background loop
 * every 10 s, and a temporary crontab line every minute, which outlives a reboot
 * or a killed loop.  It holds no secrets, and removes itself and the line once
 * the new build confirms or the old one is back.  The body is the same text in
 * all four trees: ircbot, ircbot.rs, irchub, irchub.rs. */
#define FAILBACK_FILE ".upgrade.failback"
#define FAILBACK_STATE ".upgrade.state"
#define FAILBACK_CONFIRM ".upgrade.confirmed"
#define CRON_HELPER ".cron.helper"

static const char *const FAILBACK_BODY[] = {
  "umask 077\n",
  "PATH=\"${PATH:-}:/usr/bin:/bin\"; export PATH\n",
  "cd \"$D\" 2>/dev/null || exit 1\n",
  "STATE=.upgrade.state; CONF=.upgrade.confirmed; SELF=${SELF:-.upgrade.failback}\n",
  "LOCK=.upgrade.lock; TRIES=.upgrade.tries; PREV=\"$EXE.prev\"\n",
  "FAILTAG=\"# $PRODUCT:failback:$D:\"; PRODTAG=\"# $PRODUCT:production:$D:\"\n",
  "# A hardened daemon is not dumpable, so its /proc/<pid>/exe cannot be read: the\n",
  "# pid file and the process name say whether it is ours.\n",
  "COMM=$(basename \"$EXE\" | cut -c1-15)\n",
  "HLOCK=\"${HOME:-$D}/.irc-cron.lock\"\n",
  "HELD=\"\"\n",
  "\n",
  "take_lock() {\n",
  "  i=0\n",
  "  while :; do\n",
  "    if ( set -C; echo $$ >\"$1\" ) 2>/dev/null; then HELD=\"$HELD $1\"; return 0; fi\n",
  "    h=$(cat \"$1\" 2>/dev/null)\n",
  "    if [ -n \"$h\" ] && kill -0 \"$h\" 2>/dev/null; then\n",
  "      i=$((i + 1)); [ \"$i\" -ge \"$2\" ] && return 1\n",
  "      sleep 1\n",
  "    else\n",
  "      rm -f \"$1\"\n",
  "    fi\n",
  "  done\n",
  "}\n",
  "drop_locks() { for l in $HELD; do rm -f \"$l\"; done; HELD=\"\"; }\n",
  "trap drop_locks EXIT\n",
  "\n",
  "clean() { printf '%s' \"$1\" | tr -d '|\\r\\n' | cut -c1-160; }\n",
  "set_state() { # phase pid note\n",
  "  printf '%s|%s|%s|%s|%s\\n' \"$ID\" \"$1\" \"$(date +%s)\" \"$2\" \"$(clean \"$3\")\" >\"$STATE.tmp\" &&\n",
  "    mv -f \"$STATE.tmp\" \"$STATE\"\n",
  "}\n",
  "read_state() {\n",
  "  rid=\"\"; phase=\"\"; since=0; spid=\"\"; note=\"\"\n",
  "  [ -f \"$STATE\" ] || return 1\n",
  "  IFS='|' read -r rid phase since spid note <\"$STATE\" || return 1\n",
  "  [ \"$rid\" = \"$ID\" ]\n",
  "}\n",
  "pid_now() { [ -f \"$PIDF\" ] && tr -dc 0-9 <\"$PIDF\"; }\n",
  "alive() {\n",
  "  p=$(pid_now)\n",
  "  [ -n \"$p\" ] && kill -0 \"$p\" 2>/dev/null && [ \"$(cat \"/proc/$p/comm\" 2>/dev/null)\" = \"$COMM\" ]\n",
  "}\n",
  "start_exe() { \"$EXE\" </dev/null >/dev/null 2>&1 & }\n",
  "\n",
  "# Read, change, write, read back, compare.  Only an answer that says there is\n",
  "# no crontab counts as empty: any other read error writes nothing, so a bad read\n",
  "# can never wipe an admin's jobs.  Only a line holding this tag changes, along with\n",
  "# tagged lines whose directory is gone; every other line stays as it was.\n",
  "cron_read() { # file\n",
  "  if ! crontab -l >\"$1\" 2>\"$1.err\"; then\n",
  "    grep -Eqi 'no crontab|no such file|does not exist' \"$1.err\" || return 1\n",
  "    : >\"$1\"\n",
  "  fi\n",
  "}\n",
  "cron_sweep() { # in out\n",
  "  sed -nE 's/.*# (ircbot|irchub):(production|failback):(\\/[^:]*):$/\\3/p' \"$1\" |\n",
  "    while read -r dd; do [ -d \"$dd\" ] || printf ':%s:\\n' \"$dd\"; done >\"$2.dead\"\n",
  "  if [ -s \"$2.dead\" ]; then grep -vF -f \"$2.dead\" \"$1\" >\"$2\"; else cp \"$1\" \"$2\"; fi\n",
  "}\n",
  "cron_edit() { # add|remove tag line\n",
  "  command -v crontab >/dev/null 2>&1 || return 3\n",
  "  take_lock \"$HLOCK\" 15 || return 1\n",
  "  T=\".upgrade.cron.$$\"; rc=1; n=0\n",
  "  while [ \"$n\" -lt 3 ]; do\n",
  "    n=$((n + 1))\n",
  "    cron_read \"$T.cur\" || break\n",
  "    if [ \"$1\" = remove ] && ! grep -qF \"$2\" \"$T.cur\"; then rc=0; break; fi\n",
  "    if [ \"$1\" = add ] && grep -qF \"$2\" \"$T.cur\"; then rc=0; break; fi\n",
  "    cron_sweep \"$T.cur\" \"$T.swept\"\n",
  "    grep -vF \"$2\" \"$T.swept\" >\"$T.rest\"\n",
  "    cp \"$T.rest\" \"$T.new\"\n",
  "    [ \"$1\" = add ] && printf '%s\\n' \"$3\" >>\"$T.new\"\n",
  "    crontab \"$T.new\" >/dev/null 2>&1 || { sleep 1; continue; }\n",
  "    crontab -l >\"$T.chk\" 2>/dev/null\n",
  "    grep -vF \"$2\" \"$T.chk\" | grep -v '^# \\(DO NOT EDIT\\|(\\)' >\"$T.a\"\n",
  "    grep -v '^# \\(DO NOT EDIT\\|(\\)' \"$T.rest\" >\"$T.b\"\n",
  "    if cmp -s \"$T.a\" \"$T.b\"; then\n",
  "      if [ \"$1\" = add ]; then grep -qF \"$2\" \"$T.chk\" && { rc=0; break; }\n",
  "      else grep -qF \"$2\" \"$T.chk\" || { rc=0; break; }; fi\n",
  "    fi\n",
  "    sleep 1\n",
  "  done\n",
  "  rm -f \"$T\".*\n",
  "  rm -f \"$HLOCK\"; HELD=$(printf '%s' \"$HELD\" | sed \"s| $HLOCK||\")\n",
  "  return \"$rc\"\n",
  "}\n",
  "fail_line() {\n",
  "  printf \"* * * * * [ -x '%s/%s' ] && '%s/%s' tick >/dev/null 2>&1 %s\\n\" \\\n",
  "    \"$D\" \"$SELF\" \"$D\" \"$SELF\" \"$FAILTAG\"\n",
  "}\n",
  "prod_line() {\n",
  "  printf \"*/5 * * * * touch '%s/.cron.seen'; [ -x '%s' ] && '%s' >/dev/null 2>&1 %s\\n\" \\\n",
  "    \"$D\" \"$EXE\" \"$EXE\" \"$PRODTAG\"\n",
  "}\n",
  "# What this instance's production line is: 0 ours, 10 a hand-written line runs\n",
  "# this binary, 11 none, 3 no crontab tool, 1 it cannot be read.\n",
  "cron_status() {\n",
  "  command -v crontab >/dev/null 2>&1 || return 3\n",
  "  T=\".upgrade.cron.$$\"\n",
  "  cron_read \"$T.st\" || { rm -f \"$T\".*; return 1; }\n",
  "  rc=11\n",
  "  if grep -qF \"$PRODTAG\" \"$T.st\"; then rc=0\n",
  "  elif grep -vE '^[[:space:]]*#' \"$T.st\" | grep -qF \"$EXE\"; then rc=10\n",
  "  fi\n",
  "  rm -f \"$T\".*\n",
  "  return \"$rc\"\n",
  "}\n",
  "safe_path() { case \"$D\" in *[!A-Za-z0-9._/-]*) return 1 ;; esac; }\n",
  "\n",
  "# keep = leave the state file, for the build that has to report it\n",
  "finish() {\n",
  "  cron_edit remove \"$FAILTAG\"\n",
  "  [ \"${1:-}\" = keep ] || rm -f \"$STATE\"\n",
  "  rm -f \"$CONF\" \"$TRIES\" \"$SELF\" \"./$SCRIPT\"\n",
  "  drop_locks\n",
  "  exit 1\n",
  "}\n",
  "\n",
  "restore() { # reason\n",
  "  read_state\n",
  "  [ -n \"$spid\" ] && [ \"$spid\" != \"$PPID\" ] && [ \"$spid\" != \"$$\" ] && kill \"$spid\" 2>/dev/null\n",
  "  if alive; then\n",
  "    p=$(pid_now); kill \"$p\" 2>/dev/null\n",
  "    i=0\n",
  "    while kill -0 \"$p\" 2>/dev/null && [ \"$i\" -lt 5 ]; do sleep 1; i=$((i + 1)); done\n",
  "    kill -9 \"$p\" 2>/dev/null\n",
  "  fi\n",
  "  if [ ! -f \"$PREV\" ]; then\n",
  "    [ -x \"$EXE\" ] && ! alive && start_exe\n",
  "    set_state failback-gave-up \"\" \"$1; no previous build retained\"\n",
  "    return\n",
  "  fi\n",
  "  mv -f \"$EXE\" \"$EXE.failed\" 2>/dev/null\n",
  "  if ! mv -f \"$PREV\" \"$EXE\"; then\n",
  "    mv -f \"$EXE.failed\" \"$EXE\" 2>/dev/null\n",
  "    set_state failback-gave-up \"\" \"$1; could not restore the previous build\"\n",
  "    return\n",
  "  fi\n",
  "  [ -f \"$CFG.prev\" ] && cp -f \"$CFG.prev\" \"$CFG\"\n",
  "  rm -f \"$PIDF\"\n",
  "  set_state restored \"\" \"$1\"\n",
  "  start_exe\n",
  "}\n",
  "\n",
  "tick() {\n",
  "  read_state || finish\n",
  "  now=$(date +%s); age=$((now - since))\n",
  "  if [ \"$now\" -ge \"$HARD\" ]; then\n",
  "    case \"$phase\" in\n",
  "      restored|failback-gave-up) ;;\n",
  "      *) set_state failback-gave-up \"\" \"the upgrade never finished\" ;;\n",
  "    esac\n",
  "    finish keep\n",
  "  fi\n",
  "  case \"$phase\" in\n",
  "    installing)\n",
  "      if ! kill -0 \"$spid\" 2>/dev/null; then restore \"the install was interrupted\"\n",
  "      elif [ \"$age\" -ge \"$INSTALL_LIMIT\" ]; then restore \"the install took over $INSTALL_LIMIT s\"\n",
  "      fi ;;\n",
  "    started)\n",
  "      if [ -f \"$CONF\" ] && [ \"$(cat \"$CONF\" 2>/dev/null)\" = \"$ID\" ] && alive; then finish\n",
  "      elif ! alive; then\n",
  "        [ \"$age\" -ge \"$WATCH\" ] && restore \"the new build did not stay up\"\n",
  "      elif [ \"$age\" -ge \"$CONFIRM_LIMIT\" ]; then restore \"$NOTE within $CONFIRM_LIMIT s\"\n",
  "      fi ;;\n",
  "    restored)\n",
  "      alive && finish keep\n",
  "      t=$(cat \"$TRIES\" 2>/dev/null); t=$((${t:-0} + 1)); echo \"$t\" >\"$TRIES\"\n",
  "      if [ \"$t\" -ge 5 ]; then\n",
  "        set_state failback-gave-up \"\" \"$note; the previous build will not start\"\n",
  "        finish keep\n",
  "      fi\n",
  "      start_exe ;;\n",
  "    failback-gave-up) finish keep ;;\n",
  "    *) finish ;;\n",
  "  esac\n",
  "  return 0\n",
  "}\n",
  "\n",
  "# The cron-* arguments are a one-shot helper's: it runs once and removes itself.\n",
  "case \"${1:-tick}\" in\n",
  "  install)\n",
  "    safe_path || exit 3\n",
  "    cron_edit add \"$FAILTAG\" \"$(fail_line)\"; exit $? ;;\n",
  "  phase) take_lock \"$LOCK\" 20 && set_state \"$2\" \"$3\" \"\" ;;\n",
  "  restore) take_lock \"$LOCK\" 20 && restore \"$2\" ;;\n",
  "  done) take_lock \"$LOCK\" 20; finish ;;\n",
  "  tick) take_lock \"$LOCK\" 2 || exit 0; tick ;;\n",
  "  cron-status) cron_status; rc=$?; rm -f \"$SELF\"; exit \"$rc\" ;;\n",
  "  cron-on)\n",
  "    cron_status; rc=$?\n",
  "    if [ \"$rc\" = 11 ]; then\n",
  "      if safe_path; then\n",
  "        touch .cron.seen\n",
  "        cron_edit add \"$PRODTAG\" \"$(prod_line)\" && cron_status; rc=$?\n",
  "      else\n",
  "        rc=4\n",
  "      fi\n",
  "    fi\n",
  "    rm -f \"$SELF\"; exit \"$rc\" ;;\n",
  "  cron-off)\n",
  "    rc=0\n",
  "    cron_edit remove \"$PRODTAG\" || rc=$?\n",
  "    if [ \"$rc\" = 0 ]; then rm -f .cron.seen; cron_status; rc=$?; fi\n",
  "    rm -f \"$SELF\"; exit \"$rc\" ;;\n",
  "  cron-drop)\n",
  "    rc=0\n",
  "    cron_edit remove \"$PRODTAG\" || rc=$?\n",
  "    cron_edit remove \"$FAILTAG\" || rc=$?\n",
  "    if [ \"$rc\" = 0 ]; then\n",
  "      cron_status; [ $? = 10 ] && rc=10\n",
  "    fi\n",
  "    rm -f \"$SELF\" .cron.seen; exit \"$rc\" ;;\n",
  "esac\n",
  "exit 0\n"
};

/* A value for the script's header: single-quoted, so nothing in a path expands */
static void failback_quoted(FILE *f, const char *name, const char *value) {
  fprintf(f, "%s='", name);
  for (const char *p = value; *p; p++) {
    if (*p == '\'') fputs("'\\''", f);
    else fputc(*p, f);
  }
  fputs("'\n", f);
}

/* The script, for one upgrade (FAILBACK_FILE) or one crontab change (CRON_HELPER). */
static bool failback_write(const char *path, const char *exe, const char *id, bool is_bin,
                           const char *cfg, const char *pidf, const char *script,
                           const char *note, const char *self) {
  char dir[PATH_MAX];
  snprintf(dir, sizeof(dir), "%s", exe);
  char *slash = strrchr(dir, '/');
  if (!slash) return false;
  *slash = '\0';
  int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
  FILE *f = fd >= 0 ? fdopen(fd, "w") : NULL;
  if (!f) {
    if (fd >= 0) close(fd);
    return false;
  }
  int install = is_bin ? UPGRADE_INSTALL_SECS : UPGRADE_BUILD_SECS;
  fputs("#!/bin/sh\n", f);
  fputs("# Written by ircbot: removes itself.  See its README.\n", f);
  failback_quoted(f, "PRODUCT", "ircbot");
  failback_quoted(f, "SELF", self);
  failback_quoted(f, "D", dir);
  failback_quoted(f, "EXE", exe);
  failback_quoted(f, "ID", id);
  failback_quoted(f, "CFG", cfg);
  failback_quoted(f, "PIDF", pidf);
  failback_quoted(f, "SCRIPT", script);
  failback_quoted(f, "NOTE", note);
  fprintf(f, "INSTALL_LIMIT=%d\nCONFIRM_LIMIT=%d\nWATCH=%d\nHARD=%lld\n", install,
          UPGRADE_CONFIRM_SECS, UPGRADE_WATCH_SECS,
          (long long)time(NULL) + install + UPGRADE_CONFIRM_SECS + UPGRADE_FAILBACK_EXPIRY);
  for (size_t i = 0; i < sizeof(FAILBACK_BODY) / sizeof(FAILBACK_BODY[0]); i++)
    fputs(FAILBACK_BODY[i], f);
  (void)fchmod(fileno(f), 0700);
  if (fclose(f) != 0) {
    remove(path);
    return false;
  }
  return true;
}

/* Run the script with one argument; its exit status, -1 if it could not run. */
static int failback_run(const char *arg) {
  pid_t pid = fork();
  if (pid < 0) return -1;
  if (pid == 0) {
    for (int fd = 3; fd < 1024; fd++) close(fd);
    execl("./" FAILBACK_FILE, "./" FAILBACK_FILE, arg, (char *)NULL);
    _exit(127);
  }
  int st = 0;
  if (waitpid(pid, &st, 0) != pid || !WIFEXITED(st)) return -1;
  return WEXITSTATUS(st);
}

/* Takes the upgrade back out of cron and off the disk. */
static void failback_clear(void) {
  if (access(FAILBACK_FILE, X_OK) == 0) (void)failback_run("done");
  remove(FAILBACK_STATE);
  remove(FAILBACK_CONFIRM);
}

/* The new build is up and has proved it can do its job. */
void updater_failback_confirm(void) {
  char line[256];
  FILE *f = fopen(FAILBACK_STATE, "r");
  if (!f) return;
  bool got = fgets(line, sizeof(line), f) != NULL;
  fclose(f);
  if (!got) return;
  char *phase = strchr(line, '|');
  if (!phase) return;
  *phase++ = '\0';
  if (strncmp(phase, "started|", 8) != 0) return;
  char tmp[64];
  snprintf(tmp, sizeof(tmp), "%s.tmp", FAILBACK_CONFIRM);
  f = fopen(tmp, "w");
  if (!f) return;
  fprintf(f, "%s\n", line);
  if (fclose(f) == 0) (void)rename(tmp, FAILBACK_CONFIRM);
}

/* Why this build is running instead of the one asked for: the note the script
 * wrote when it restored it.  Taken once. */
bool updater_failback_note(char *out, size_t out_size) {
  char line[256];
  out[0] = '\0';
  FILE *f = fopen(FAILBACK_STATE, "r");
  if (!f) return false;
  bool got = fgets(line, sizeof(line), f) != NULL;
  fclose(f);
  if (!got) return false;
  line[strcspn(line, "\r\n")] = '\0';
  char *phase = strchr(line, '|');
  if (!phase) return false;
  phase++;
  if (strncmp(phase, "restored|", 9) != 0 &&
      strncmp(phase, "failback-gave-up|", 17) != 0)
    return false;
  char *note = strrchr(phase, '|');
  if (!note || !note[1]) return false;
  snprintf(out, out_size, "%s", note + 1);
  remove(FAILBACK_STATE);
  return true;
}

/* A bot with no hub: there is no link to report on, so the first time it is on IRC
 * it settles its own upgrade.  Once per process. */
void updater_standalone_tick(bot_state_t *state) {
  static bool done = false;
  if (done || state->hub_count != 0 || !(state->status & S_AUTHED)) return;
  done = true;
  char id[64], want[64], want_variant[16], ops[UPGRADE_OPS_MAX];
  if (!updater_take_pending_upgrade(id, sizeof(id), want, sizeof(want), want_variant,
                                    sizeof(want_variant), ops, sizeof(ops)))
    return;
  if (updater_version_cmp(BOT_VERSION, want) == 0) {
    updater_failback_confirm();
    log_message(L_INFO, state, "[UPGRADE] Now running %s\n", BOT_VERSION);
    return;
  }
  char note[192];
  if (!updater_failback_note(note, sizeof(note))) snprintf(note, sizeof(note), "reason unknown");
  log_message(L_INFO, state, "[UPGRADE] The upgrade to %s did not hold, back on %s: %s\n", want,
              BOT_VERSION, note);
}

/* ---- Production crontab line --------------------------------------------
 * An instance's keepalive line, tagged "# <product>:production:<dir>:".  Off
 * unless a hub says otherwise, and only ever this one tagged line: everything
 * else in the crontab is read and left alone.  The script runs as a child, so a
 * slow crontab never holds up the event loop. */
static pid_t g_cron_pid = 0;
static time_t g_cron_started = 0, g_cron_next = 0, g_cron_stat = 0;
static int g_cron_wanted = -1;  /* -1 no hub has said, 0 off, 1 on */
static char g_cron_status[64] = "";
static bool g_cron_ours = false;

static const char *cron_helper_run_arg(const char *exe, const char **fail) {
  *fail = NULL;
  if (g_cron_wanted == 1 && access(PASS_FILE, F_OK) != 0) {
    *fail = "no .ircbot.pass";
    return NULL;
  }
  if (!failback_write(CRON_HELPER, exe, "", true, CONFIG_FILE, PID_FILE, "upgrade.sh", "",
                      CRON_HELPER)) {
    *fail = "cannot write here";
    return NULL;
  }
  return g_cron_wanted == 1 ? "cron-on" : g_cron_wanted == 0 ? "cron-off" : "cron-status";
}

static void cron_note(int rc, time_t now) {
  char next[sizeof(g_cron_status)];
  g_cron_ours = rc == 0;
  if (rc == 0) snprintf(next, sizeof(next), "yes");
  else if (rc == 10) snprintf(next, sizeof(next), "manual");
  else if (rc == 11 || g_cron_wanted != 1) snprintf(next, sizeof(next), "no");
  else if (rc == 3) snprintf(next, sizeof(next), "failed:no crontab tool");
  else if (rc == 4) snprintf(next, sizeof(next), "failed:unsafe path");
  else snprintf(next, sizeof(next), "failed:cannot read crontab");
  snprintf(g_cron_status, sizeof(g_cron_status), "%s", next);
  g_cron_stat = now;
}

/* What updater_cron_tick last found: yes, silent, manual, no or failed:<why>. */
const char *updater_cron_status(void) { return g_cron_status; }

/* A hub's order. */
void updater_cron_set(bool on) {
  int want = on ? 1 : 0;
  if (want != g_cron_wanted) g_cron_next = 0;
  g_cron_wanted = want;
}

/* True when the status changed, so the hub should hear it. */
bool updater_cron_tick(const char *exe) {
  time_t now = time(NULL);
  char before[sizeof(g_cron_status)];
  snprintf(before, sizeof(before), "%s", g_cron_status);
  if (g_cron_pid > 0) {
    int st = 0;
    pid_t r = waitpid(g_cron_pid, &st, WNOHANG);
    if (r == 0) {
      if (now - g_cron_started > CRON_HELPER_TIMEOUT) kill(g_cron_pid, SIGKILL);
      return false;
    }
    g_cron_pid = 0;
    remove(CRON_HELPER);
    cron_note(r > 0 && WIFEXITED(st) ? WEXITSTATUS(st) : 1, now);
  }
  if (now >= g_cron_next && exe && exe[0]) {
    const char *fail = NULL;
    const char *arg = cron_helper_run_arg(exe, &fail);
    if (!arg) {
      snprintf(g_cron_status, sizeof(g_cron_status), "failed:%s", fail);
      g_cron_next = now + CRON_CHECK_SECS;
    } else {
      pid_t pid = fork();
      if (pid == 0) {
        for (int fd = 3; fd < 1024; fd++) close(fd);
        execl("./" CRON_HELPER, "./" CRON_HELPER, arg, (char *)NULL);
        _exit(127);
      }
      if (pid > 0) {
        g_cron_pid = pid;
        g_cron_started = now;
      }
      /* Set before it finishes: an order that arrives meanwhile clears this, and
       * must not be overwritten when this child ends. */
      g_cron_next = now + CRON_CHECK_SECS;
    }
  }
  /* The line stamps .cron.seen each time it runs: no stamp, no cron daemon. */
  if (g_cron_ours && now - g_cron_stat >= 60) {
    struct stat cs;
    g_cron_stat = now;
    bool quiet = stat(".cron.seen", &cs) != 0 || now - cs.st_mtime > CRON_SILENT_SECS;
    snprintf(g_cron_status, sizeof(g_cron_status), "%s", quiet ? "silent" : "yes");
  }
  return strcmp(before, g_cron_status) != 0;
}

/* The node is being deleted: both tagged lines go.  0 gone, 10 gone but a
 * hand-written line still runs this binary, anything else could not. */
int updater_cron_drop(const char *exe) {
  if (g_cron_pid > 0) {
    kill(g_cron_pid, SIGKILL);
    (void)waitpid(g_cron_pid, NULL, 0);
    g_cron_pid = 0;
  }
  if (!failback_write(CRON_HELPER, exe, "", true, CONFIG_FILE, PID_FILE, "upgrade.sh", "",
                      CRON_HELPER))
    return 1;
  pid_t pid = fork();
  if (pid < 0) return 1;
  if (pid == 0) {
    for (int fd = 3; fd < 1024; fd++) close(fd);
    execl("./" CRON_HELPER, "./" CRON_HELPER, "cron-drop", (char *)NULL);
    _exit(127);
  }
  int st = 0;
  int rc = waitpid(pid, &st, 0) == pid && WIFEXITED(st) ? WEXITSTATUS(st) : 1;
  remove(CRON_HELPER);
  return rc;
}

/* A keepalive line can fire while an upgrade installs, when no daemon holds the
 * pid lock.  Starting the old build then would make the new one refuse to start,
 * so a start waits that out.  A stale file past its limits stops nothing. */
bool updater_install_in_progress(void) {
  char line[256];
  FILE *f = fopen(FAILBACK_STATE, "r");
  if (!f) return false;
  bool got = fgets(line, sizeof(line), f) != NULL;
  fclose(f);
  if (!got) return false;
  char *phase = strchr(line, '|');
  if (!phase || strncmp(phase + 1, "installing|", 11) != 0) return false;
  long long since = 0, pid = 0;
  if (sscanf(phase + 12, "%lld|%lld", &since, &pid) != 2 || pid <= 0) return false;
  if (time(NULL) - since > UPGRADE_BUILD_SECS + 60) return false;
  return kill((pid_t)pid, 0) == 0;
}


/* Put back the binary and config a hub-driven upgrade retained, then restart
 * onto them.  Used for CMD_UPGRADE_ABORT: by the time it arrives the new
 * build is already the running process, so undoing it means another exec. */
bool updater_hub_rollback(bot_state_t *state, const char *reason) {
  if (!state) return false;
  char prev_exe[PATH_MAX + 8], prev_cfg[PATH_MAX];
  if (snprintf(prev_exe, sizeof(prev_exe), "%s%s", state->executable_path,
               UPGRADE_PREV_SUFFIX) >= (int)sizeof(prev_exe) ||
      snprintf(prev_cfg, sizeof(prev_cfg), "%s%s", CONFIG_FILE,
               UPGRADE_PREV_SUFFIX) >= (int)sizeof(prev_cfg))
    return false;
  if (access(prev_exe, X_OK) != 0) {
    log_message(L_INFO, state,
                "[UPGRADE] Rollback requested (%s) but no retained binary\n",
                reason ? reason : "no reason given");
    return false;
  }

  log_message(L_INFO, state, "[UPGRADE] Rolling back to the retained build: %s\n",
              reason ? reason : "hub aborted the upgrade");
  /* Config first: if the restart races us, the old binary must not come up
   * against a config only the newer build understands. */
  if (access(prev_cfg, R_OK) == 0 && rename(prev_cfg, CONFIG_FILE) != 0)
    log_message(L_INFO, state,
                "[UPGRADE] Could not restore %s; keeping the current one\n",
                prev_cfg);
  if (rename(prev_exe, state->executable_path) != 0) {
    log_message(L_INFO, state, "[UPGRADE] Could not restore %s\n", prev_exe);
    return false;
  }
  remove(UPGRADE_MARKER_FILE);
  failback_clear();

  irc_printf(state, "QUIT :Upgrade aborted; restoring previous build...\r\n");
  irc_disconnect(state);
  dcc_close_all(state, "Bot rolling back; closing.");
  hub_client_disconnect(state);
  close(state->pid_fd);
  remove(PID_FILE);
  sleep(1);
  execl(state->executable_path, state->executable_path, (char *)NULL);
  handle_fatal_error("execl rollback");
}
#ifdef HAVE_CURL

/* curl 7.85 replaced the bitmask protocol options with string ones and marked
 * the old pair deprecated; Rocky 8's 7.61 has only the bitmask.  Pick at
 * compile time so both build warning-free. */
#if LIBCURL_VERSION_NUM >= 0x075500
#define UPDATER_SET_PROTOCOLS(h)                                               \
  do {                                                                         \
    curl_easy_setopt((h), CURLOPT_PROTOCOLS_STR, "https,file");                \
    curl_easy_setopt((h), CURLOPT_REDIR_PROTOCOLS_STR, "https");               \
  } while (0)
#else
#define UPDATER_SET_PROTOCOLS(h)                                               \
  do {                                                                         \
    curl_easy_setopt((h), CURLOPT_PROTOCOLS, CURLPROTO_HTTPS | CURLPROTO_FILE);\
    curl_easy_setopt((h), CURLOPT_REDIR_PROTOCOLS, CURLPROTO_HTTPS);           \
  } while (0)
#endif

/* A statically linked release binary carries the CA-bundle path of the distro
 * it was built on (Alpine: /etc/ssl/certs/ca-certificates.crt), which RHEL /
 * Rocky / Fedora do not have — every https fetch would then fail closed.  If
 * that compiled-in bundle is missing here, point curl at the first readable
 * bundle this host does have.  A distro-built (dynamic) libcurl's default is
 * right for its own host and is left alone.  Peer verification stays on
 * either way; this only chooses which trust store it uses. */
static void updater_set_ca(CURL *h) {
#if LIBCURL_VERSION_NUM >= 0x074600 /* 7.70: curl_version_info()->cainfo */
  static const char *const bundles[] = {
      "/etc/ssl/certs/ca-certificates.crt",               /* Debian/Ubuntu/Alpine */
      "/etc/pki/tls/certs/ca-bundle.crt",                 /* RHEL/Rocky/Fedora    */
      "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", /* RHEL (extracted)     */
      "/etc/ssl/ca-bundle.pem",                           /* openSUSE             */
      "/etc/ssl/cert.pem",                                /* Alpine/BSD           */
  };
  const curl_version_info_data *vi = curl_version_info(CURLVERSION_NOW);
  if (vi && vi->age >= CURLVERSION_SEVENTH && vi->cainfo &&
      access(vi->cainfo, R_OK) == 0)
    return;
  for (size_t i = 0; i < sizeof(bundles) / sizeof(bundles[0]); i++) {
    if (access(bundles[i], R_OK) == 0) {
      curl_easy_setopt(h, CURLOPT_CAINFO, bundles[i]);
      return;
    }
  }
#else
  (void)h;
#endif
}

static size_t write_callback(void *contents, size_t size, size_t nmemb,
                             void *userp) {
  size_t realsize = size * nmemb;
  http_response_t *mem = (http_response_t *)userp;
  if (mem->size + realsize + 1 > UPDATE_MAX_MANIFEST) return 0;

  char *ptr = realloc(mem->buffer, mem->size + realsize + 1);
  if (ptr == NULL) {
    printf("ERROR: not enough memory (realloc returned NULL)\n");
    return 0;
  }

  mem->buffer = ptr;
  memcpy(&(mem->buffer[mem->size]), contents, realsize);
  mem->size += realsize;
  mem->buffer[mem->size] = 0;

  return realsize;
}
/* An archive download, counted: CURLOPT_MAXFILESIZE_LARGE only sees a
 * declared Content-Length on older curl (Rocky 8). */
typedef struct {
  FILE *fp;
  curl_off_t n;
} capped_file_t;

static size_t write_file_callback(void *ptr, size_t size, size_t nmemb, void *userp) {
  capped_file_t *cf = (capped_file_t *)userp;
  size_t real = size * nmemb;
  if (cf->n + (curl_off_t)real > (curl_off_t)UPDATE_MAX_ARCHIVE) return 0;
  cf->n += (curl_off_t)real;
  return fwrite(ptr, 1, real, cf->fp);
}

/* Set around a manifest read made from the event loop (see
 * UPGRADE_QUICK_TIMEOUT); 0 = the full budget. */
static long g_fetch_quick = 0;

static void updater_set_timeouts(CURL *h) {
  curl_easy_setopt(h, CURLOPT_CONNECTTIMEOUT, g_fetch_quick ? 5L : 30L);
  curl_easy_setopt(h, CURLOPT_TIMEOUT,
                   g_fetch_quick ? g_fetch_quick : UPDATE_FETCH_TIMEOUT);
}

static bool fetch_url(const char *url, http_response_t *response) {
  CURL *curl_handle = curl_easy_init();
  if (!curl_handle) return false;

  response->buffer = malloc(1);
  response->size = 0;

  curl_easy_setopt(curl_handle, CURLOPT_URL, url);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEFUNCTION, write_callback);
  curl_easy_setopt(curl_handle, CURLOPT_WRITEDATA, (void *)response);
  curl_easy_setopt(curl_handle, CURLOPT_USERAGENT, "ircbot-updater/1.0");
  curl_easy_setopt(curl_handle, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl_handle, CURLOPT_SSL_VERIFYHOST, 2L);
  /* Fail-closed transport: a 404 page is not a manifest.  Without
   * FAILONERROR curl reports CURLE_OK for a 4xx/5xx and hands the error body
   * to the caller, which is how a missing release tree reached the signature
   * check as "release manifest signature INVALID" instead of a clean
   * "not found".  The protocol allow-list keeps a redirect from walking the
   * updater onto scp://, ftp:// or any other scheme curl was built with. */
  curl_easy_setopt(curl_handle, CURLOPT_FAILONERROR, 1L);
  UPDATER_SET_PROTOCOLS(curl_handle);
  updater_set_ca(curl_handle);
  updater_set_timeouts(curl_handle);

  CURLcode res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);

  return (res == CURLE_OK);
}

/* A stage reports how far it has got in the note of its status line: "72%" while it
 * fetches, "40% 18 of 45 files" while make runs, "~60% 120 of 200 crates" while cargo
 * runs, whose crates differ too much in size for more than an estimate. */
static void stage_say(const char *phase, const char *code, const char *note);
static void stage_build_tick(void);
static bool g_stage_fetching = false;     /* in the stage child, during its download */
static const char *g_stage_build = NULL;  /* in the stage child, during its build */

static int stage_fetch_tick(void *data, curl_off_t total, curl_off_t now, curl_off_t ut,
                            curl_off_t un) {
  (void)data;
  (void)ut;
  (void)un;
  static int last = -1;
  static time_t said = 0;
  time_t t = time(NULL);
  if (total <= 0 || t - said < 2) return 0;
  int pct = (int)(now * 100 / total);
  if (pct == last) return 0;
  last = pct;
  said = t;
  char note[16];
  snprintf(note, sizeof(note), "%d%%", pct);
  stage_say("fetching", "", note);
  return 0;
}

static bool download_file(const char *url, const char *outfile) {
  CURL *curl = curl_easy_init();
  if (!curl) return false;

  FILE *fp = fopen(outfile, "wb");
  if (!fp) {
    curl_easy_cleanup(curl);
    return false;
  }

  capped_file_t cf = {fp, 0};
  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, &cf);
  curl_easy_setopt(curl, CURLOPT_MAXFILESIZE_LARGE, (curl_off_t)UPDATE_MAX_ARCHIVE);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "ircbot-updater/1.0");
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);
  /* Fail-closed transport: a 404 page is not a manifest.  Without
   * FAILONERROR curl reports CURLE_OK for a 4xx/5xx and hands the error body
   * to the caller, which is how a missing release tree reached the signature
   * check as "release manifest signature INVALID" instead of a clean
   * "not found".  The protocol allow-list keeps a redirect from walking the
   * updater onto scp://, ftp:// or any other scheme curl was built with. */
  curl_easy_setopt(curl, CURLOPT_FAILONERROR, 1L);
  UPDATER_SET_PROTOCOLS(curl);
  updater_set_ca(curl);
  updater_set_timeouts(curl);
  if (g_stage_fetching) {
    curl_easy_setopt(curl, CURLOPT_XFERINFOFUNCTION, stage_fetch_tick);
    curl_easy_setopt(curl, CURLOPT_NOPROGRESS, 0L);
  }

  CURLcode res = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  bool ok = (fclose(fp) == 0) && res == CURLE_OK;
  if (!ok) remove(outfile);
  return ok;
}

static bool verify_sha256(const char *filepath, const char *expected_hash) {
  unsigned char hash[EVP_MAX_MD_SIZE];
  unsigned int hash_len;
  EVP_MD_CTX *ctx;
  const EVP_MD *md;

  ctx = EVP_MD_CTX_new();
  md = EVP_sha256();
  if (ctx == NULL || md == NULL) {
    EVP_MD_CTX_free(ctx);
    return false;
  }
  if (1 != EVP_DigestInit_ex(ctx, md, NULL)) {
    EVP_MD_CTX_free(ctx);
    return false;
  }

  FILE *f = fopen(filepath, "rb");
  if (!f) {
    EVP_MD_CTX_free(ctx);
    return false;
  }
  unsigned char buffer[4096];
  size_t bytes_read = 0;
  while ((bytes_read = fread(buffer, 1, sizeof(buffer), f)) > 0) {
    if (1 != EVP_DigestUpdate(ctx, buffer, bytes_read)) {
      EVP_MD_CTX_free(ctx);
      fclose(f);
      return false;
    }
  }
  if (1 != EVP_DigestFinal_ex(ctx, hash, &hash_len)) {
    EVP_MD_CTX_free(ctx);
    fclose(f);
    return false;
  }
  EVP_MD_CTX_free(ctx);
  fclose(f);

  char hex_hash[EVP_MAX_MD_SIZE * 2 + 1];
  int offset = 0;
  for (unsigned int i = 0; i < hash_len; i++) {
    int written = snprintf(hex_hash + offset,
                           sizeof(hex_hash) - (size_t)offset,
                           "%02x", hash[i]);
    if (written > 0)
      offset += written;
  }
  hex_hash[offset] = '\0';

  return (strcasecmp(hex_hash, expected_hash) == 0);
}

static bool validate_dependency_name(const char *dep) {
  if (!dep || strlen(dep) == 0) return false;
  if (strlen(dep) > 64) return false;

  for (const char *p = dep; *p; p++) {
    if (!isalnum(*p) && *p != '-' && *p != '_' && *p != '.' && *p != '+') {
      return false;
    }
  }
  return true;
}

static bool check_dependency(const char *dep) {
  if (!validate_dependency_name(dep)) {
      return false;
  }

  char command[256];

  if (strcmp(dep, "gcc") == 0 || strcmp(dep, "make") == 0 ||
      strcmp(dep, "tar") == 0 || strcmp(dep, "bash") == 0) {
    snprintf(command, sizeof(command), "command -v %s >/dev/null 2>&1", dep);
  } else {
    snprintf(command, sizeof(command),
             "pkg-config --exists %s >/dev/null 2>&1 || "
             "echo '#include <%s.h>' | gcc -E - >/dev/null 2>&1",
             dep, dep);
  }
  return (system(command) == 0);
}

static bool sanitize_filename(const char *input, char *output, size_t output_size) {
  if (!input || !output || output_size == 0) return false;

  size_t len = 0;
  for (const char *p = input; *p && len < output_size - 1; p++) {
    if (isalnum(*p) || *p == '-' || *p == '_' || *p == '.') {
      output[len++] = *p;
    }
  }
  output[len] = '\0';

  if (len < 8 || strcmp(output + len - 7, ".tar.gz") != 0) {
    return false;
  }
  return len > 0;
}

/* Test hook, compiled in only with -DIRC_TEST_HOOKS (the testnet's builds;
 * never a release or a plain `make`): a non-empty IRCBOT_UPDATE_BASE
 * overrides the compiled release ROOT (BOT_UPDATE_BASE) so the sandbox can
 * read a local ircbot-releases tree over file://, and IRCBOT_UPDATE_PUBKEY
 * then names the throwaway key that signs it.  A production binary has no
 * code that reads either: its root and key are the compiled-in ones, so
 * nobody who can set the daemon's environment can point it at their own
 * signed releases.  Nothing a hub sends can set or move the root either. */
#ifdef IRC_TEST_HOOKS
static const char *updater_env_base(void) {
  const char *b = getenv("IRCBOT_UPDATE_BASE");
  return (b && b[0]) ? b : NULL;
}
#else
static const char *updater_env_base(void) { return NULL; }
#endif

/* The release tree <root>/<variant> the next manifest read uses; "" = this
 * build's own variant.  A hub-driven run or -checkupdate names the variant
 * (updater_set_tree); the root is never the hub's to choose. */
static char g_update_tree[600];

static bool updater_set_tree(const char *variant) {
  const char *root = updater_env_base();
  if (!root) root = BOT_UPDATE_BASE;
  if (!variant || !variant[0] || strlen(variant) > 7 ||
      strpbrk(variant, "/;|&`$ \t\r\n"))
    return false;
  return snprintf(g_update_tree, sizeof(g_update_tree), "%s/%s", root,
                  variant) < (int)sizeof(g_update_tree);
}

/* An https:// URL whose host is exactly github.com, githubusercontent.com or
 * a subdomain of it (raw. for manifests; downloads redirect to objects.).
 * "Contains github.com" let https://evil.example/github.com through; userinfo
 * (github.com@evil.example) is refused outright. */
static bool url_host_trusted(const char *url) {
  if (strncmp(url, "https://", 8) != 0) return false;
  const char *h = url + 8;
  size_t n = strcspn(h, "/:?#@");
  if (h[n] == '@') return false;
  static const char gh[] = "github.com", ghu[] = "githubusercontent.com";
  if (n == sizeof(gh) - 1 && strncasecmp(h, gh, n) == 0) return true;
  if (n == sizeof(ghu) - 1 && strncasecmp(h, ghu, n) == 0) return true;
  return n > sizeof(ghu) && h[n - sizeof(ghu)] == '.' &&
         strncasecmp(h + n - (sizeof(ghu) - 1), ghu, sizeof(ghu) - 1) == 0;
}

static bool validate_url(const char *url) {
  if (!url) return false;
  /* Reject shell metacharacters regardless of source. */
  if (strstr(url, ";") || strstr(url, "|") || strstr(url, "&") ||
      strstr(url, "`") || strstr(url, "$")) {
    return false;
  }
  /* Local-source override: accept only URLs under the configured base. */
  const char *ebase = updater_env_base();
  if (ebase && strncmp(url, ebase, strlen(ebase)) == 0) {
    return true;
  }
  return url_host_trusted(url);
}

/* Fetch the release manifest AND its detached Ed25519 signature, then verify
 * the signature against the compiled-in public key (BOT_UPDATE_PUBKEY_B64)
 * over the EXACT manifest bytes received.  Returns the verified, NUL-terminated
 * manifest text on success (caller frees); returns NULL on ANY failure and
 * sets *err to a short human-readable reason.  Fail-closed: an unconfigured,
 * unreachable, or invalid signature all yield NULL so no unauthenticated
 * manifest is ever parsed, downloaded from, or executed. */
static char *fetch_verified_manifest(const char **err) {
  *err = NULL;

  /* Pinned key.  Only a test-hooks build (see updater_env_base) takes a
   * throwaway key from IRCBOT_UPDATE_PUBKEY, and only alongside
   * IRCBOT_UPDATE_BASE. */
  const char *pubkey_b64 = BOT_UPDATE_PUBKEY_B64;
#ifdef IRC_TEST_HOOKS
  if (updater_env_base()) {
    const char *ep = getenv("IRCBOT_UPDATE_PUBKEY");
    if (ep && ep[0]) pubkey_b64 = ep;
  }
#endif

  /* Empty pinned key = updater intentionally disabled. */
  if (pubkey_b64[0] == '\0') {
    *err = "self-updater disabled (no signing key configured)";
    return NULL;
  }

  /* Decode the Ed25519 public key (must be exactly 32 raw bytes). */
  int publen = 0;
  unsigned char *pub = base64_decode(pubkey_b64, &publen);
  if (!pub || publen != 32) {
    if (pub) free(pub);
    *err = "configured update public key is malformed";
    return NULL;
  }

  /* Fetch the manifest. */
  http_response_t man;
  man.buffer = NULL;
  man.size = 0;
  if (!g_update_tree[0] && !updater_set_tree(updater_host_variant())) {
    free(pub);
    *err = "release base URL too long";
    return NULL;
  }
  char man_url[1024], sig_url[1024];
  snprintf(man_url, sizeof(man_url), "%s/releases.txt", g_update_tree);
  snprintf(sig_url, sizeof(sig_url), "%s/releases.sig", g_update_tree);
  if (!fetch_url(man_url, &man)) {
    free(pub);
    if (man.buffer) free(man.buffer);
    *err = "failed to download release manifest";
    return NULL;
  }

  /* Fetch the detached signature (base64 of 64 raw bytes). */
  http_response_t sig;
  sig.buffer = NULL;
  sig.size = 0;
  if (!fetch_url(sig_url, &sig)) {
    free(pub);
    if (man.buffer) free(man.buffer);
    if (sig.buffer) free(sig.buffer);
    *err = "failed to download release signature (releases.txt.sig)";
    return NULL;
  }

  int siglen = 0;
  unsigned char *sigbytes = base64_decode(sig.buffer, &siglen);
  bool ok = (sigbytes && siglen == 64 &&
             crypto_ed25519_verify(pub, (const unsigned char *)man.buffer,
                                   man.size, sigbytes));

  free(pub);
  if (sigbytes) free(sigbytes);
  if (sig.buffer) free(sig.buffer);

  if (!ok) {
    if (man.buffer) free(man.buffer);
    *err = "release manifest signature INVALID — possible tampering";
    return NULL;
  }
  return man.buffer; /* verified manifest; caller frees */
}

void updater_check_for_updates(bot_state_t *state, const char *nick) {
  log_message(L_DEBUG, state, "[DEBUG] updater_check_for_updates called.\n");

  const char *verr = NULL;
  char *manifest = fetch_verified_manifest(&verr);
  if (!manifest) {
    irc_printf(state, "PRIVMSG %s :Update check failed: %s.\r\n",
               nick, verr ? verr : "unknown error");
    return;
  }
  http_response_t response;
  response.buffer = manifest; /* verified bytes; existing parse/free below */
  response.size = 0;

  irc_printf(state, "PRIVMSG %s :--- Available Updates (Current: %s) ---\r\n",
             nick, BOT_VERSION);
  char *saveptr_line;
  char *line = strtok_r(response.buffer, "\n", &saveptr_line);
  int updates_found = 0;

  while (line) {
    if (line[0] == '#') {
      line = strtok_r(NULL, "\n", &saveptr_line);
      continue;
    }

    char version[64], date[64], url[512], hash[128], deps[256];
    if (sscanf(line, "%63s %63s %511s %127s %255s", version, date, url, hash,
               deps) == 5) {
      if (updater_version_cmp(version, BOT_VERSION) > 0) {
        updates_found++;
        char deps_status[512] = "[OK]";
        bool all_deps_ok = true;

        char deps_copy[256];
        snprintf(deps_copy, sizeof(deps_copy), "%s", deps);
        char *saveptr_dep;
        char *dep = strtok_r(deps_copy, ",", &saveptr_dep);

        while (dep) {
          if (!check_dependency(dep)) {
            if (all_deps_ok) {
              snprintf(deps_status, sizeof(deps_status), "[FAILED: %s", dep);
            } else {
              strncat(deps_status, ", ",
                      sizeof(deps_status) - strlen(deps_status) - 1);
              strncat(deps_status, dep,
                      sizeof(deps_status) - strlen(deps_status) - 1);
            }
            all_deps_ok = false;
          }
          dep = strtok_r(NULL, ",", &saveptr_dep);
        }
        if (!all_deps_ok)
          strncat(deps_status, "]",
                  sizeof(deps_status) - strlen(deps_status) - 1);

        irc_printf(state, "PRIVMSG %s :%s (%s) - Dependencies: %s\r\n", nick,
                   version, date, deps_status);
      }
    }
    line = strtok_r(NULL, "\n", &saveptr_line);
  }

  if (updates_found == 0) {
    irc_printf(state, "PRIVMSG %s :Bot is up-to-date.\r\n", nick);
  } else {
    irc_printf(
        state,
        "PRIVMSG %s :To upgrade, type: update <version>. IE: update v2.0.0\r\n",
        nick);
  }

  if (response.buffer) {
    free(response.buffer);
  }
}

/* ircbot -checkupdate [variant]: fetch the release manifest and its signature
 * exactly as a hub-driven upgrade does — the release tree <base>/<variant>,
 * the compiled-in base and pinned key unless IRCBOT_UPDATE_BASE says
 * otherwise — verify one against the other, and report.  Nothing past the
 * manifest is downloaded and nothing is installed, so an operator (or the
 * testnet) can prove a host reaches and trusts the real release channel —
 * TLS, CA store, pinned key — without upgrading anything.  0 = verified. */
int updater_check_cli(const char *variant) {
  const char *want = (variant && variant[0]) ? variant : updater_host_variant();
  if (strpbrk(want, "/;|&`$ \t\r\n") || strlen(want) > 7) {
    printf("checkupdate: FAIL malformed variant\n");
    return 1;
  }
  if (!updater_set_tree(want)) {
    printf("checkupdate: FAIL release base URL too long\n");
    return 1;
  }
  const char *verr = NULL;
  char *manifest = fetch_verified_manifest(&verr);
  if (!manifest) {
    printf("checkupdate: FAIL %s (%s)\n", verr ? verr : "manifest fetch failed",
           g_update_tree);
    return 1;
  }
  int rows = 0;
  char newest[64] = "";
  char *saveptr = NULL;
  for (char *line = strtok_r(manifest, "\n", &saveptr); line;
       line = strtok_r(NULL, "\n", &saveptr)) {
    char version[64];
    if (line[0] == '#' || sscanf(line, "%63s", version) != 1) continue;
    rows++;
    if (!newest[0] || updater_version_cmp(version, newest) > 0)
      snprintf(newest, sizeof(newest), "%s", version);
  }
  free(manifest);
  printf("checkupdate: OK %s manifest verified: %d release row(s), newest %s, "
         "running %s\n",
         want, rows, newest[0] ? newest : "-", BOT_VERSION);
  return 0;
}

void updater_perform_upgrade(bot_state_t *state, const char *nick,
                             const char *version_to_install) {
  log_message(L_DEBUG, state,
              "[DEBUG] updater_perform_upgrade called for %s.\n",
              version_to_install);

  /* Downgrade protection: refuse to install anything older than the running
   * build, defeating a replay of an old (but validly signed) manifest that
   * points at a known-vulnerable version. */
  if (updater_version_cmp(version_to_install, BOT_VERSION) < 0) {
    irc_printf(state,
               "PRIVMSG %s :Refusing downgrade: %s is older than the running "
               "version %s.\r\n",
               nick, version_to_install, BOT_VERSION);
    return;
  }

  /* One install path: the same checks, staging, script and failback as a
   * hub-driven upgrade, with this id instead of a run's.  On success this does
   * not return. */
  char id[64];
  snprintf(id, sizeof(id), "local-%lld", (long long)time(NULL));
  irc_printf(state, "PRIVMSG %s :Installing %s...\r\n", nick, version_to_install);
  const char *err = NULL;
  if (!updater_hub_commit(state, id, version_to_install, "", &err))
    irc_printf(state, "PRIVMSG %s :Upgrade aborted: %s.\r\n", nick,
               err ? err : "unknown error");
}

/* ======================================================================
 * Hub-driven upgrade (CMD_UPGRADE_COMMIT)
 *
 * A hub-configured bot never upgrades itself from an IRC command (see the
 * gate in commands.c); its hub drives the whole network in a rolling plan.
 * This entry point is kept PARALLEL to updater_perform_upgrade() rather than
 * folded into it: that function's QUIT/exec sequence is delicate and is still
 * the entire story for standalone bots, while this path differs in nearly
 * every other respect —
 *   - no admin nick to answer: progress goes to the log, and the outcome to
 *     the hub as CMD_UPGRADE_RESULT after the restart,
 *   - the artifact is chosen by {kind,arch,libc} rather than "first row with
 *     this version" — a prebuilt binary matching this host beats a source
 *     build (Task 5), and a source build needs its dependencies present,
 *   - the old binary and config are RETAINED as <exe>.prev / <config>.prev,
 *     never deleted, so the hub can order a rollback after the new build is
 *     already running (Task 4).
 * ====================================================================== */

/* Byte-copy with an explicit mode.  Used for the config snapshot, where the
 * original must stay in place (the binary is renamed instead). */
static bool copy_file(const char *src, const char *dst, mode_t mode) {
  int in = open(src, O_RDONLY | O_CLOEXEC);
  if (in < 0) return false;
  int out = open(dst, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, mode);
  if (out < 0) {
    close(in);
    return false;
  }
  char buf[8192];
  bool ok = true;
  ssize_t n;
  while ((n = read(in, buf, sizeof(buf))) > 0) {
    ssize_t off = 0;
    while (off < n) {
      ssize_t w = write(out, buf + off, (size_t)(n - off));
      if (w <= 0) {
        ok = false;
        break;
      }
      off += w;
    }
    if (!ok) break;
  }
  if (n < 0) ok = false;
  if (ok && fsync(out) != 0) ok = false;
  close(in);
  if (close(out) != 0) ok = false;
  if (!ok) remove(dst);
  return ok;
}

/* One artifact row of the release manifest.  Columns 1-5 are the legacy
 * format the standalone updater already parses; 6-9 were appended for the
 * network upgrade and are absent from older manifests, which is why they
 * default to a source build that fits anything. */
typedef struct {
  char version[64];
  char url[512];
  char hash[128];
  char deps[256];
  char kind[8];     /* bin | src              */
  char arch[32];    /* x86_64 | any           */
  char libc[16];    /* gnu | musl | any       */
  char min_from[64];/* oldest version this may upgrade FROM; '*' = any */
  char cpu[256];    /* CPU features it needs, "-" = none (column 10)    */
  unsigned long long size; /* archive + unpacked bytes (column 11), 0 = unknown */
} manifest_row_t;

/* The variant whose tree manifest_select() is reading, for its reasons. */
static const char *g_select_variant = NULL;

/* Is CPU feature `f` present, per /proc/cpuinfo ("flags" on x86_64,
 * "Features" on aarch64; "neon" is that file's "asimd")?  A host whose
 * cpuinfo cannot be read is not refused here: the staged -selftest and the
 * upgrade script's watchdog still stand between it and a build it cannot
 * run. */
static bool host_cpu_has(const char *f) {
  static char flags[8192];
  static bool loaded = false;
  if (!loaded) {
    loaded = true;
    FILE *fp = fopen("/proc/cpuinfo", "r");
    if (fp) {
      char line[8192];
      while (fgets(line, sizeof(line), fp)) {
        if (strncmp(line, "flags", 5) != 0 && strncmp(line, "Features", 8) != 0)
          continue;
        const char *colon = strchr(line, ':');
        if (!colon) continue;
        snprintf(flags, sizeof(flags), " %s", colon + 1);
        flags[strcspn(flags, "\r\n")] = '\0';
        size_t fl = strlen(flags);
        if (fl + 1 < sizeof(flags)) {
          flags[fl] = ' ';
          flags[fl + 1] = '\0';
        }
        break;
      }
      fclose(fp);
    }
  }
  if (!flags[0]) return true;
  if (strcmp(f, "neon") == 0) f = "asimd";
  char needle[80];
  snprintf(needle, sizeof(needle), " %s ", f);
  return strstr(flags, needle) != NULL;
}

/* The first CPU feature a row's column 10 names that this host lacks, or
 * NULL.  Entries are comma-separated; "arch:feature" applies only on that
 * arch. */
static const char *row_cpu_missing(const manifest_row_t *r) {
  static char miss[64];
  if (!r->cpu[0] || strcmp(r->cpu, "-") == 0) return NULL;
  char arch[32];
  updater_host_arch(arch, sizeof(arch));
  char work[256];
  snprintf(work, sizeof(work), "%s", r->cpu);
  char *save = NULL;
  for (char *e = strtok_r(work, ",", &save); e; e = strtok_r(NULL, ",", &save)) {
    const char *feat = e;
    char *colon = strchr(e, ':');
    if (colon) {
      *colon = '\0';
      if (strcasecmp(e, arch) != 0) continue;
      feat = colon + 1;
    }
    if (!feat[0] || host_cpu_has(feat)) continue;
    snprintf(miss, sizeof(miss), "%s", feat);
    return miss;
  }
  return NULL;
}

/* Does this row's {arch,libc} fit the running host?  "any" fits everything,
 * which is what source tarballs and older manifests carry. */
static bool row_fits_host(const manifest_row_t *r) {
  char arch[32], libc[16];
  updater_host_arch(arch, sizeof(arch));
  updater_host_libc(libc, sizeof(libc));
  if (strcmp(r->arch, "any") != 0 && strcasecmp(r->arch, arch) != 0)
    return false;
  if (strcmp(r->libc, "any") != 0 && strcasecmp(r->libc, libc) != 0)
    return false;
  return true;
}

/* Every dependency the row names must be present (source builds only; a
 * prebuilt binary carries "none").  failed is filled with the missing ones. */
static bool row_deps_ok(const manifest_row_t *r, char *failed, size_t failed_size) {
  if (failed && failed_size) failed[0] = '\0';
  if (strcasecmp(r->deps, "none") == 0) return true;
  char deps_copy[256];
  snprintf(deps_copy, sizeof(deps_copy), "%s", r->deps);
  bool all_ok = true;
  char *saveptr = NULL;
  for (char *dep = strtok_r(deps_copy, ",", &saveptr); dep;
       dep = strtok_r(NULL, ",", &saveptr)) {
    if (check_dependency(dep)) continue;
    if (failed && failed_size) {
      if (!all_ok) strncat(failed, ", ", failed_size - strlen(failed) - 1);
      strncat(failed, dep, failed_size - strlen(failed) - 1);
    }
    all_ok = false;
  }
  return all_ok;
}

/* Choose the artifact for `version`: a usable prebuilt binary for this host
 * wins, otherwise a source tarball whose build dependencies are installed.
 * `manifest` is consumed (strtok_r).  reason explains an empty result. */
static bool manifest_select(char *manifest, const char *version,
                            manifest_row_t *out, char *reason,
                            size_t reason_size) {
  bool have_pick = false;
  char missing[256] = "";
  snprintf(reason, reason_size, "requested version is not in the manifest");

  char *saveptr = NULL;
  for (char *line = strtok_r(manifest, "\n", &saveptr); line;
       line = strtok_r(NULL, "\n", &saveptr)) {
    if (line[0] == '#' || line[0] == '\0') continue;

    manifest_row_t row;
    memset(&row, 0, sizeof(row));
    char date[64];
    /* Columns 6-9 are optional: an older 5-column manifest yields a source
     * artifact that fits any host and may be installed from any version. */
    snprintf(row.kind, sizeof(row.kind), "src");
    snprintf(row.arch, sizeof(row.arch), "any");
    snprintf(row.libc, sizeof(row.libc), "any");
    snprintf(row.min_from, sizeof(row.min_from), "*");
    snprintf(row.cpu, sizeof(row.cpu), "-");
    int n = sscanf(line, "%63s %63s %511s %127s %255s %7s %31s %15s %63s %255s %llu",
                   row.version, date, row.url, row.hash, row.deps, row.kind,
                   row.arch, row.libc, row.min_from, row.cpu, &row.size);
    if (n < 5) continue;
    if (!version_eq(row.version, version)) continue;

    if (!validate_url(row.url)) {
      snprintf(reason, reason_size, "untrusted artifact URL in manifest");
      continue;
    }
    if (!row_fits_host(&row)) {
      snprintf(reason, reason_size, "no artifact for this host arch/libc");
      continue;
    }
    const char *lacks = row_cpu_missing(&row);
    if (lacks) {
      snprintf(reason, reason_size, "this CPU lacks %s, which the %s build needs",
               lacks, g_select_variant ? g_select_variant : updater_host_variant());
      continue;
    }
    if (strcmp(row.min_from, "*") != 0 &&
        updater_version_cmp(BOT_VERSION, row.min_from) < 0) {
      snprintf(reason, reason_size,
               "running version is below the artifact's min_from %s",
               row.min_from);
      continue;
    }
    if (!row_deps_ok(&row, missing, sizeof(missing))) {
      snprintf(reason, reason_size, "missing build dependencies: %s", missing);
      continue;
    }
    /* Usable.  Prefer a prebuilt binary; keep looking only if this is a
     * source row that a later binary row could beat. */
    *out = row;
    have_pick = true;
    if (strcasecmp(row.kind, "bin") == 0) break;
  }

  if (have_pick) reason[0] = '\0';
  return have_pick;
}

/* The checks a hub-driven upgrade needs that touch no network: version
 * order, the variant, min_from and the unattended-restart prerequisites.
 * The same version is only "already running" when the variant matches too —
 * a different variant is a switch between the C and Rust builds. */
static bool hub_local_check(const bot_state_t *state, const char *target_ver,
                            const char *want_variant, const char *min_from,
                            char *reason, size_t reason_size) {
  if (!want_variant[0] || strpbrk(want_variant, "/;|&`$ \t\r\n") ||
      strlen(want_variant) > 7) {
    snprintf(reason, reason_size, "rejected malformed variant from hub");
    return false;
  }
  /* Same downgrade guard as the standalone path: a validly signed but stale
   * manifest must not be able to walk us back onto a known-bad build. */
  int cmp = updater_version_cmp(target_ver, BOT_VERSION);
  if (cmp < 0) {
    snprintf(reason, reason_size, "target is older than the running version");
    return false;
  }
  if (cmp == 0 && strcmp(want_variant, updater_host_variant()) == 0) {
    snprintf(reason, reason_size, "already running the target version");
    return false;
  }
  if (min_from && min_from[0] && strcmp(min_from, "*") != 0 &&
      updater_version_cmp(BOT_VERSION, min_from) < 0) {
    /* The hub walks the intermediate releases when it sees this. */
    snprintf(reason, reason_size,
             "running version is below the target's min_from");
    return false;
  }
  /* An unattended restart needs the machine-bound password file; without it
   * the new binary would stop at a password prompt with nobody to answer. */
  if (access(PASS_FILE, R_OK) != 0) {
    snprintf(reason, reason_size, "no " PASS_FILE "; cannot restart unattended");
    return false;
  }
  if (state->executable_path[0] != '/') {
    snprintf(reason, reason_size, "executable path is not absolute");
    return false;
  }
  return true;
}

/* Point the updater at the tree a hub-driven run names: <root>/<variant>.
 * The run picks only the variant — that is what lets one network-wide run
 * leave each node on its own kind of build, and lets an admin move a node
 * from the C build to the Rust one.  The root is this build's own (or the
 * operator's env override): the only tree its pinned key can verify. */
static bool hub_set_tree(const char *want_variant, char *reason,
                         size_t reason_size) {
  if (!updater_set_tree(want_variant)) {
    snprintf(reason, reason_size, "rejected malformed release variant");
    return false;
  }
  return true;
}

/* CMD_UPGRADE_PREPARE.  Everything COMMIT will need short of the download is
 * checked here — the signed manifest for the wanted build must verify and
 * list an artifact for this host.  A node that answers "ready" and then fails
 * at COMMIT is what turns a routine run into an abort, so the question is
 * asked in full up front. */
/* ---- Preflight (PREPARE) -----------------------------------------------
 * Can this host take the build at all?  Asked before anything changes, so a
 * full disk or a read-only directory is an "unable" with a reason an admin
 * can act on, not a failed restart.  Each reason starts with a fixed code
 * word (disk:, dir:, exe:, exec:, tool:, net:).  Only a probe file is
 * written, and it is gone again before this returns.  The instance dir is the
 * cwd: instance_dir_enter() put us there. */
#ifndef ST_NOEXEC
#define ST_NOEXEC 8 /* Linux: glibc hides it without _GNU_SOURCE */
#endif

static bool preflight_tool(const char *name) {
  const char *path = getenv("PATH");
  char work[1024], full[1100];
  snprintf(work, sizeof(work), "%s", path && path[0] ? path : "/usr/bin:/bin");
  char *save = NULL;
  for (char *d = strtok_r(work, ":", &save); d; d = strtok_r(NULL, ":", &save)) {
    snprintf(full, sizeof(full), "%s/%s", d, name);
    if (access(full, X_OK) == 0) return true;
  }
  return false;
}

static bool preflight_dir_probe(char *reason, size_t reason_size, const char *dir) {
  const char *probe = ".upgrade.probe", *moved = ".upgrade.probe2";
  int fd = open(probe, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
  bool ok = fd >= 0 && write(fd, "x", 1) == 1 && fsync(fd) == 0;
  int err = errno;
  if (fd >= 0) close(fd);
  if (ok && rename(probe, moved) != 0) {
    ok = false;
    err = errno;
  }
  (void)unlink(probe);
  (void)unlink(moved);
  if (!ok)
    snprintf(reason, reason_size, "dir: cannot write %.160s: %s", dir, strerror(err));
  return ok;
}

/* The binary must be ours, and not immutable: a hard link fails on that where
 * a rename could not be tried without moving it.  A filesystem with no hard
 * links at all still passes: it is a different errno. */
static bool preflight_exe(const char *exe, char *reason, size_t reason_size) {
  struct stat st;
  if (stat(exe, &st) != 0) {
    snprintf(reason, reason_size, "exe: cannot read %.160s: %s", exe, strerror(errno));
    return false;
  }
  if (st.st_uid != geteuid()) {
    snprintf(reason, reason_size, "exe: cannot replace %.160s: owned by another user", exe);
    return false;
  }
  const char *probe = ".upgrade.probe3";
  (void)unlink(probe);
  int rc = link(exe, probe);
  int err = errno;
  (void)unlink(probe);
  if (rc != 0 && (err == EPERM || err == EACCES)) {
    snprintf(reason, reason_size, "exe: cannot replace %.160s: %s", exe, strerror(err));
    return false;
  }
  return true;
}

/* Everything the swap will write, plus a margin.  A manifest row without the
 * size column gets a fixed allowance; a source build always gets one on top,
 * for its objects. */
static bool preflight_space(const char *dir, const char *exe, const char *cfg,
                            unsigned long long size,
                            bool is_bin, const char *variant, char *reason,
                            size_t reason_size) {
  struct statvfs sv;
  if (statvfs(".", &sv) != 0) return true; /* unknown: the stage will tell */
  if (sv.f_flag & ST_NOEXEC) {
    snprintf(reason, reason_size, "exec: %.160s is mounted noexec", dir);
    return false;
  }
  if (sv.f_files > 0 && sv.f_favail < UPGRADE_MIN_INODES) {
    snprintf(reason, reason_size, "disk: no free inodes in %.160s", dir);
    return false;
  }
  unsigned long long need = size;
  if (!need) need = is_bin ? UPGRADE_SPACE_BIN_DEFAULT : 0;
  if (!is_bin)
    need += strcmp(variant, "rs") == 0 ? UPGRADE_SPACE_BUILD_RS : UPGRADE_SPACE_BUILD_C;
  struct stat st;
  if (stat(cfg, &st) == 0 && st.st_size > 0) need += (unsigned long long)st.st_size;
  if (stat(exe, &st) == 0 && st.st_size > 0) need += (unsigned long long)st.st_size;
  need += UPGRADE_SPACE_MARGIN;
  unsigned long long have = (unsigned long long)sv.f_bavail * sv.f_frsize;
  if (have < need) {
    snprintf(reason, reason_size, "disk: needs %llu MB in %.160s, has %llu MB",
             need / (1024 * 1024) + 1, dir, have / (1024 * 1024));
    return false;
  }
  return true;
}

/* HEAD on the artifact.  A server that does not do HEAD says nothing either
 * way, so it passes and the download decides. */
static bool preflight_artifact(const char *url, char *reason, size_t reason_size) {
  CURL *h = curl_easy_init();
  if (!h) return true;
  g_fetch_quick = UPGRADE_QUICK_TIMEOUT;
  curl_easy_setopt(h, CURLOPT_URL, url);
  curl_easy_setopt(h, CURLOPT_NOBODY, 1L);
  curl_easy_setopt(h, CURLOPT_USERAGENT, "ircbot-updater/1.0");
  curl_easy_setopt(h, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(h, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(h, CURLOPT_SSL_VERIFYHOST, 2L);
  curl_easy_setopt(h, CURLOPT_FAILONERROR, 1L);
  UPDATER_SET_PROTOCOLS(h);
  updater_set_ca(h);
  updater_set_timeouts(h);
  g_fetch_quick = 0;
  CURLcode res = curl_easy_perform(h);
  long code = 0;
  curl_easy_getinfo(h, CURLINFO_RESPONSE_CODE, &code);
  curl_easy_cleanup(h);
  const char *slash = strrchr(url, '/');
  const char *name = slash ? slash + 1 : url;
  if (code >= 400) {
    if (code == 405 || code == 501) return true;
    snprintf(reason, reason_size, "net: %ld from %.120s", code, name);
    return false;
  }
  if (res != CURLE_OK) {
    snprintf(reason, reason_size, "net: cannot reach %.120s: %s", name, curl_easy_strerror(res));
    return false;
  }
  return true;
}

static bool preflight_host(const char *exe, const char *cfg, const char *url,
                           unsigned long long size, const char *kind,
                           const char *variant, char *reason, size_t reason_size) {
  char dir[512];
  if (!getcwd(dir, sizeof(dir))) snprintf(dir, sizeof(dir), ".");
  bool is_bin = strcasecmp(kind, "bin") == 0;
  if (!preflight_space(dir, exe, cfg, size, is_bin, variant, reason, reason_size)) return false;
  if (!preflight_dir_probe(reason, reason_size, dir)) return false;
  if (!preflight_exe(exe, reason, reason_size)) return false;
  if (access("/bin/bash", X_OK) != 0) {
    snprintf(reason, reason_size, "tool: /bin/bash not found");
    return false;
  }
  if (!preflight_tool("tar")) {
    snprintf(reason, reason_size, "tool: tar not found");
    return false;
  }
  return preflight_artifact(url, reason, reason_size);
}

bool updater_hub_prepare_check(bot_state_t *state, const char *target_ver,
                               const char *variant, const char *min_from,
                               char *reason, size_t reason_size) {
  reason[0] = '\0';
  const char *want_variant = (variant && variant[0]) ? variant
                                                     : updater_host_variant();
  if (!hub_local_check(state, target_ver, want_variant, min_from, reason,
                       reason_size) ||
      !hub_set_tree(want_variant, reason, reason_size))
    return false;
  const char *verr = NULL;
  g_fetch_quick = UPGRADE_QUICK_TIMEOUT;
  char *manifest = fetch_verified_manifest(&verr);
  g_fetch_quick = 0;
  if (!manifest) {
    snprintf(reason, reason_size, "%s", verr ? verr : "manifest fetch failed");
    return false;
  }
  manifest_row_t row;
  memset(&row, 0, sizeof(row));
  g_select_variant = want_variant;
  bool picked = manifest_select(manifest, target_ver, &row, reason, reason_size);
  free(manifest);
  if (!picked) {
    /* Can't run this build here — would the other one?  Say so, never
     * switch: which build a node runs is the admin's call. */
    const char *other = strcmp(want_variant, "c") == 0 ? "rs" : "c";
    char why_other[320] = "";
    if (strncmp(reason, "this CPU lacks ", 15) == 0 &&
        hub_set_tree(other, why_other, sizeof(why_other))) {
      g_fetch_quick = UPGRADE_QUICK_TIMEOUT;
      char *om = fetch_verified_manifest(&verr);
      g_fetch_quick = 0;
      if (om) {
        manifest_row_t orow;
        memset(&orow, 0, sizeof(orow));
        g_select_variant = other;
        bool fits = manifest_select(om, target_ver, &orow, why_other,
                                    sizeof(why_other));
        free(om);
        if (fits) {
          size_t rl = strlen(reason);
          snprintf(reason + rl, reason_size - rl,
                   " — the %s build fits: select this node with =%s", other,
                   other);
        }
      }
      hub_set_tree(want_variant, why_other, sizeof(why_other));
    }
    g_select_variant = NULL;
    return false;
  }
  g_select_variant = NULL;
  const char *slash = strrchr(row.url, '/');
  if (strncmp(slash ? slash + 1 : row.url, "ircbot-", 7) != 0) {
    snprintf(reason, reason_size, "manifest artifact is not a ircbot release");
    return false;
  }
  return preflight_host(state->executable_path, CONFIG_FILE, row.url, row.size,
                        row.kind, want_variant, reason, reason_size);
}

/* Run argv[0] with argv, stdout+stderr captured into `out` (first line
 * kept), killed after `timeout_s`.  Returns its exit status, or -1 when it
 * could not run or timed out.  No shell: every argument is passed as-is. */
static int run_bounded(const char *const argv[], int timeout_s, char *out,
                       size_t out_size) {
  if (out && out_size) out[0] = '\0';
  int pipefd[2];
  if (pipe(pipefd) != 0) return -1;
  pid_t pid = fork();
  if (pid < 0) {
    close(pipefd[0]);
    close(pipefd[1]);
    return -1;
  }
  if (pid == 0) {
    dup2(pipefd[1], STDOUT_FILENO);
    dup2(pipefd[1], STDERR_FILENO);
    int devnull = open("/dev/null", O_RDONLY);
    if (devnull >= 0) dup2(devnull, STDIN_FILENO);
    /* Nothing of this process leaks into the child: not the IRC socket, not
     * the hub link, not the PID lock. */
    long maxfd = sysconf(_SC_OPEN_MAX);
    if (maxfd < 0 || maxfd > 65536) maxfd = 65536;
    for (int fd = 3; fd < maxfd; fd++) close(fd);
    /* execv() takes char *const[] for historical reasons only: POSIX never
     * writes through it, so the union passes the const array unchanged. */
    union { const char *const *ro; char *const *rw; } av = { .ro = argv };
    /* A bare name (make, cargo) is looked up on PATH, as the Rust port's Command does;
     * a path runs as given. */
    if (strchr(argv[0], '/')) execv(argv[0], av.rw);
    else execvp(argv[0], av.rw);
    _exit(127);
  }
  close(pipefd[1]);
  fcntl(pipefd[0], F_SETFL, fcntl(pipefd[0], F_GETFL) | O_NONBLOCK);
  size_t got = 0;
  int status = 0;
  bool done = false;
  for (int waited_ms = 0; waited_ms < timeout_s * 1000; waited_ms += 100) {
    char buf[256];
    ssize_t n;
    while ((n = read(pipefd[0], buf, sizeof(buf))) > 0) {
      if (out && got + 1 < out_size) {
        size_t take = (size_t)n < out_size - 1 - got ? (size_t)n : out_size - 1 - got;
        memcpy(out + got, buf, take);
        got += take;
        out[got] = '\0';
      }
    }
    stage_build_tick();
    if (waitpid(pid, &status, WNOHANG) == pid) {
      done = true;
      break;
    }
    struct timespec tick = {0, 100 * 1000 * 1000};
    nanosleep(&tick, NULL);
  }
  if (!done) {
    kill(pid, SIGKILL);
    waitpid(pid, &status, 0);
  }
  close(pipefd[0]);
  if (out) out[strcspn(out, "\r\n")] = '\0';
  if (!done) return -1;
  return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
}

/* Unpack `archive` into a scratch directory and run the binary in it with
 * -selftest, from this directory (so it reads this config and pass file).
 * Nothing live is touched either way; the scratch directory is removed. */
static bool staged_selftest(const char *archive, char *err, size_t err_size) {
  static const char *dir = "./ircbot_selftest_tmp";
  const char *rm[] = {"/bin/rm", "-rf", dir, NULL};
  run_bounded(rm, 30, NULL, 0);
  if (mkdir(dir, 0700) != 0) {
    snprintf(err, err_size, "could not stage the new build for its selftest");
    return false;
  }
  char out[256];
  const char *tar[] = {"/bin/tar", "-xzf", archive, "--strip-components=1",
                       "-C", dir, NULL};
  if (access("/bin/tar", X_OK) != 0) tar[0] = "/usr/bin/tar";
  if (run_bounded(tar, 60, out, sizeof(out)) != 0) {
    run_bounded(rm, 30, NULL, 0);
    snprintf(err, err_size, "could not unpack the new build for its selftest");
    return false;
  }
  char bin[64];
  snprintf(bin, sizeof(bin), "%s/ircbot", dir);
  const char *st[] = {bin, "-selftest", NULL};
  int rc = run_bounded(st, UPGRADE_SELFTEST_SECS, out, sizeof(out));
  run_bounded(rm, 30, NULL, 0);
  if (rc != 0) {
    if (out[0])
      snprintf(err, err_size, "new build failed its selftest: %.160s", out);
    else if (rc < 0)
      snprintf(err, err_size, "new build failed its selftest: timed out after %d s",
               UPGRADE_SELFTEST_SECS);
    else
      snprintf(err, err_size, "new build failed its selftest: exited with %d", rc);
    return false;
  }
  return true;
}

/* ---- Staging -------------------------------------------------------------
 * Get the new build ready and proven while the old one keeps running.  A child
 * does the work under STAGE_DIR and writes one status line after each phase; the
 * event loop reads it and tells the hub.  COMMIT then only swaps a file.  Nothing
 * here touches <exe>, and everything here is gone again if no COMMIT comes. */
#define STAGE_DIR ".upgrade.stage"

static pid_t g_stage_pid = 0;
static char g_stage_id[64] = "", g_stage_ver[64] = "";
static char g_stage_phase[16] = "", g_stage_code[16] = "", g_stage_note[192] = "";
static time_t g_stage_started = 0, g_stage_said = 0, g_stage_done = 0;
static bool g_stage_ready = false;

static void stage_rm(void) {
  const char *rm[] = {"/bin/rm", "-rf", STAGE_DIR, NULL};
  run_bounded(rm, 30, NULL, 0);
}

/* In the child: one line, atomically, for the parent to read. */
static void stage_say(const char *phase, const char *code, const char *note) {
  char clean[192];
  snprintf(clean, sizeof(clean), "%s", note ? note : "");
  for (char *c = clean; *c; c++)
    if (*c == '|' || *c == '\r' || *c == '\n') *c = ' ';
  FILE *f = fopen(STAGE_DIR "/status.tmp", "w");
  if (!f) return;
  fprintf(f, "%s|%s|%s\n", phase, code ? code : "", clean);
  if (fclose(f) == 0) (void)rename(STAGE_DIR "/status.tmp", STAGE_DIR "/status");
}

/* Files make has compiled so far: a top-level .c with its object in place. */
static void stage_count_c(const char *dir, int *total, int *done) {
  static const char *const where[] = {"", "build/", "build/obj/", "obj/"};
  DIR *d = opendir(dir);
  if (!d) return;
  struct dirent *e;
  while ((e = readdir(d)) != NULL) {
    size_t n = strlen(e->d_name);
    if (n < 3 || n > 200 || strcmp(e->d_name + n - 2, ".c") != 0) continue;
    (*total)++;
    for (size_t i = 0; i < sizeof(where) / sizeof(where[0]); i++) {
      char obj[512];
      snprintf(obj, sizeof(obj), "%s/%s%.*s.o", dir, where[i], (int)(n - 2), e->d_name);
      if (access(obj, F_OK) == 0) {
        (*done)++;
        break;
      }
    }
  }
  closedir(d);
}

/* Crates cargo has got to, against the packages its lock file names. */
static void stage_count_crates(const char *dir, int *total, int *done) {
  char path[512], line[64];
  snprintf(path, sizeof(path), "%s/Cargo.lock", dir);
  FILE *f = fopen(path, "r");
  if (!f) return;
  while (fgets(line, sizeof(line), f))
    if (strncmp(line, "[[package]]", 11) == 0) (*total)++;
  fclose(f);
  snprintf(path, sizeof(path), "%s/target/release/.fingerprint", dir);
  DIR *d = opendir(path);
  if (!d) return;
  struct dirent *e;
  while ((e = readdir(d)) != NULL)
    if (e->d_name[0] != '.') (*done)++;
  closedir(d);
}

/* From run_bounded's loop: at most one look every 5 s, and a word only on a change. */
static void stage_build_tick(void) {
  static time_t said = 0;
  static char last[64] = "";
  if (!g_stage_build) return;
  time_t t = time(NULL);
  if (t - said < 5) return;
  said = t;
  char path[512], note[64];
  int total = 0, done = 0;
  snprintf(path, sizeof(path), "%s/Cargo.toml", g_stage_build);
  bool crates = access(path, R_OK) == 0;
  if (crates) stage_count_crates(g_stage_build, &total, &done);
  else stage_count_c(g_stage_build, &total, &done);
  if (total <= 0) return;
  if (done > total) done = total;
  int pct = done * 100 / total;
  if (pct > 99) pct = 99;
  snprintf(note, sizeof(note), "%s%d%% %d of %d %s", crates ? "~" : "", pct, done, total,
           crates ? "crates" : "files");
  if (strcmp(note, last) == 0) return;
  snprintf(last, sizeof(last), "%s", note);
  stage_say("building", "src", note);
}

static void stage_fail(const char *code, const char *note) {
  stage_say("failed", code, note);
  _exit(1);
}

/* The whole job, in the child. */
static void stage_child(const char *ver, const char *variant, const char *exe) {
  (void)exe;
  char why[320] = "";
  /* A run names no variant unless the admin chose one: this host's own, as at PREPARE. */
  if (!variant || !variant[0]) variant = updater_host_variant();
  stage_say("fetching", "", "");
  if (!hub_set_tree(variant, why, sizeof(why))) stage_fail("net", why);
  const char *verr = NULL;
  char *manifest = fetch_verified_manifest(&verr);
  if (!manifest) {
    const char *t = verr ? verr : "manifest fetch failed";
    stage_fail(strstr(t, "signature") ? "sig" : "net", t);
  }
  manifest_row_t row;
  memset(&row, 0, sizeof(row));
  g_select_variant = variant;
  bool picked = manifest_select(manifest, ver, &row, why, sizeof(why));
  free(manifest);
  if (!picked) stage_fail("build", why[0] ? why : "no usable artifact");
  bool is_bin = strcasecmp(row.kind, "bin") == 0;
  const char *archive = STAGE_DIR "/archive.tar.gz";
  g_stage_fetching = true;
  bool fetched = download_file(row.url, archive);
  g_stage_fetching = false;
  if (!fetched) stage_fail("net", "artifact download failed");
  stage_say("verifying", is_bin ? "bin" : "src", "");
  if (!verify_sha256(archive, row.hash)) stage_fail("hash", "artifact SHA-256 mismatch");
  const char *bdir = STAGE_DIR "/build";
  if (mkdir(bdir, 0700) != 0) stage_fail("dir", "could not make the build directory");
  char out[256] = "";
  const char *tar[] = {"/bin/tar", "-xzf", archive, "--strip-components=1", "-C", bdir, NULL};
  if (access("/bin/tar", X_OK) != 0) tar[0] = "/usr/bin/tar";
  if (run_bounded(tar, 120, out, sizeof(out)) != 0)
    stage_fail("archive", "could not unpack the artifact");
  char bin[256];
  snprintf(bin, sizeof(bin), "%s/ircbot", bdir);
  if (!is_bin) {
    stage_say("building", "src", "");
    g_stage_build = bdir;
    char cargo[256];
    snprintf(cargo, sizeof(cargo), "%s/Cargo.toml", bdir);
    int rc;
    if (access(cargo, R_OK) == 0) {
      const char *cb[] = {"cargo", "build", "--release", "--manifest-path", cargo, NULL};
      rc = run_bounded(cb, UPGRADE_BUILD_SECS - 60, out, sizeof(out));
      snprintf(bin, sizeof(bin), "%s/target/release/ircbot", bdir);
    } else {
      const char *mk[] = {"make", "-C", bdir, NULL};
      rc = run_bounded(mk, UPGRADE_BUILD_SECS - 60, out, sizeof(out));
      
    }
    g_stage_build = NULL;
    if (rc < 0) stage_fail("build", "the build ran past its limit");
    if (rc != 0 || access(bin, F_OK) != 0) {
      snprintf(why, sizeof(why), "the build failed: %.200s", out);
      stage_fail("build", why);
    }
  }
  if (access(bin, F_OK) != 0) stage_fail("archive", "the artifact holds no ircbot binary");
  (void)chmod(bin, 0700);
  stage_say("testing", is_bin ? "bin" : "src", "");
  const char *st[] = {bin, "-selftest", NULL};
  int rc = run_bounded(st, UPGRADE_SELFTEST_SECS, out, sizeof(out));
  if (rc != 0) {
    snprintf(why, sizeof(why), "new build failed its selftest: %.200s",
             out[0] ? out : (rc < 0 ? "timed out" : "it exited with an error"));
    stage_fail("selftest", why);
  }
  if (rename(bin, STAGE_DIR "/new") != 0) stage_fail("dir", "could not keep the staged build");
  const char *rmb[] = {"/bin/rm", "-rf", bdir, archive, NULL};
  run_bounded(rmb, 60, NULL, 0);
  stage_say("staged", is_bin ? "bin" : "src", "");
  _exit(0);
}

/* A hub's STAGE.  Starting again for the same build is a no-op, so a repeat costs
 * nothing. */
void updater_stage_start(const char *exe, const char *id, const char *ver, const char *variant) {
  if (g_stage_id[0] && strcmp(g_stage_id, id) == 0 && (g_stage_pid > 0 || g_stage_ready)) return;
  updater_stage_clear();
  stage_rm();
  snprintf(g_stage_id, sizeof(g_stage_id), "%s", id);
  snprintf(g_stage_ver, sizeof(g_stage_ver), "%s", ver);
  snprintf(g_stage_phase, sizeof(g_stage_phase), "fetching");
  g_stage_code[0] = g_stage_note[0] = '\0';
  g_stage_started = time(NULL);
  g_stage_said = 0;
  if (mkdir(STAGE_DIR, 0700) != 0) {
    snprintf(g_stage_phase, sizeof(g_stage_phase), "failed");
    snprintf(g_stage_code, sizeof(g_stage_code), "dir");
    snprintf(g_stage_note, sizeof(g_stage_note), "could not make %s", STAGE_DIR);
    return;
  }
  pid_t pid = fork();
  if (pid == 0) {
    for (int fd = 3; fd < 1024; fd++) close(fd);
    /* It goes when the daemon goes: a stage belongs to one process. */
    (void)prctl(PR_SET_PDEATHSIG, SIGTERM);
    stage_child(ver, variant, exe);
    _exit(1);
  }
  if (pid < 0) {
    snprintf(g_stage_phase, sizeof(g_stage_phase), "failed");
    snprintf(g_stage_code, sizeof(g_stage_code), "fork");
    snprintf(g_stage_note, sizeof(g_stage_note), "could not start the stage");
    return;
  }
  g_stage_pid = pid;
}

void updater_stage_clear(void) {
  if (g_stage_pid > 0) {
    kill(g_stage_pid, SIGKILL);
    (void)waitpid(g_stage_pid, NULL, 0);
    g_stage_pid = 0;
  }
  if (g_stage_id[0]) stage_rm();
  g_stage_id[0] = g_stage_phase[0] = '\0';
  g_stage_ready = false;
}

/* True when the hub should hear: "phase|code|note" in out, with the run's id. */
bool updater_stage_tick(char *id, size_t id_size, char *out, size_t out_size) {
  if (!g_stage_id[0]) return false;
  time_t now = time(NULL);
  bool changed = false;
  if (g_stage_pid > 0) {
    char line[256];
    FILE *f = fopen(STAGE_DIR "/status", "r");
    if (f) {
      if (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\r\n")] = '\0';
        char *c1 = strchr(line, '|');
        char *c2 = c1 ? strchr(c1 + 1, '|') : NULL;
        if (c1 && c2) {
          *c1 = *c2 = '\0';
          if (strcmp(g_stage_phase, line) != 0) changed = true;
          snprintf(g_stage_phase, sizeof(g_stage_phase), "%.15s", line);
          snprintf(g_stage_code, sizeof(g_stage_code), "%.15s", c1 + 1);
          snprintf(g_stage_note, sizeof(g_stage_note), "%.191s", c2 + 1);
        }
      }
      fclose(f);
    }
    int st = 0;
    pid_t r = waitpid(g_stage_pid, &st, WNOHANG);
    if (r != 0) {
      g_stage_pid = 0;
      if (strcmp(g_stage_phase, "staged") == 0 && access(STAGE_DIR "/new", X_OK) == 0) {
        g_stage_ready = true;
        g_stage_done = now;
      } else if (strcmp(g_stage_phase, "failed") != 0) {
        snprintf(g_stage_phase, sizeof(g_stage_phase), "failed");
        snprintf(g_stage_code, sizeof(g_stage_code), "stopped");
        snprintf(g_stage_note, sizeof(g_stage_note), "the stage stopped before it finished");
      }
      changed = true;
    } else if (now - g_stage_started > UPGRADE_BUILD_SECS) {
      kill(g_stage_pid, SIGKILL);
      (void)waitpid(g_stage_pid, NULL, 0);
      g_stage_pid = 0;
      snprintf(g_stage_phase, sizeof(g_stage_phase), "failed");
      snprintf(g_stage_code, sizeof(g_stage_code), "limit");
      snprintf(g_stage_note, sizeof(g_stage_note), "the stage ran past its limit");
      changed = true;
    }
  }
  /* A failed stage holds nothing worth keeping, and the run may not come back to say so. */
  if (changed && g_stage_pid <= 0 && strcmp(g_stage_phase, "failed") == 0) stage_rm();
  if (g_stage_ready && now - g_stage_done > UPGRADE_STAGE_KEEP) {
    updater_stage_clear();
    return false;
  }
  /* A beat while it works: silence is how the driver tells a stage has died. */
  if (!changed && (g_stage_pid <= 0 || now - g_stage_said < UPGRADE_STAGE_BEAT)) {
    if (g_stage_said) return false;
  }
  g_stage_said = now;
  snprintf(id, id_size, "%s", g_stage_id);
  snprintf(out, out_size, "%s|%s|%s", g_stage_phase, g_stage_code, g_stage_note);
  return true;
}

/* A stage belongs to one process: whatever a dead one left is rubbish. */
void updater_stage_boot_clean(void) {
  if (access(STAGE_DIR, F_OK) == 0) stage_rm();
}

/* The staged build for this run, ready to swap in. */
static bool stage_ready_for(const char *id, const char *ver) {
  return g_stage_ready && strcmp(g_stage_id, id) == 0 && strcmp(g_stage_ver, ver) == 0 &&
         access(STAGE_DIR "/new", X_OK) == 0;
}

/* Write the upgrade script for a hub-driven commit.  `kind` decides the
 * middle of it: a prebuilt binary is unpacked and moved into place, a source
 * tarball is compiled first.  Either way the previous binary stays at
 * <exe>.prev — the hub, not the script, decides whether to keep it. */
/* Lay the script down and put it in cron, before anything changes.  A host with
 * no usable cron still has the upgrade script's own loop: it loses only the
 * reboot cover, and says so. */
static bool failback_stage(const char *exe, const char *id, bool is_bin,
                           const char *cfg, const char *pidf, const char *script,
                           const char *note) {
  if (!failback_write(FAILBACK_FILE, exe, id, is_bin, cfg, pidf, script, note, FAILBACK_FILE))
    return false;
  FILE *f;
  /* The state first: a tick that finds none takes the script away again.  exec
   * keeps this pid, so it already names the upgrade script. */
  remove(FAILBACK_CONFIRM);
  f = fopen(FAILBACK_STATE ".tmp", "w");
  if (!f) {
    remove(FAILBACK_FILE);
    return false;
  }
  fprintf(f, "%s|installing|%lld|%d|\n", id, (long long)time(NULL), (int)getpid());
  if (fclose(f) != 0 || rename(FAILBACK_STATE ".tmp", FAILBACK_STATE) != 0) {
    remove(FAILBACK_STATE ".tmp");
    remove(FAILBACK_FILE);
    return false;
  }
  return true;
}

static bool write_hub_upgrade_script(const bot_state_t *state, const char *kind,
                                     const char *archive, bool selftest) {
  /* 0700 at creation: no umask-dependent window on a script we are about to
   * exec (same reasoning as the standalone path). */
  int fd = open("upgrade.sh", O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0700);
  FILE *f = (fd >= 0) ? fdopen(fd, "w") : NULL;
  if (!f) {
    if (fd >= 0) close(fd);
    return false;
  }
  const char *exe = state->executable_path;
  bool is_bin = (strcasecmp(kind, "bin") == 0);
  bool is_staged = (strcasecmp(kind, "staged") == 0);

  fprintf(f, "#!/bin/bash\n");
  fprintf(f, "set -u\n");
  fprintf(f, "OLD_PID=%d\n", getpid());
  /* The bot execs this script, so OLD_PID is usually the script itself;
   * waiting on it would only burn 30 s of every restart. */
  fprintf(f, "for i in $(seq 1 30); do\n");
  fprintf(f, "  [ \"$OLD_PID\" = \"$$\" ] && break\n");
  fprintf(f, "  kill -0 $OLD_PID 2>/dev/null || break\n");
  fprintf(f, "  sleep 1\n");
  fprintf(f, "done\n");
  fprintf(f, "UPGRADE_DIR=\"./bot_build_tmp\"\n");
  fprintf(f, "rm -rf \"$UPGRADE_DIR\"\n");
  fprintf(f, "mkdir \"$UPGRADE_DIR\" || exit 1\n");
  /* One rollback path for every failure below: put <exe>.prev back and run
   * it, so a bot that cannot upgrade still comes back on the old build. */
  fprintf(f, "rollback() {\n");
  fprintf(f, "  echo \"[UPGRADE] FAILED: $1 — restoring previous build\"\n");
  fprintf(f, "  ./" FAILBACK_FILE " restore \"$1\"\n");
  fprintf(f, "  rm -rf \"$UPGRADE_DIR\" \"%s\"\n", archive);
  fprintf(f, "  wait\n");
  fprintf(f, "  rm -f \"./upgrade.sh\"\n");
  fprintf(f, "  exit 0\n");
  fprintf(f, "}\n");
  /* The failback's loop runs through every phase, so a hung build or a new
   * build that never confirms is undone even with no cron on this host. */
  fprintf(f, "./" FAILBACK_FILE " phase installing $$\n");
  fprintf(f, "( while ./" FAILBACK_FILE " tick; do sleep 10; done ) </dev/null >/dev/null 2>&1 &\n");
  if (!is_staged)
  fprintf(f, "tar -xzf \"%s\" --strip-components=1 -C \"$UPGRADE_DIR\" "
             "2>/dev/null || rollback \"could not extract artifact\"\n",
          archive);

  if (is_staged) {
    /* Fetched, built and selftested while the old build ran: only the swap is left. */
    fprintf(f, "NEW_BIN=\"" STAGE_DIR "/new\"\n");
    fprintf(f, "[ -x \"$NEW_BIN\" ] || rollback \"the staged build is gone\"\n");
  } else if (is_bin) {
    /* Prebuilt: the tarball holds the binary itself, no toolchain needed. */
    fprintf(f, "NEW_BIN=\"$UPGRADE_DIR/ircbot\"\n");
    fprintf(f, "[ -f \"$NEW_BIN\" ] || rollback \"artifact contains no ircbot binary\"\n");
    fprintf(f, "chmod 700 \"$NEW_BIN\"\n");
    /* No "run it once" probe here: ircbot has no --version flag and starting
     * a second instance would fight the one we are replacing.  The hub is the
     * health monitor — it waits for this node to reappear announcing the new
     * version and sends CMD_UPGRADE_ABORT if it never does. */
    fprintf(f, "[ -x \"$NEW_BIN\" ] || rollback \"artifact binary is not executable\"\n");
  } else {
    fprintf(f, "cd \"$UPGRADE_DIR\" || rollback \"build directory vanished\"\n");
    fprintf(f, "make clean >/dev/null 2>&1\n");
    fprintf(f, "make >make.log 2>&1\n");
    fprintf(f, "cd ..\n");
    fprintf(f, "NEW_BIN=\"$UPGRADE_DIR/ircbot\"\n");
    fprintf(f, "[ -f \"$NEW_BIN\" ] || rollback \"build failed (see $UPGRADE_DIR/make.log)\"\n");
    /* A prebuilt binary was selftested before the swap; a source build can
     * only be checked here, once it exists. */
    if (selftest)
      fprintf(f, "\"$NEW_BIN\" -selftest >/dev/null 2>&1 || rollback \"new build failed its selftest\"\n");
  }

  /* Atomic same-directory rename into place; <exe> was already renamed to
   * <exe>.prev, which we keep for the hub's rollback window. */
  fprintf(f, "mv -f \"$NEW_BIN\" \"%s\" || rollback \"could not install new binary\"\n", exe);
  fprintf(f, "chmod 700 \"%s\"\n", exe);
  fprintf(f, "rm -f \"%s\"\n", PID_FILE);
  fprintf(f, "rm -rf \"$UPGRADE_DIR\" \"%s\" 2>/dev/null\n", archive);
  /* From here the failback decides.  The marker stays either way, so a restored
   * build reports why on its first link. */
  fprintf(f, "rm -rf " STAGE_DIR " 2>/dev/null\n");
  fprintf(f, "./" FAILBACK_FILE " phase started $$\n");
  fprintf(f, "\"%s\" </dev/null >/dev/null 2>&1\n", exe);
  fprintf(f, "wait\n");
  fprintf(f, "rm -f \"./upgrade.sh\"\n");
  fprintf(f, "exit 0\n");

  (void)fchmod(fileno(f), 0700);
  return fclose(f) == 0;
}

/* Run the upgrade the hub just committed us to.  Returns false with *err set
 * when nothing was touched (the caller answers CMD_UPGRADE_RESULT fail and
 * stays on the current build); on success it does not return — the process is
 * replaced and reports in after the restart. */
bool updater_hub_commit(bot_state_t *state, const char *upgrade_id,
                        const char *target_ver, const char *variant,
                        const char **err) {
  *err = NULL;
  if (!state || !upgrade_id || !target_ver) {
    *err = "malformed upgrade command";
    return false;
  }

  const char *want_variant = (variant && variant[0]) ? variant
                                                     : updater_host_variant();
  static char why_local[320];
  if (!hub_local_check(state, target_ver, want_variant, "", why_local,
                       sizeof(why_local)) ||
      !hub_set_tree(want_variant, why_local, sizeof(why_local))) {
    *err = why_local;
    return false;
  }
  log_message(L_INFO, state, "[UPGRADE] Hub commit %s: %s -> %s (variant %s)\n",
              upgrade_id, BOT_VERSION, target_ver, want_variant);

  manifest_row_t row;
  memset(&row, 0, sizeof(row));
  char archive[256] = "";
  bool staged = stage_ready_for(upgrade_id, target_ver);
  if (staged) {
    snprintf(row.kind, sizeof(row.kind), "staged");
    log_message(L_INFO, state, "[UPGRADE] Using the build staged for %s\n", target_ver);
  } else {
  updater_stage_clear();
  const char *verr = NULL;
  char *manifest = fetch_verified_manifest(&verr);
  if (!manifest) {
    *err = verr ? verr : "manifest fetch failed";
    return false;
  }

  static char why[320];
  g_select_variant = want_variant;
  bool picked = manifest_select(manifest, target_ver, &row, why, sizeof(why));
  g_select_variant = NULL;
  free(manifest);
  if (!picked) {
    *err = why[0] ? why : "no usable artifact";
    return false;
  }

  const char *slash = strrchr(row.url, '/');
  if (!sanitize_filename(slash ? slash + 1 : "ircbot.tar.gz", archive,
                         sizeof(archive))) {
    *err = "artifact filename in manifest is not acceptable";
    return false;
  }

  /* Every release artifact is named "<product>-…tar.gz" (see the releases
   * repo README).  A base override that names the OTHER product's tree would
   * otherwise hand this daemon the wrong binary and install it over itself —
   * fail closed here instead, where nothing has been downloaded yet. */
  if (strncmp(archive, "ircbot-", 7) != 0) {
    *err = "manifest artifact is not a ircbot release";
    return false;
  }

  log_message(L_INFO, state, "[UPGRADE] Fetching %s artifact %s\n", row.kind,
              archive);
  if (!download_file(row.url, archive)) {
    *err = "artifact download failed";
    return false;
  }
  if (!verify_sha256(archive, row.hash)) {
    remove(archive);
    *err = "artifact SHA-256 mismatch";
    return false;
  }

  /* Run the NEW binary's -selftest before anything is swapped: CPU, libraries
   * and this very config, checked by the build that would have to run on
   * them; a source build is checked by the script. */
  if (updater_version_cmp(target_ver, UPGRADE_TARGET_MIN) < 0) {
    remove(archive);
    *err = "target predates " UPGRADE_TARGET_MIN ", the oldest the mesh links with";
    return false;
  }
  if (strcasecmp(row.kind, "bin") == 0) {
    static char st_err[320];
    if (!staged_selftest(archive, st_err, sizeof(st_err))) {
      remove(archive);
      *err = st_err;
      return false;
    }
    log_message(L_INFO, state, "[UPGRADE] Staged %s passed its selftest\n",
                target_ver);
  }
  }

  /* Flush the live config, then snapshot the pair we may have to restore.
   * Both are copied: <exe> stays in place until the new one is renamed over it,
   * so there is never a moment with no binary there. */
  unsigned long saves = config_saves();
  config_write_with_state_pass(state);
  if (config_saves() == saves) {
    if (archive[0]) remove(archive);
    *err = "could not save the config before the swap";
    return false;
  }
  char prev_cfg[PATH_MAX];
  char prev_exe[PATH_MAX + 8];
  if (snprintf(prev_cfg, sizeof(prev_cfg), "%s%s", CONFIG_FILE,
               UPGRADE_PREV_SUFFIX) >= (int)sizeof(prev_cfg) ||
      snprintf(prev_exe, sizeof(prev_exe), "%s%s", state->executable_path,
               UPGRADE_PREV_SUFFIX) >= (int)sizeof(prev_exe)) {
    remove(archive);
    *err = "path too long for rollback snapshot";
    return false;
  }
  if (!copy_file(CONFIG_FILE, prev_cfg, 0600)) {
    remove(archive);
    *err = "could not snapshot config for rollback";
    return false;
  }
  char prev_tmp[PATH_MAX + 16];
  snprintf(prev_tmp, sizeof(prev_tmp), "%s.tmp", prev_exe);
  if (!copy_file(state->executable_path, prev_tmp, 0700) ||
      rename(prev_tmp, prev_exe) != 0) {
    remove(prev_tmp);
    remove(prev_cfg);
    remove(archive);
    *err = "could not retain previous binary";
    return false;
  }
  /* From here a failure is the script's to handle: it restores <exe>.prev
   * and restarts the old build rather than leaving the node with no binary. */
  /* The channels this bot holds ops in right now: the new build reports done
   * only once it holds them again (see UPGRADE_OPS_WAIT). */
  char ops[UPGRADE_OPS_MAX] = "";
  for (chan_t *c = state->chanlist; c; c = c->next) {
    if (c->status != C_IN || !c->i_am_opped) continue;
    size_t ol = strlen(ops);
    if (ol + strlen(c->name) + 2 >= sizeof(ops)) break;
    snprintf(ops + ol, sizeof(ops) - ol, "%s%s", ol ? " " : "", c->name);
  }
  if (!upgrade_marker_write(upgrade_id, target_ver, want_variant, ops) ||
      !write_hub_upgrade_script(state, row.kind, archive, true) ||
      !failback_stage(state->executable_path, upgrade_id,
                      strcasecmp(row.kind, "src") != 0, CONFIG_FILE, PID_FILE,
                      "upgrade.sh", state->hub_count ? "no hub link and IRC" : "no IRC")) {
    failback_clear();
    remove(UPGRADE_MARKER_FILE);
    remove(prev_exe);
    remove(prev_cfg);
    remove(archive);
    *err = "could not stage the upgrade script";
    return false;
  }

  int cron = failback_run("install");
  if (cron != 0)
    log_message(L_INFO, state,
                "[UPGRADE] No cron failback on this host (%d): it will not survive "
                "a reboot during this upgrade\n", cron);
  log_message(L_INFO, state, "[UPGRADE] Installing %s and restarting\n",
              target_ver);
  irc_printf(state, "QUIT :Upgrading to %s (hub-managed)...\r\n", target_ver);
  irc_disconnect(state);
  dcc_close_all(state, "Bot upgrading; closing.");
  hub_client_disconnect(state);
  close(state->pid_fd);
  sleep(1);

  execl("./upgrade.sh", "./upgrade.sh", NULL);
  /* exec failed: <exe> was never moved, so this node is still whole. */
  failback_clear();
  remove(prev_exe);
  remove(UPGRADE_MARKER_FILE);
  handle_fatal_error("execl upgrade.sh");
}
#else /* !HAVE_CURL */
int updater_check_cli(const char *variant) {
  (void)variant;
  printf("checkupdate: FAIL bot compiled without curl support\n");
  return 1;
}

void updater_check_for_updates(bot_state_t *state, const char *nick) {
  irc_printf(state, "PRIVMSG %s :Update feature unavailable - bot compiled without curl support.\r\n", nick);
}

void updater_perform_upgrade(bot_state_t *state, const char *nick,
                             const char *version_to_install) {
  (void)version_to_install;  /* Unused parameter */
  irc_printf(state, "PRIVMSG %s :Update feature unavailable - bot compiled without curl support.\r\n", nick);
}

bool updater_hub_prepare_check(bot_state_t *state, const char *target_ver,
                               const char *variant, const char *min_from,
                               char *reason, size_t reason_size) {
  (void)state; (void)target_ver; (void)variant; (void)min_from;
  snprintf(reason, reason_size, "bot compiled without curl support");
  return false;
}

void updater_stage_start(const char *exe, const char *id, const char *ver, const char *variant) {
  (void)exe; (void)id; (void)ver; (void)variant;
}
void updater_stage_clear(void) {}
void updater_stage_boot_clean(void) {}
bool updater_stage_tick(char *id, size_t id_size, char *out, size_t out_size) {
  (void)id; (void)id_size; (void)out; (void)out_size;
  return false;
}

bool updater_hub_commit(bot_state_t *state, const char *upgrade_id,
                        const char *target_ver, const char *variant,
                        const char **err) {
  (void)state; (void)upgrade_id; (void)target_ver; (void)variant;
  *err = "bot compiled without curl support";
  return false;
}
#endif /* HAVE_CURL */
