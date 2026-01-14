#include <arpa/inet.h>
#include <ctype.h>
#include <curl/curl.h>
#include <netdb.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <unistd.h>

#include "bot.h"

void handle_fatal_error(const char *message) {
  perror(message);
  exit(EXIT_FAILURE);
}

void get_local_ip(bot_state_t *state) {
  char hostname[256];
  if (gethostname(hostname, sizeof(hostname)) != 0) return;
  struct addrinfo hints, *info;
  memset(&hints, 0, sizeof(hints));
  hints.ai_family = AF_INET;
  if (getaddrinfo(hostname, NULL, &hints, &info) != 0) return;
  struct sockaddr_in *sa = (struct sockaddr_in *)info->ai_addr;
  state->local_ip_long = ntohl(sa->sin_addr.s_addr);
  freeaddrinfo(info);
}

int strverscmp(const char *s1, const char *s2) {
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

static size_t write_callback(void *contents, size_t size, size_t nmemb,
                             void *userp) {
  size_t realsize = size * nmemb;
  http_response_t *mem = (http_response_t *)userp;

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

static size_t write_file_callback(void *ptr, size_t size, size_t nmemb,
                                  FILE *stream) {
  return fwrite(ptr, size, nmemb, stream);
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

  CURLcode res = curl_easy_perform(curl_handle);
  curl_easy_cleanup(curl_handle);

  return (res == CURLE_OK);
}

static bool download_file(const char *url, const char *outfile) {
  CURL *curl = curl_easy_init();
  if (!curl) return false;

  FILE *fp = fopen(outfile, "wb");
  if (!fp) {
    curl_easy_cleanup(curl);
    return false;
  }

  curl_easy_setopt(curl, CURLOPT_URL, url);
  curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_file_callback);
  curl_easy_setopt(curl, CURLOPT_WRITEDATA, fp);
  curl_easy_setopt(curl, CURLOPT_USERAGENT, "ircbot-updater/1.0");
  curl_easy_setopt(curl, CURLOPT_FOLLOWLOCATION, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 1L);
  curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 2L);

  CURLcode res = curl_easy_perform(curl);
  curl_easy_cleanup(curl);
  fclose(fp);

  return (res == CURLE_OK);
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
  int bytes_read = 0;
  while ((bytes_read = fread(buffer, 1, sizeof(buffer), f))) {
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
    offset += sprintf(hex_hash + offset, "%02x", hash[i]);
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

static bool validate_url(const char *url) {
  if (!url) return false;
  if (strncmp(url, "https://", 8) != 0) {
    return false;
  }
  if (strstr(url, "github.com") == NULL && 
      strstr(url, "githubusercontent.com") == NULL) {
    return false;
  }
  if (strstr(url, ";") || strstr(url, "|") || strstr(url, "&") ||
      strstr(url, "`") || strstr(url, "$") || strstr(url, "$(")) {
    return false;
  }
  return true;
}

void updater_check_for_updates(bot_state_t *state, const char *nick) {
  log_message(L_DEBUG, state, "[DEBUG] updater_check_for_updates called.\n");
  http_response_t response;
  response.buffer = NULL;

  if (!fetch_url(BOT_UPDATE_URL, &response)) {
    irc_printf(state, "PRIVMSG %s :Failed to download release file.\r\n", nick);
    return;
  }

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
      if (strverscmp(version, BOT_VERSION) > 0) {
        updates_found++;
        char deps_status[512] = "[OK]";
        bool all_deps_ok = true;

        char deps_copy[256];
        strncpy(deps_copy, deps, sizeof(deps_copy) - 1);
        deps_copy[sizeof(deps_copy) - 1] = '\0';
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

void updater_perform_upgrade(bot_state_t *state, const char *nick,
                             const char *version_to_install) {
  log_message(L_DEBUG, state,
              "[DEBUG] updater_perform_upgrade called for %s.\n",
              version_to_install);

  http_response_t response;
  response.buffer = NULL;
  char *binary_url = NULL;
  char *expected_hash = NULL;
  char *deps_to_check = NULL;

  if (!fetch_url(BOT_UPDATE_URL, &response)) {
    irc_printf(state, "PRIVMSG %s :Failed to download release file.\r\n", nick);
    return;
  }

  char *saveptr;
  char *line = strtok_r(response.buffer, "\n", &saveptr);

  while (line) {
    char version[64], date[64], url[512], hash[128], deps[256];
    if (sscanf(line, "%63s %63s %511s %127s %255s", version, date, url, hash,
               deps) == 5) {
      if (strcasecmp(version, version_to_install) == 0) {
        if (!validate_url(url)) {
          irc_printf(state, "PRIVMSG %s :Error: Invalid or untrusted URL in release file.\r\n", nick);
          free(response.buffer);
          return;
        }
        binary_url = strdup(url);
        expected_hash = strdup(hash);
        deps_to_check = strdup(deps);
        break;
      }
    }
    line = strtok_r(NULL, "\n", &saveptr);
  }

  if (!binary_url) {
    irc_printf(state,
               "PRIVMSG %s :Error: Version '%s' not found in release file.\r\n",
               nick, version_to_install);
    if (response.buffer) free(response.buffer);
    return;
  }
  if (response.buffer) {
    free(response.buffer);
    response.buffer = NULL;
  }

  char failed_deps[256] = "";
  bool all_deps_ok = true;
  char *dep = strtok_r(deps_to_check, ",", &saveptr);
  while (dep) {
    if (!check_dependency(dep)) {
      if (!all_deps_ok)
        strncat(failed_deps, ", ",
                sizeof(failed_deps) - strlen(failed_deps) - 1);
      strncat(failed_deps, dep, sizeof(failed_deps) - strlen(failed_deps) - 1);
      all_deps_ok = false;
    }
    dep = strtok_r(NULL, ",", &saveptr);
  }
  free(deps_to_check);

  if (!all_deps_ok) {
    irc_printf(
        state,
        "PRIVMSG %s :Error: Cannot upgrade. Missing dependencies: %s\r\n", nick,
        failed_deps);
    free(binary_url);
    free(expected_hash);
    return;
  }

  const char *url_filename = strrchr(binary_url, '/');
  if (url_filename) {
    url_filename++;
  } else {
    url_filename = "ircbot.tar.gz";
  }
  char safe_filename[256];
  if (!sanitize_filename(url_filename, safe_filename, sizeof(safe_filename))) {
    irc_printf(state, "PRIVMSG %s :Error: Invalid filename in URL.\r\n", nick);
    free(binary_url);
    free(expected_hash);
    return;
  }

  irc_printf(state, "PRIVMSG %s :Downloading %s...\r\n", nick, safe_filename);
  if (!download_file(binary_url, safe_filename)) {
    irc_printf(state, "PRIVMSG %s :Error: Failed to download new version.\r\n",
               nick);
    free(binary_url);
    free(expected_hash);
    return;
  }

  irc_printf(state, "PRIVMSG %s :Verifying hash...\r\n", nick);
  if (!verify_sha256(safe_filename, expected_hash)) {
    irc_printf(state,
               "PRIVMSG %s :Error: SHA256 hash mismatch! Aborting upgrade.\r\n",
               nick);
    remove(safe_filename);
    free(binary_url);
    free(expected_hash);
    return;
  }

  free(binary_url);
  free(expected_hash);

  char dir_name[256];
  strncpy(dir_name, safe_filename, sizeof(dir_name) - 1);
  dir_name[sizeof(dir_name) - 1] = '\0';
  char *tar_gz = strstr(dir_name, ".tar.gz");
  if (tar_gz) {
    *tar_gz = '\0';
  } else {
    irc_printf(
        state,
        "PRIVMSG %s :Error: Invalid archive name. Must end in .tar.gz\r\n",
        nick);
    remove(safe_filename);
    return;
  }
  config_write(state, state->startup_password);
  char backup_path[PATH_MAX + 8];
  snprintf(backup_path, sizeof(backup_path), "%s.backup", state->executable_path);
  rename(state->executable_path, backup_path);

  irc_printf(state, "PRIVMSG %s :Hash verified. Creating upgrade script...\r\n",
             nick);

  FILE *f = fopen("upgrade.sh", "w");
  if (!f) {
    irc_printf(state,
               "PRIVMSG %s :Error: Could not create upgrade.sh script.\r\n",
               nick);
    remove(safe_filename);
    rename(backup_path, state->executable_path);
    return;
  }

  fprintf(f, "#!/bin/bash\n");
  fprintf(f, "set -e\n");
  fprintf(f, "OLD_PID=%d\n", getpid());
  fprintf(f, "echo \"[UPGRADE] Waiting for old process (PID: $OLD_PID) to exit...\"\n");
  fprintf(f, "for i in {1..30}; do\n");
  fprintf(f, "  if ! kill -0 $OLD_PID 2>/dev/null; then\n");
  fprintf(f, "    break\n");
  fprintf(f, "  fi\n");
  fprintf(f, "  sleep 1\n");
  fprintf(f, "done\n");
  fprintf(f, "UPGRADE_DIR=\"./bot_build_tmp\"\n");
  fprintf(f, "rm -rf \"$UPGRADE_DIR\"\n");
  fprintf(f, "mkdir \"$UPGRADE_DIR\"\n");
  fprintf(f, "if [ ! -d \"$UPGRADE_DIR\" ]; then\n");
  fprintf(f, "  echo \"[UPGRADE] FATAL: Could not create build directory.\"\n");
  fprintf(f, "  exit 1\n");
  fprintf(f, "fi\n");
  fprintf(f, "echo \"[UPGRADE] Unpacking archive...\"\n");
  fprintf(f, "tar -xzf \"%s\" --strip-components=1 -C \"$UPGRADE_DIR\" 2>/dev/null\n", 
          safe_filename);
  fprintf(f, "if [ $? -ne 0 ]; then\n");
  fprintf(f, "  echo \"[UPGRADE] FATAL: Failed to extract archive.\"\n");
  fprintf(f, "  mv \"%s\" \"%s\" 2>/dev/null\n", backup_path, state->executable_path);
  fprintf(f, "  exit 1\n");
  fprintf(f, "fi\n");
  fprintf(f, "echo \"[UPGRADE] Entering $UPGRADE_DIR and compiling...\"\n");
  fprintf(f, "cd \"$UPGRADE_DIR\"\n");
  fprintf(f, "make clean >/dev/null 2>&1\n");
  fprintf(f, "make 2>&1 | tee make.log\n");
  fprintf(f, "if [ ! -f ircbot ]; then\n");
  fprintf(f, "  echo \"[UPGRADE] FATAL: Make failed. Binary not found.\"\n");
  fprintf(f, "  echo \"[UPGRADE] Restoring backup...\"\n");
  fprintf(f, "  cd ..\n");
  fprintf(f, "  mv \"%s\" \"%s\" 2>/dev/null\n", backup_path, state->executable_path);
  fprintf(f, "  rm -f \"%s\"\n", PID_FILE);
  fprintf(f, "  rm -rf \"$UPGRADE_DIR\"\n");
  fprintf(f, "  rm -f \"%s\"\n", safe_filename);
  fprintf(f, "  exit 1\n");
  fprintf(f, "fi\n");
  fprintf(f, "echo \"[UPGRADE] Moving new binary into place...\"\n");
  fprintf(f, "mv ircbot \"%s\"\n", state->executable_path);
  fprintf(f, "chmod 700 \"%s\"\n", state->executable_path);
  fprintf(f, "cd ..\n");
  fprintf(f, "echo \"[UPGRADE] Removing old PID file...\"\n");
  fprintf(f, "rm -f \"%s\"\n", PID_FILE);
  fprintf(f, "echo \"[UPGRADE] Removing backup...\"\n");
  fprintf(f, "rm -f \"%s\"\n", backup_path);
  fprintf(f, "echo \"[UPGRADE] Scheduling cleanup...\"\n");
  fprintf(f, "(sleep 5; rm -rf \"$UPGRADE_DIR\" \"%s\" \"./upgrade.sh\" 2>/dev/null) &\n",
          safe_filename);
  fprintf(f, "echo \"[UPGRADE] Restarting bot...\"\n");
  fprintf(f, "exec %s\n", state->executable_path);

  fclose(f);

  chmod("upgrade.sh", 0700);

  irc_printf(state, "QUIT :Upgrading to %s...\r\n", version_to_install);
  irc_disconnect(state);
  close(state->pid_fd);

  sleep(1);

  execl("./upgrade.sh", "./upgrade.sh", NULL);

  perror("execl failed");
  exit(1);
}
