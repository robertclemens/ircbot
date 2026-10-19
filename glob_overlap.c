#include <ctype.h>
#include <string.h>

#include "glob_overlap.h"

/* ov(i,j): is there a string matched by a[i..] and by b[j..]?
 *   both ended                 -> yes
 *   a[i] == '*'                -> ov(i+1,j)  (star empty)
 *                                 or, if b has a symbol left, ov(i,j+1)
 *                                 (star swallows that symbol of b)
 *   b[j] == '*'                -> symmetric
 *   one ended, other not '*'   -> no
 *   else                       -> symbols compatible and ov(i+1,j+1)
 * Filled bottom-up in two rolling rows. */
bool glob_overlap(const char *a, const char *b) {
  if (!a || !b)
    return true;
  size_t la = strlen(a), lb = strlen(b);
  if (la > GLOB_OVERLAP_MAX || lb > GLOB_OVERLAP_MAX)
    return true;

  unsigned char row[2][GLOB_OVERLAP_MAX + 2];
  unsigned char *next = row[0], *cur = row[1]; /* row i+1, row i */

  /* Row i = la: a has ended. */
  next[lb] = 1;
  for (size_t j = lb; j-- > 0;)
    next[j] = (b[j] == '*') ? next[j + 1] : 0;

  for (size_t i = la; i-- > 0;) {
    cur[lb] = (a[i] == '*') ? next[lb] : 0; /* b ended */
    for (size_t j = lb; j-- > 0;) {
      unsigned char r;
      if (a[i] == '*' || b[j] == '*') {
        r = next[j] | cur[j + 1];
      } else if (a[i] == '?' || b[j] == '?' ||
                 tolower((unsigned char)a[i]) == tolower((unsigned char)b[j])) {
        r = next[j + 1];
      } else {
        r = 0;
      }
      cur[j] = r;
    }
    unsigned char *t = next;
    next = cur;
    cur = t;
  }
  return next[0] != 0;
}

/* Split "nick!user@host" into its three parts (each at most GLOB_OVERLAP_MAX
 * bytes, which a whole pattern within the limit always satisfies). */
static bool hm_split(const char *m, char nick[], char user[], char host[]) {
  const char *bang = strchr(m, '!');
  const char *at = bang ? strchr(bang + 1, '@') : NULL;
  if (!at || strlen(m) > GLOB_OVERLAP_MAX)
    return false;
  memcpy(nick, m, (size_t)(bang - m));
  nick[bang - m] = '\0';
  memcpy(user, bang + 1, (size_t)(at - bang - 1));
  user[at - bang - 1] = '\0';
  strcpy(host, at + 1);
  return true;
}

/* Host pattern kind: 'i' address, 'n' name, 'a' wildcards only (either). */
static char host_kind(const char *h) {
  bool digit = false, other = false;
  for (; *h; h++) {
    unsigned char c = (unsigned char)*h;
    if (c == ':')
      return 'i';
    if (c >= '0' && c <= '9')
      digit = true;
    else if (c != '.' && c != '*' && c != '?')
      other = true;
  }
  return other ? 'n' : digit ? 'i' : 'a';
}

bool hostmask_overlap(const char *a, const char *b) {
  if (!a || !b)
    return true;
  char an[GLOB_OVERLAP_MAX + 1], au[GLOB_OVERLAP_MAX + 1], ah[GLOB_OVERLAP_MAX + 1];
  char bn[GLOB_OVERLAP_MAX + 1], bu[GLOB_OVERLAP_MAX + 1], bh[GLOB_OVERLAP_MAX + 1];
  if (!hm_split(a, an, au, ah) || !hm_split(b, bn, bu, bh))
    return glob_overlap(a, b);
  char ka = host_kind(ah), kb = host_kind(bh);
  if (ka != 'a' && kb != 'a' && ka != kb)
    return false;
  return glob_overlap(an, bn) && glob_overlap(au, bu) && glob_overlap(ah, bh);
}
