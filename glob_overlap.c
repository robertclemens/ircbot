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
