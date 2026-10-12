#ifndef GLOB_OVERLAP_H
#define GLOB_OVERLAP_H

#include <stdbool.h>

/* Longest pattern glob_overlap() will analyse; longer input is reported as
 * overlapping (fail closed: callers use it to refuse unsafe bans). */
#define GLOB_OVERLAP_MAX 256

/* True when at least one string is matched by BOTH glob patterns, where '*'
 * matches any run (including none) and '?' any one character.  Letters
 * compare ASCII case-insensitively.  Pure; no allocation; O(len(a)*len(b)).
 * The hub carries an identical helper. */
bool glob_overlap(const char *a, const char *b);

#endif
