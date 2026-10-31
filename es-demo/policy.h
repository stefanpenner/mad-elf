#ifndef MADELF_ES_POLICY_H
#define MADELF_ES_POLICY_H

#include <stddef.h>

/* Allowlist file format (one rule per line):
 *   path /absolute/binary
 *   prefix /usr/bin/
 *   teamid ABCDE12345
 *   signingid com.example.tool
 * Blank lines and lines starting with # are ignored.
 * The mode file contains "monitor" or "enforce".
 */

typedef enum {
    MADELF_ES_PATH = 1,
    MADELF_ES_PREFIX = 2,
    MADELF_ES_TEAMID = 3,
    MADELF_ES_SIGNINGID = 4
} madelf_es_kind;

typedef struct {
    madelf_es_kind kind;
    char value[1024];
} madelf_es_rule;

typedef struct {
    madelf_es_rule *rules;
    size_t count;
    int enforce; /* 0 = monitor (allow all), 1 = deny anything that does not match */
} madelf_es_policy;

/* Missing files yield an empty allowlist and monitor mode. Returns 0, or -1
 * if a file exists but cannot be read. */
int madelf_es_policy_load(const char *allowlist_path, const char *mode_path,
                          madelf_es_policy *out);
void madelf_es_policy_free(madelf_es_policy *policy);

/* 1 if any rule matches. Does not consult enforce; the caller does. */
int madelf_es_policy_match(const madelf_es_policy *policy, const char *path,
                           const char *teamid, const char *signingid);

#endif
