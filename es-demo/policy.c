#include "policy.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static void trim(char *s) {
    char *start = s;
    size_t n;
    while (*start == ' ' || *start == '\t' || *start == '\r') start++;
    if (start != s) memmove(s, start, strlen(start) + 1);
    n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' ||
                     s[n - 1] == '\r' || s[n - 1] == '\n')) {
        s[--n] = 0;
    }
}

static int add_rule(madelf_es_policy *policy, madelf_es_kind kind, const char *value) {
    madelf_es_rule *grown;
    if (!value || !value[0] || strlen(value) >= sizeof policy->rules[0].value) return -1;
    grown = realloc(policy->rules, (policy->count + 1) * sizeof(*policy->rules));
    if (!grown) return -1;
    policy->rules = grown;
    snprintf(policy->rules[policy->count].value,
             sizeof policy->rules[policy->count].value, "%s", value);
    policy->rules[policy->count].kind = kind;
    policy->count++;
    return 0;
}

static int load_allowlist_file(const char *path, madelf_es_policy *policy) {
    FILE *f;
    char line[2048];
    if (!path || !path[0]) return 0;
    f = fopen(path, "r");
    if (!f) return (errno == ENOENT) ? 0 : -1;
    while (fgets(line, sizeof line, f)) {
        char *rest;
        madelf_es_kind kind;
        if (strchr(line, '\n') == NULL && !feof(f)) {
            fclose(f);
            return -1;
        }
        trim(line);
        if (line[0] == 0 || line[0] == '#') continue;
        rest = strchr(line, ' ');
        if (!rest) {
            fclose(f);
            return -1;
        }
        *rest++ = 0;
        trim(rest);
        if (strcmp(line, "path") == 0) kind = MADELF_ES_PATH;
        else if (strcmp(line, "prefix") == 0) kind = MADELF_ES_PREFIX;
        else if (strcmp(line, "teamid") == 0) kind = MADELF_ES_TEAMID;
        else if (strcmp(line, "signingid") == 0) kind = MADELF_ES_SIGNINGID;
        else {
            fclose(f);
            return -1;
        }
        if (add_rule(policy, kind, rest) != 0) {
            fclose(f);
            return -1;
        }
    }
    fclose(f);
    return 0;
}

int madelf_es_policy_load(const char *allowlist_path, const char *mode_path,
                          madelf_es_policy *out) {
    FILE *mode;
    char buf[64];
    memset(out, 0, sizeof *out);
    if (load_allowlist_file(allowlist_path, out) != 0) {
        madelf_es_policy_free(out);
        memset(out, 0, sizeof *out);
        return -1;
    }
    if (!mode_path || !mode_path[0]) return 0;
    mode = fopen(mode_path, "r");
    if (!mode) return (errno == ENOENT) ? 0 : -1;
    if (!fgets(buf, sizeof buf, mode)) {
        fclose(mode);
        return 0;
    }
    fclose(mode);
    trim(buf);
    out->enforce = (strcmp(buf, "enforce") == 0) ? 1 : 0;
    return 0;
}

void madelf_es_policy_free(madelf_es_policy *policy) {
    if (!policy) return;
    free(policy->rules);
    policy->rules = NULL;
    policy->count = 0;
}

int madelf_es_policy_match(const madelf_es_policy *policy, const char *path,
                           const char *teamid, const char *signingid) {
    size_t i;
    if (!policy) return 0;
    for (i = 0; i < policy->count; i++) {
        const madelf_es_rule *rule = &policy->rules[i];
        if (rule->kind == MADELF_ES_PATH) {
            if (path && strcmp(path, rule->value) == 0) return 1;
        } else if (rule->kind == MADELF_ES_PREFIX) {
            size_t n = strlen(rule->value);
            if (path && n > 0 && strncmp(path, rule->value, n) == 0) return 1;
        } else if (rule->kind == MADELF_ES_TEAMID) {
            if (teamid && teamid[0] && strcmp(teamid, rule->value) == 0) return 1;
        } else if (rule->kind == MADELF_ES_SIGNINGID) {
            if (signingid && signingid[0] && strcmp(signingid, rule->value) == 0) return 1;
        }
    }
    return 0;
}
