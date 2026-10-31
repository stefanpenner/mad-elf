#include "logic.h"

static size_t mf_len(const char *s) {
    size_t n = 0;
    if (!s) return 0;
    while (s[n]) n++;
    return n;
}

static int mf_eq(const char *a, const char *b) {
    if (!a || !b) return 0;
    while (*a && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}

static int mf_startswith(const char *s, const char *pfx) {
    if (!s || !pfx) return 0;
    while (*pfx) {
        if (*s != *pfx) return 0;
        s++;
        pfx++;
    }
    return 1;
}

static void mf_copy(char *dst, size_t cap, const char *src) {
    size_t i = 0;
    if (cap == 0) return;
    if (!src) src = "";
    while (src[i] && i + 1 < cap) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = 0;
}

static void mf_err(char *err, size_t errlen, const char *msg) {
    if (err && errlen) mf_copy(err, errlen, msg);
}

static const char *skip_ws(const char *s) {
    while (*s == ' ' || *s == '\t') s++;
    return s;
}

static void rtrim(char *s) {
    size_t n = mf_len(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) {
        s[--n] = 0;
    }
}

void madelf_config_init(struct madelf_config *cfg) {
    size_t i;
    char *p = (char *)cfg;
    for (i = 0; i < sizeof(*cfg); i++) p[i] = 0;
}

static int add_env(struct madelf_config *cfg, int mode, const char *body,
                   char *err, size_t errlen) {
    const char *eq;
    size_t klen;
    struct madelf_env_op *op;
    if (cfg->nops >= MADELF_MAX_OPS) {
        mf_err(err, errlen, "too many env directives");
        return -1;
    }
    eq = body;
    while (*eq && *eq != '=') eq++;
    if (*eq != '=' || eq == body) {
        mf_err(err, errlen, "env directive needs KEY=VALUE");
        return -1;
    }
    klen = (size_t)(eq - body);
    if (klen >= MADELF_KEY_MAX) {
        mf_err(err, errlen, "env key too long");
        return -1;
    }
    if (mf_len(eq + 1) >= MADELF_VAL_MAX) {
        mf_err(err, errlen, "env value too long");
        return -1;
    }
    op = &cfg->ops[cfg->nops++];
    {
        size_t i;
        for (i = 0; i < klen; i++) op->key[i] = body[i];
        op->key[klen] = 0;
    }
    mf_copy(op->val, sizeof op->val, eq + 1);
    op->mode = mode;
    return 0;
}

int madelf_parse_config(const char *text, struct madelf_config *cfg,
                        char *err, size_t errlen) {
    const char *p;
    int loader_set = 0;
    if (!text || !cfg) {
        mf_err(err, errlen, "missing config");
        return -1;
    }
    madelf_config_init(cfg);
    p = text;
    while (*p) {
        const char *nl = p;
        char line[MADELF_VAL_MAX + MADELF_KEY_MAX];
        size_t n = 0;
        const char *s;
        while (*nl && *nl != '\n' && n + 1 < sizeof line) {
            line[n++] = *nl++;
        }
        line[n] = 0;
        if (*nl == '\n') nl++;
        else if (*nl) {
            mf_err(err, errlen, "config line too long");
            return -1;
        }
        p = nl;
        rtrim(line);
        s = skip_ws(line);
        if (*s == 0 || *s == '#') continue;
        if (mf_startswith(s, "loader=")) {
            if (!loader_set) {
                if (mf_len(s + 7) >= MADELF_PATH_MAX) {
                    mf_err(err, errlen, "loader path too long");
                    return -1;
                }
                mf_copy(cfg->loader, sizeof cfg->loader, s + 7);
                loader_set = 1;
            }
            continue;
        }
        if (mf_startswith(s, "markerfile=")) {
            if (mf_len(s + 11) >= MADELF_PATH_MAX) {
                mf_err(err, errlen, "markerfile path too long");
                return -1;
            }
            mf_copy(cfg->marker_file, sizeof cfg->marker_file, s + 11);
            continue;
        }
        if (mf_startswith(s, "setenv=")) {
            if (add_env(cfg, MADELF_ENV_SET_IF_ABSENT, s + 7, err, errlen)) return -1;
            continue;
        }
        if (mf_startswith(s, "forceenv=")) {
            if (add_env(cfg, MADELF_ENV_FORCE, s + 9, err, errlen)) return -1;
            continue;
        }
        if (mf_startswith(s, "mergeenv=")) {
            if (add_env(cfg, MADELF_ENV_MERGE, s + 9, err, errlen)) return -1;
            continue;
        }
        if (mf_startswith(s, "flag=")) {
            if (s[5] == 0) {
                mf_err(err, errlen, "empty flag");
                return -1;
            }
            if (cfg->nflags >= MADELF_MAX_FLAGS) {
                mf_err(err, errlen, "too many flags");
                return -1;
            }
            if (mf_len(s + 5) >= MADELF_VAL_MAX) {
                mf_err(err, errlen, "flag too long");
                return -1;
            }
            mf_copy(cfg->flags[cfg->nflags], MADELF_VAL_MAX, s + 5);
            cfg->nflags++;
            continue;
        }
        mf_err(err, errlen, "unknown config directive");
        return -1;
    }
    return 0;
}

int madelf_flag_present(int argc, char **argv, const char *flag) {
    int i;
    if (!flag) return 0;
    for (i = 1; i < argc; i++) {
        if (argv[i] && mf_eq(argv[i], flag)) return 1;
    }
    return 0;
}

int madelf_build_argv(int argc, char **argv, const char *loader, const char *exe,
                      const struct madelf_config *cfg,
                      char **out, int cap, char *err, size_t errlen) {
    int k = 0;
    int i;
    const char *argv0;
    if (!loader || !loader[0] || !exe || !exe[0] || !out || cap < 6) {
        mf_err(err, errlen, "argv build missing loader or exe");
        return -1;
    }
    argv0 = (argc > 0 && argv && argv[0] && argv[0][0]) ? argv[0] : exe;
    out[k++] = (char *)loader;
    out[k++] = (char *)"--argv0";
    out[k++] = (char *)argv0;
    out[k++] = (char *)exe;
    if (cfg) {
        for (i = 0; i < cfg->nflags; i++) {
            int j;
            int queued = 0;
            if (madelf_flag_present(argc, argv, cfg->flags[i])) continue;
            for (j = 0; j < k; j++) {
                if (out[j] && mf_eq(out[j], cfg->flags[i])) queued = 1;
            }
            if (queued) continue;
            if (k + 2 >= cap) {
                mf_err(err, errlen, "argv list full");
                return -1;
            }
            out[k++] = (char *)cfg->flags[i];
        }
    }
    for (i = 1; i < argc; i++) {
        if (k + 1 >= cap) {
            mf_err(err, errlen, "argv list full");
            return -1;
        }
        out[k++] = argv[i];
    }
    out[k] = 0;
    return k;
}

static int key_index(char **env, int n, const char *key) {
    size_t klen = mf_len(key);
    int i;
    for (i = 0; i < n; i++) {
        const char *e = env[i];
        size_t j;
        if (!e) continue;
        for (j = 0; j < klen; j++) {
            if (e[j] != key[j]) break;
        }
        if (j == klen && e[j] == '=') return i;
    }
    return -1;
}

static const char *env_value(const char *entry, const char *key) {
    return entry + mf_len(key) + 1;
}

static int token_present(const char *list, const char *token) {
    const char *p;
    size_t tlen;
    if (!list || !token || !token[0]) return 0;
    tlen = mf_len(token);
    p = list;
    while (*p) {
        const char *start;
        size_t n;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        start = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        n = (size_t)(p - start);
        if (n == tlen) {
            size_t i;
            for (i = 0; i < n; i++) if (start[i] != token[i]) break;
            if (i == n) return 1;
        }
    }
    return 0;
}

static int arena_put(char *arena, size_t cap, size_t *used, const char *s, char **out) {
    size_t n = mf_len(s);
    if (*used + n + 1 > cap) return -1;
    *out = arena + *used;
    {
        size_t i;
        for (i = 0; i < n; i++) (*out)[i] = s[i];
        (*out)[n] = 0;
    }
    *used += n + 1;
    return 0;
}

static int merge_value(char *arena, size_t cap, size_t *used,
                       const char *existing, const char *extra, char **out) {
    char buf[MADELF_VAL_MAX * 2];
    size_t len = 0;
    const char *p;
    if (existing) {
        size_t n = mf_len(existing);
        size_t i;
        if (n >= sizeof buf) return -1;
        for (i = 0; i < n; i++) buf[i] = existing[i];
        len = n;
    }
    p = extra ? extra : "";
    while (*p) {
        const char *start;
        size_t n;
        while (*p == ' ' || *p == '\t') p++;
        if (!*p) break;
        start = p;
        while (*p && *p != ' ' && *p != '\t') p++;
        n = (size_t)(p - start);
        {
            char tok[MADELF_VAL_MAX];
            size_t i;
            if (n >= sizeof tok) return -1;
            for (i = 0; i < n; i++) tok[i] = start[i];
            tok[n] = 0;
            if (token_present(buf, tok)) continue;
            if (len && len + 1 < sizeof buf) buf[len++] = ' ';
            if (len + n >= sizeof buf) return -1;
            for (i = 0; i < n; i++) buf[len++] = tok[i];
            buf[len] = 0;
        }
    }
    buf[len] = 0;
    return arena_put(arena, cap, used, buf, out);
}

static int append_kv(char **out_env, int *n, int cap,
                     char *arena, size_t arena_cap, size_t *used,
                     const char *key, const char *val,
                     char *err, size_t errlen) {
    char scratch[MADELF_KEY_MAX + MADELF_VAL_MAX + 2];
    size_t klen = mf_len(key);
    size_t vlen = mf_len(val);
    size_t i;
    char *stored;
    if (*n + 2 >= cap) {
        mf_err(err, errlen, "environment list full");
        return -1;
    }
    if (klen + 1 + vlen + 1 > sizeof scratch) {
        mf_err(err, errlen, "environment entry too long");
        return -1;
    }
    for (i = 0; i < klen; i++) scratch[i] = key[i];
    scratch[klen] = '=';
    for (i = 0; i < vlen; i++) scratch[klen + 1 + i] = val[i];
    scratch[klen + 1 + vlen] = 0;
    if (arena_put(arena, arena_cap, used, scratch, &stored)) {
        mf_err(err, errlen, "environment arena full");
        return -1;
    }
    out_env[(*n)++] = stored;
    return 0;
}

int madelf_build_env(char **envp, const struct madelf_config *cfg,
                     char **out_env, int cap,
                     char *arena, size_t arena_cap,
                     char *err, size_t errlen) {
    int n = 0;
    size_t used = 0;
    int i;
    if (!out_env || cap < 2 || !arena) {
        mf_err(err, errlen, "env build missing buffers");
        return -1;
    }
    if (envp) {
        for (i = 0; envp[i]; i++) {
            if (n + 2 >= cap) {
                mf_err(err, errlen, "environment list full");
                return -1;
            }
            out_env[n++] = envp[i];
        }
    }
    if (cfg) {
        for (i = 0; i < cfg->nops; i++) {
            const struct madelf_env_op *op = &cfg->ops[i];
            int idx = key_index(out_env, n, op->key);
            if (op->mode == MADELF_ENV_SET_IF_ABSENT) {
                if (idx >= 0) continue;
                if (append_kv(out_env, &n, cap, arena, arena_cap, &used,
                              op->key, op->val, err, errlen)) return -1;
            } else if (op->mode == MADELF_ENV_FORCE) {
                char *stored = 0;
                if (idx < 0) {
                    if (append_kv(out_env, &n, cap, arena, arena_cap, &used,
                                  op->key, op->val, err, errlen)) return -1;
                } else {
                    char scratch[MADELF_KEY_MAX + MADELF_VAL_MAX + 2];
                    size_t klen = mf_len(op->key);
                    size_t vlen = mf_len(op->val);
                    size_t j;
                    if (klen + vlen + 2 > sizeof scratch) {
                        mf_err(err, errlen, "environment entry too long");
                        return -1;
                    }
                    for (j = 0; j < klen; j++) scratch[j] = op->key[j];
                    scratch[klen] = '=';
                    for (j = 0; j < vlen; j++) scratch[klen + 1 + j] = op->val[j];
                    scratch[klen + 1 + vlen] = 0;
                    if (arena_put(arena, arena_cap, &used, scratch, &stored)) {
                        mf_err(err, errlen, "environment arena full");
                        return -1;
                    }
                    out_env[idx] = stored;
                }
            } else if (op->mode == MADELF_ENV_MERGE) {
                const char *existing = (idx >= 0) ? env_value(out_env[idx], op->key) : "";
                char *merged = 0;
                if (merge_value(arena, arena_cap, &used, existing, op->val, &merged)) {
                    mf_err(err, errlen, "environment merge failed");
                    return -1;
                }
                if (idx >= 0) {
                    char scratch[MADELF_KEY_MAX + MADELF_VAL_MAX + 2];
                    size_t klen = mf_len(op->key);
                    size_t vlen = mf_len(merged);
                    size_t j;
                    char *stored;
                    /* merged already lives in the arena; rebuild KEY=value after it */
                    if (klen + vlen + 2 > sizeof scratch) {
                        mf_err(err, errlen, "environment entry too long");
                        return -1;
                    }
                    for (j = 0; j < klen; j++) scratch[j] = op->key[j];
                    scratch[klen] = '=';
                    for (j = 0; j < vlen; j++) scratch[klen + 1 + j] = merged[j];
                    scratch[klen + 1 + vlen] = 0;
                    if (arena_put(arena, arena_cap, &used, scratch, &stored)) {
                        mf_err(err, errlen, "environment arena full");
                        return -1;
                    }
                    out_env[idx] = stored;
                } else {
                    if (append_kv(out_env, &n, cap, arena, arena_cap, &used,
                                  op->key, merged, err, errlen)) return -1;
                }
            }
        }
    }
    {
        int idx = key_index(out_env, n, MADELF_MARKER_KEY);
        char *stored = 0;
        char scratch[64];
        size_t j;
        const char *kv = MADELF_MARKER_KEY "=" MADELF_MARKER_VAL;
        for (j = 0; kv[j] && j + 1 < sizeof scratch; j++) scratch[j] = kv[j];
        scratch[j] = 0;
        if (arena_put(arena, arena_cap, &used, scratch, &stored)) {
            mf_err(err, errlen, "environment arena full");
            return -1;
        }
        if (idx >= 0) out_env[idx] = stored;
        else {
            if (n + 2 >= cap) {
                mf_err(err, errlen, "environment list full");
                return -1;
            }
            out_env[n++] = stored;
        }
    }
    out_env[n] = 0;
    return n;
}
