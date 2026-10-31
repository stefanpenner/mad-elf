#ifndef MADELF_LOGIC_H
#define MADELF_LOGIC_H

/* Pure config / argv / env transforms shared by the freestanding Linux shim,
 * the macOS constructor, and the hosted unit tests. No libc calls. */

#include <stddef.h>

#define MADELF_PATH_MAX 512
#define MADELF_VAL_MAX 1024
#define MADELF_KEY_MAX 256
#define MADELF_MAX_OPS 64
#define MADELF_MAX_FLAGS 64
#define MADELF_MARKER_KEY "MADELF_SHIM"
#define MADELF_MARKER_VAL "1"

enum madelf_env_mode {
    MADELF_ENV_SET_IF_ABSENT = 0,
    MADELF_ENV_FORCE = 1,
    MADELF_ENV_MERGE = 2
};

struct madelf_env_op {
    char key[MADELF_KEY_MAX];
    char val[MADELF_VAL_MAX];
    int mode;
};

struct madelf_config {
    char loader[MADELF_PATH_MAX];
    char marker_file[MADELF_PATH_MAX];
    struct madelf_env_op ops[MADELF_MAX_OPS];
    int nops;
    char flags[MADELF_MAX_FLAGS][MADELF_VAL_MAX];
    int nflags;
};

void madelf_config_init(struct madelf_config *cfg);

/* Parse the text config. loader: first line wins. markerfile: last wins.
 * Env ops and flags accumulate. Returns 0 or -1 (message in err). */
int madelf_parse_config(const char *text, struct madelf_config *cfg,
                        char *err, size_t errlen);

/* 1 if flag is an exact element of argv[1..argc). */
int madelf_flag_present(int argc, char **argv, const char *flag);

/* Build the ld.so argv:
 *   loader --argv0 <argv0> <exe> [missing flags...] argv[1...]
 * Writes pointers only (no string copies). Returns new argc or -1. */
int madelf_build_argv(int argc, char **argv, const char *loader, const char *exe,
                      const struct madelf_config *cfg,
                      char **out, int cap, char *err, size_t errlen);

/* Copy envp, apply ops, then force MADELF_SHIM=1.
 * New strings are written into arena. Returns env count or -1.
 * out_env is NULL-terminated. */
int madelf_build_env(char **envp, const struct madelf_config *cfg,
                     char **out_env, int cap,
                     char *arena, size_t arena_cap,
                     char *err, size_t errlen);

#endif
