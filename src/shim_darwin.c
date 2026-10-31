/* macOS launch shim, baked in with an absolute LC_LOAD_DYLIB path.
 *
 * dyld runs this constructor before main. The caller does not set any
 * environment variable. Config lives in <executable>.madelf (or an embedded
 * .madelf section). Environment edits are visible to main. Argv edits are
 * not: dyld already captured the kernel argument vector, so when configured
 * flags are missing this constructor execs the same binary once (same pid)
 * with those flags inserted after argv[0]. The second start sees the flags
 * and does not exec again.
 */
#include "logic.h"

#include <crt_externs.h>
#include <errno.h>
#include <fcntl.h>
#include <mach-o/dyld.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

extern char **environ;

static int append_file(const char *path, const char *text) {
    int fd = open(path, O_CREAT | O_WRONLY | O_APPEND, 0644);
    size_t n;
    ssize_t w;
    if (fd < 0) return -1;
    n = strlen(text);
    w = write(fd, text, n);
    close(fd);
    return (w == (ssize_t)n) ? 0 : -1;
}

static char *read_file(const char *path, size_t *out_len) {
    FILE *f = fopen(path, "rb");
    char *buf;
    long sz;
    if (!f) return NULL;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return NULL; }
    sz = ftell(f);
    if (sz < 0 || sz > 1024 * 1024) { fclose(f); return NULL; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return NULL; }
    buf = malloc((size_t)sz + 1);
    if (!buf) { fclose(f); return NULL; }
    if (fread(buf, 1, (size_t)sz, f) != (size_t)sz) {
        free(buf);
        fclose(f);
        return NULL;
    }
    fclose(f);
    buf[sz] = 0;
    if (out_len) *out_len = (size_t)sz;
    return buf;
}

/* Minimal ELF-less Mach-O section reader is intentionally not duplicated here.
 * The install tool writes a sibling <exe>.madelf file, which is the supported
 * config on macOS. An embedded section is a Linux convenience. */
static int load_config(const char *exe, struct madelf_config *cfg, int *have) {
    char path[4096];
    char err[256];
    char *text;
    int n;
    *have = 0;
    madelf_config_init(cfg);
    n = snprintf(path, sizeof path, "%s.madelf", exe);
    if (n < 0 || (size_t)n >= sizeof path) return -1;
    text = read_file(path, NULL);
    if (!text) return 0;
    *have = 1;
    if (madelf_parse_config(text, cfg, err, sizeof err) != 0) {
        fprintf(stderr, "mad-elf: bad config %s: %s\n", path, err);
        free(text);
        return -1;
    }
    free(text);
    return 0;
}

static void apply_live_env(const struct madelf_config *cfg) {
    char arena[262144];
    char *built[4096];
    char err[256];
    int i;
    err[0] = 0;
    if (madelf_build_env(environ, cfg, built, 4096, arena, sizeof arena, err, sizeof err) < 0) {
        fprintf(stderr, "mad-elf: %s\n", err[0] ? err : "environment build failed");
        _exit(127);
    }
    for (i = 0; built[i]; i++) {
        char *eq = strchr(built[i], '=');
        if (!eq) continue;
        *eq = 0;
        setenv(built[i], eq + 1, 1);
        *eq = '=';
    }
}

__attribute__((constructor))
static void madelf_init(void) {
    char exe[4096];
    uint32_t sz = (uint32_t)sizeof exe;
    struct madelf_config cfg;
    int have = 0;
    int argc;
    char **argv;
    const char *missing[MADELF_MAX_FLAGS];
    int nmiss = 0;
    int i;

    if (_NSGetExecutablePath(exe, &sz) != 0) {
        fprintf(stderr, "mad-elf: executable path is too long\n");
        _exit(127);
    }
    if (load_config(exe, &cfg, &have) != 0) _exit(127);

    argc = *_NSGetArgc();
    argv = *_NSGetArgv();
    apply_live_env(have ? &cfg : NULL);
    if (have && cfg.marker_file[0]) setenv("MADELF_MARKER_FILE", cfg.marker_file, 1);

    if (have) {
        for (i = 0; i < cfg.nflags; i++) {
            if (!madelf_flag_present(argc, argv, cfg.flags[i])) {
                missing[nmiss++] = cfg.flags[i];
            }
        }
    }
    if (nmiss > 0) {
        char *newargv[1024];
        int k = 0;
        if (argc + nmiss + 2 > (int)(sizeof newargv / sizeof newargv[0])) {
            fprintf(stderr, "mad-elf: argument list too long to insert flags\n");
            _exit(127);
        }
        newargv[k++] = (argc > 0 && argv && argv[0]) ? argv[0] : exe;
        for (i = 0; i < nmiss; i++) newargv[k++] = (char *)missing[i];
        for (i = 1; i < argc; i++) newargv[k++] = argv[i];
        newargv[k] = NULL;
        execve(exe, newargv, environ);
        fprintf(stderr, "mad-elf: re-exec of %s failed: %s\n", exe, strerror(errno));
        _exit(127);
    }
    if (have && cfg.marker_file[0]) append_file(cfg.marker_file, "ctor\n");
}
