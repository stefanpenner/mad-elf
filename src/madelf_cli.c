#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "madelf_elf.h"
#include "madelf_macho.h"

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#ifdef __APPLE__
#include <libproc.h>
#endif

#define ERR_MAX 8192
#define MAX_DIRECTIVES 256

static int is_reg(const char *path) {
    struct stat st;
    if (stat(path, &st) != 0) return 0;
    return S_ISREG(st.st_mode);
}

static int same_file(const char *a, const char *b) {
    struct stat sa, sb;
    if (stat(a, &sa) != 0 || stat(b, &sb) != 0) return 0;
    return sa.st_dev == sb.st_dev && sa.st_ino == sb.st_ino;
}

/* Absolute path with . and .. removed. Symlinks are kept, matching Python abspath. */
static int abs_norm(const char *in, char *out, size_t outlen) {
    char storage[8192];
    char *stack[256];
    int nstack = 0;
    char *p;
    size_t pos;
    int i;
    int n;

    if (!in || !in[0]) return -1;
    if (in[0] == '/') n = snprintf(storage, sizeof storage, "%s", in);
    else {
        char cwd[4096];
        if (!getcwd(cwd, sizeof cwd)) return -1;
        n = snprintf(storage, sizeof storage, "%s/%s", cwd, in);
    }
    if (n < 0 || (size_t)n >= sizeof storage) return -1;
    p = storage;
    while (*p) {
        char *start;
        while (*p == '/') p++;
        if (!*p) break;
        start = p;
        while (*p && *p != '/') p++;
        if (*p) *p++ = 0;
        if (strcmp(start, ".") == 0) continue;
        if (strcmp(start, "..") == 0) {
            if (nstack > 0) nstack--;
            continue;
        }
        if (nstack >= (int)(sizeof stack / sizeof stack[0])) return -1;
        stack[nstack++] = start;
    }
    if (nstack == 0) {
        if (outlen < 2) return -1;
        out[0] = '/';
        out[1] = 0;
        return 0;
    }
    pos = 0;
    for (i = 0; i < nstack; i++) {
        size_t ln = strlen(stack[i]);
        if (pos + 1 + ln + 1 > outlen) return -1;
        out[pos++] = '/';
        memcpy(out + pos, stack[i], ln);
        pos += ln;
    }
    out[pos] = 0;
    return 0;
}

static int mkdir_p(const char *path) {
    char tmp[4096];
    size_t len, i;
    if (!path || !path[0]) return -1;
    len = strlen(path);
    if (len >= sizeof tmp) return -1;
    memcpy(tmp, path, len + 1);
    for (i = 1; i < len; i++) {
        if (tmp[i] != '/') continue;
        tmp[i] = 0;
        if (mkdir(tmp, 0777) != 0 && errno != EEXIST) return -1;
        tmp[i] = '/';
    }
    if (mkdir(tmp, 0777) != 0 && errno != EEXIST) return -1;
    return 0;
}

static int copy_file(const char *src, const char *dst, char *err, size_t errlen) {
    int in, out;
    char buf[65536];
    struct stat st;
    if (stat(src, &st) != 0) {
        snprintf(err, errlen, "%s", strerror(errno));
        return -1;
    }
    in = open(src, O_RDONLY);
    if (in < 0) {
        snprintf(err, errlen, "%s", strerror(errno));
        return -1;
    }
    out = open(dst, O_WRONLY | O_CREAT | O_TRUNC, st.st_mode & 0777);
    if (out < 0) {
        snprintf(err, errlen, "%s", strerror(errno));
        close(in);
        return -1;
    }
    for (;;) {
        ssize_t n = read(in, buf, sizeof buf);
        if (n < 0) {
            if (errno == EINTR) continue;
            snprintf(err, errlen, "%s", strerror(errno));
            close(in);
            close(out);
            return -1;
        }
        if (n == 0) break;
        {
            ssize_t off = 0;
            while (off < n) {
                ssize_t w = write(out, buf + off, (size_t)(n - off));
                if (w < 0) {
                    if (errno == EINTR) continue;
                    snprintf(err, errlen, "%s", strerror(errno));
                    close(in);
                    close(out);
                    return -1;
                }
                off += w;
            }
        }
    }
    if (close(in) != 0 || close(out) != 0) {
        snprintf(err, errlen, "%s", strerror(errno));
        return -1;
    }
    if (chmod(dst, (st.st_mode & 07777) | 0111) != 0) {
        snprintf(err, errlen, "%s", strerror(errno));
        return -1;
    }
    return 0;
}

static const char *file_kind(const char *path) {
    int fd;
    unsigned char magic[4];
    ssize_t n;
    fd = open(path, O_RDONLY);
    if (fd < 0) return NULL;
    n = read(fd, magic, 4);
    close(fd);
    if (n < 4) return "other";
    if (magic[0] == 0x7f && magic[1] == 'E' && magic[2] == 'L' && magic[3] == 'F') return "elf";
    if (magic[0] == 0xcf && magic[1] == 0xfa && magic[2] == 0xed && magic[3] == 0xfe) return "macho";
    if (magic[0] == 0xca && magic[1] == 0xfe && magic[2] == 0xba && magic[3] == 0xbe) return "macho";
    return "other";
}

static char *render_config(const char *loader, char **directives, int nd, char *err, size_t errlen) {
    size_t cap = 64, len = 0;
    char *buf;
    int i, lines = 0;
    buf = malloc(cap);
    if (!buf) {
        snprintf(err, errlen, "out of memory");
        return NULL;
    }
    buf[0] = 0;
    if (loader && loader[0]) {
        size_t need = strlen(loader) + 8;
        if (len + need + 2 > cap) {
            while (len + need + 2 > cap) cap *= 2;
            buf = realloc(buf, cap);
            if (!buf) {
                snprintf(err, errlen, "out of memory");
                return NULL;
            }
        }
        len += (size_t)sprintf(buf + len, "loader=%s\n", loader);
        lines++;
    }
    for (i = 0; i < nd; i++) {
        size_t need = strlen(directives[i]) + 2;
        char *grown;
        if (len + need + 1 > cap) {
            while (len + need + 1 > cap) cap *= 2;
            grown = realloc(buf, cap);
            if (!grown) {
                free(buf);
                snprintf(err, errlen, "out of memory");
                return NULL;
            }
            buf = grown;
        }
        len += (size_t)sprintf(buf + len, "%s\n", directives[i]);
        lines++;
    }
    if (lines == 0) buf[0] = 0;
    return buf;
}

static int default_shim(const char *argv0, char *out, size_t outlen, char *err, size_t errlen) {
    const char *env = getenv("MADELF_SHIM");
    char joined[4096];
    if (env && env[0]) {
        if (abs_norm(env, out, outlen) != 0) {
            snprintf(err, errlen, "shim path is too long");
            return -1;
        }
        return 0;
    }
    if (argv0 && strchr(argv0, '/')) {
        char dir[4096];
        const char *slash = strrchr(argv0, '/');
        size_t dlen = (size_t)(slash - argv0);
        if (dlen >= sizeof dir) {
            snprintf(err, errlen, "shim path is too long");
            return -1;
        }
        memcpy(dir, argv0, dlen);
        dir[dlen] = 0;
        if (dlen == 0) snprintf(dir, sizeof dir, "/");
        if (snprintf(joined, sizeof joined, "%s/mad-elf-shim", dir) >= (int)sizeof joined) {
            snprintf(err, errlen, "shim path is too long");
            return -1;
        }
    } else if (snprintf(joined, sizeof joined, "build/mad-elf-shim") >= (int)sizeof joined) {
        snprintf(err, errlen, "shim path is too long");
        return -1;
    }
    if (abs_norm(joined, out, outlen) != 0) {
        snprintf(err, errlen, "shim path is too long");
        return -1;
    }
    return 0;
}

static void py_repr(const char *s, char *out, size_t outlen) {
    size_t i = 0, j = 0;
    if (j + 1 < outlen) out[j++] = '\'';
    for (; s[i] && j + 4 < outlen; i++) {
        unsigned char c = (unsigned char)s[i];
        if (c == '\\' || c == '\'') {
            out[j++] = '\\';
            out[j++] = (char)c;
        } else if (c < 32 || c > 126) {
            int n = snprintf(out + j, outlen - j, "\\x%02x", c);
            if (n < 0) break;
            j += (size_t)n;
        } else {
            out[j++] = (char)c;
        }
    }
    if (j + 1 < outlen) out[j++] = '\'';
    out[j < outlen ? j : outlen - 1] = 0;
}

static int add_directive(char **directives, int *nd, const char *line) {
    if (*nd >= MAX_DIRECTIVES) return -1;
    directives[*nd] = strdup(line);
    if (!directives[*nd]) return -1;
    (*nd)++;
    return 0;
}

static int read_config_directives(const char *path, char **directives, int *nd,
                                  char *err, size_t errlen) {
    FILE *f = fopen(path, "rb");
    char *data;
    long sz;
    size_t i = 0;
    if (!f) {
        snprintf(err, errlen, "cannot read config %s: %s", path, strerror(errno));
        return -1;
    }
    if (fseek(f, 0, SEEK_END) != 0) {
        snprintf(err, errlen, "cannot read config %s: %s", path, strerror(errno));
        fclose(f);
        return -1;
    }
    sz = ftell(f);
    if (sz < 0 || sz > 1024 * 1024) {
        snprintf(err, errlen, "cannot read config %s", path);
        fclose(f);
        return -1;
    }
    if (fseek(f, 0, SEEK_SET) != 0) {
        fclose(f);
        return -1;
    }
    data = malloc((size_t)sz + 1);
    if (!data) {
        fclose(f);
        snprintf(err, errlen, "out of memory");
        return -1;
    }
    if (sz && fread(data, 1, (size_t)sz, f) != (size_t)sz) {
        free(data);
        fclose(f);
        snprintf(err, errlen, "cannot read config %s", path);
        return -1;
    }
    fclose(f);
    data[sz] = 0;
    while (i < (size_t)sz) {
        size_t start = i;
        char *line;
        char *s;
        size_t n, a, b;
        while (i < (size_t)sz && data[i] != '\n') i++;
        n = i - start;
        if (i < (size_t)sz && data[i] == '\n') i++;
        line = malloc(n + 1);
        if (!line) {
            free(data);
            snprintf(err, errlen, "out of memory");
            return -1;
        }
        memcpy(line, data + start, n);
        line[n] = 0;
        a = 0;
        while (line[a] == ' ' || line[a] == '\t' || line[a] == '\r') a++;
        b = strlen(line);
        while (b > a && (line[b - 1] == ' ' || line[b - 1] == '\t' || line[b - 1] == '\r')) {
            line[--b] = 0;
        }
        s = line + a;
        if (s[0] == 0 || s[0] == '#') {
            free(line);
            continue;
        }
        if (strncmp(s, "loader=", 7) == 0) {
            free(line);
            continue;
        }
        if (add_directive(directives, nd, s) != 0) {
            free(line);
            free(data);
            snprintf(err, errlen, "too many directives");
            return -1;
        }
        free(line);
    }
    free(data);
    return 0;
}

static void free_directives(char **directives, int nd) {
    int i;
    for (i = 0; i < nd; i++) free(directives[i]);
}

#ifdef __APPLE__
static int command_exists(const char *name) {
    const char *path = getenv("PATH");
    char buf[4096];
    const char *p;
    if (!path) return 0;
    p = path;
    while (*p) {
        const char *colon = strchr(p, ':');
        size_t dlen = colon ? (size_t)(colon - p) : strlen(p);
        int nn;
        if (dlen == 0) nn = snprintf(buf, sizeof buf, "%s", name);
        else nn = snprintf(buf, sizeof buf, "%.*s/%s", (int)dlen, p, name);
        if (nn > 0 && (size_t)nn < sizeof buf && access(buf, X_OK) == 0) return 1;
        if (!colon) break;
        p = colon + 1;
    }
    return 0;
}

static int run_quiet(char *const argv[]) {
    pid_t pid;
    int status;
    pid = fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        int dn = open("/dev/null", O_RDWR);
        if (dn >= 0) {
            dup2(dn, STDIN_FILENO);
            dup2(dn, STDOUT_FILENO);
            dup2(dn, STDERR_FILENO);
            if (dn > 2) close(dn);
        }
        execvp(argv[0], argv);
        _exit(127);
    }
    for (;;) {
        if (waitpid(pid, &status, 0) < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        break;
    }
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
}
#endif

static int codesign_adhoc(const char *path, char *err, size_t errlen) {
#ifdef __APPLE__
    char *rm[4];
    char *ad[6];
    if (!command_exists("codesign")) return 0;
    rm[0] = "codesign";
    rm[1] = "--remove-signature";
    rm[2] = (char *)path;
    rm[3] = NULL;
    (void)run_quiet(rm);
    ad[0] = "codesign";
    ad[1] = "-f";
    ad[2] = "-s";
    ad[3] = "-";
    ad[4] = (char *)path;
    ad[5] = NULL;
    if (run_quiet(ad) != 0) {
        snprintf(err, errlen, "codesign failed for %s", path);
        return -1;
    }
#else
    (void)path;
    (void)err;
    (void)errlen;
#endif
    return 0;
}

static int install_elf(const char *src, const char *dst, const char *shim, char **directives, int nd,
                       int embed, int embed_only, char *err, size_t errlen) {
    char interp[4096];
    char shim_abs[4096];
    char *text = NULL;
    char *dir;
    char parent[4096];
    int rc;
    const char *slash;

    rc = madelf_read_interpreter(src, interp, sizeof interp, err, errlen);
    if (rc < 0) return -1;
    if (rc == 1) {
        snprintf(err, errlen,
                 "%s has no PT_INTERP. Static binaries do not use an interpreter, "
                 "so mad-elf cannot run ahead of them.",
                 src);
        return -1;
    }
    if (abs_norm(shim, shim_abs, sizeof shim_abs) != 0) {
        snprintf(err, errlen, "shim path is too long");
        return -1;
    }
    if (!is_reg(shim_abs)) {
        snprintf(err, errlen, "shim not found: %s", shim_abs);
        return -1;
    }
    if (is_reg(dst) && same_file(src, dst)) {
        snprintf(err, errlen, "refusing to patch a binary in place; install onto a copy");
        return -1;
    }
    slash = strrchr(dst, '/');
    if (!slash || slash == dst) snprintf(parent, sizeof parent, "/");
    else {
        size_t n = (size_t)(slash - dst);
        if (n >= sizeof parent) {
            snprintf(err, errlen, "path is too long");
            return -1;
        }
        memcpy(parent, dst, n);
        parent[n] = 0;
    }
    if (mkdir_p(parent) != 0) {
        snprintf(err, errlen, "cannot create directory %s: %s", parent, strerror(errno));
        return -1;
    }
    if (copy_file(src, dst, err, errlen) != 0) return -1;
    text = render_config(interp, directives, nd, err, errlen);
    if (!text) return -1;
    if (embed || embed_only) {
        if (madelf_embed_config_section(dst, text, err, errlen) != 0) {
            free(text);
            return -1;
        }
    }
    {
        char sidecar[4200];
        if (snprintf(sidecar, sizeof sidecar, "%s.madelf", dst) >= (int)sizeof sidecar) {
            free(text);
            snprintf(err, errlen, "path is too long");
            return -1;
        }
        if (embed_only) {
            if (unlink(sidecar) != 0 && errno != ENOENT) {
                snprintf(err, errlen, "cannot remove %s: %s", sidecar, strerror(errno));
                free(text);
                return -1;
            }
        } else {
            FILE *f = fopen(sidecar, "wb");
            size_t n;
            if (!f) {
                snprintf(err, errlen, "cannot write %s: %s", sidecar, strerror(errno));
                free(text);
                return -1;
            }
            n = strlen(text);
            if (n && fwrite(text, 1, n, f) != n) {
                fclose(f);
                free(text);
                snprintf(err, errlen, "cannot write %s", sidecar);
                return -1;
            }
            if (fclose(f) != 0) {
                free(text);
                snprintf(err, errlen, "cannot write %s", sidecar);
                return -1;
            }
        }
    }
    free(text);
    if (madelf_set_interpreter(dst, shim_abs, err, errlen) != 0) return -1;
    dir = shim_abs;
    printf("installed %s\n", dst);
    printf("interpreter -> %s\n", dir);
    if (!embed_only) printf("config %s.madelf\n", dst);
    return 0;
}

static int install_macho(const char *src, const char *dst, const char *dylib, char **directives,
                         int nd, char *err, size_t errlen) {
    char dylib_abs[4096];
    char parent[4096];
    char *text;
    const char *slash;

    if (abs_norm(dylib, dylib_abs, sizeof dylib_abs) != 0) {
        snprintf(err, errlen, "dylib path is too long");
        return -1;
    }
    if (is_reg(dst) && same_file(src, dst)) {
        snprintf(err, errlen, "refusing to patch a binary in place; install onto a copy");
        return -1;
    }
    slash = strrchr(dst, '/');
    if (!slash || slash == dst) snprintf(parent, sizeof parent, "/");
    else {
        size_t n = (size_t)(slash - dst);
        if (n >= sizeof parent) {
            snprintf(err, errlen, "path is too long");
            return -1;
        }
        memcpy(parent, dst, n);
        parent[n] = 0;
    }
    if (mkdir_p(parent) != 0) {
        snprintf(err, errlen, "cannot create directory %s: %s", parent, strerror(errno));
        return -1;
    }
    if (copy_file(src, dst, err, errlen) != 0) return -1;
    if (madelf_inject_load_dylib(dst, dylib_abs, err, errlen) != 0) return -1;
    text = render_config(NULL, directives, nd, err, errlen);
    if (!text) return -1;
    {
        char sidecar[4200];
        FILE *f;
        size_t n;
        if (snprintf(sidecar, sizeof sidecar, "%s.madelf", dst) >= (int)sizeof sidecar) {
            free(text);
            snprintf(err, errlen, "path is too long");
            return -1;
        }
        f = fopen(sidecar, "wb");
        if (!f) {
            snprintf(err, errlen, "cannot write %s: %s", sidecar, strerror(errno));
            free(text);
            return -1;
        }
        n = strlen(text);
        if (n && fwrite(text, 1, n, f) != n) {
            fclose(f);
            free(text);
            snprintf(err, errlen, "cannot write %s", sidecar);
            return -1;
        }
        if (fclose(f) != 0) {
            free(text);
            snprintf(err, errlen, "cannot write %s", sidecar);
            return -1;
        }
    }
    free(text);
    if (is_reg(dylib_abs)) {
        if (codesign_adhoc(dylib_abs, err, errlen) != 0) return -1;
    }
    if (codesign_adhoc(dst, err, errlen) != 0) return -1;
    printf("installed %s\n", dst);
    printf("LC_LOAD_DYLIB -> %s\n", dylib_abs);
    printf("config %s.madelf\n", dst);
    return 0;
}

static int marker_in_environ(int pid) {
#ifdef __linux__
    char path[64];
    unsigned char *data = NULL;
    size_t cap = 4096, len = 0;
    int fd;
    snprintf(path, sizeof path, "/proc/%d/environ", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    data = malloc(cap);
    if (!data) {
        close(fd);
        return 0;
    }
    for (;;) {
        ssize_t n;
        if (len == cap) {
            size_t ncap = cap * 2;
            unsigned char *grown;
            if (ncap > 4u * 1024u * 1024u) break;
            grown = realloc(data, ncap);
            if (!grown) break;
            data = grown;
            cap = ncap;
        }
        n = read(fd, data + len, cap - len);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        len += (size_t)n;
    }
    close(fd);
    {
        size_t i = 0;
        const char *needle = "MADELF_SHIM=1";
        size_t nlen = strlen(needle);
        int yes = 0;
        while (i < len) {
            size_t start = i;
            while (i < len && data[i] != 0) i++;
            if (i - start == nlen && memcmp(data + start, needle, nlen) == 0) {
                yes = 1;
                break;
            }
            if (i < len && data[i] == 0) i++;
        }
        free(data);
        return yes;
    }
#elif defined(__APPLE__)
    int pipefd[2];
    pid_t child;
    char pidbuf[32];
    char *buf;
    size_t cap = 65536, len = 0;
    int yes = 0;
    snprintf(pidbuf, sizeof pidbuf, "%d", pid);
    if (pipe(pipefd) != 0) return 0;
    child = fork();
    if (child < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return 0;
    }
    if (child == 0) {
        int dn = open("/dev/null", O_RDWR);
        dup2(pipefd[1], STDOUT_FILENO);
        if (dn >= 0) dup2(dn, STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execlp("ps", "ps", "eww", "-p", pidbuf, "-o", "command=", (char *)NULL);
        _exit(127);
    }
    close(pipefd[1]);
    buf = malloc(cap);
    if (!buf) {
        close(pipefd[0]);
        waitpid(child, NULL, 0);
        return 0;
    }
    for (;;) {
        ssize_t n = read(pipefd[0], buf + len, cap - 1 - len);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        len += (size_t)n;
        if (len + 1 >= cap) break;
    }
    buf[len] = 0;
    close(pipefd[0]);
    waitpid(child, NULL, 0);
    yes = strstr(buf, "MADELF_SHIM=1") != NULL;
    free(buf);
    return yes;
#else
    (void)pid;
    return 0;
#endif
}

static int executable_for_pid(int pid, char *out, size_t outlen, char *err, size_t errlen) {
#ifdef __linux__
    char path[64];
    char *rp;
    snprintf(path, sizeof path, "/proc/%d/exe", pid);
    rp = realpath(path, NULL);
    if (!rp) {
        snprintf(err, errlen, "[Errno %d] %s: '%s'", errno, strerror(errno), path);
        return -1;
    }
    if (strlen(rp) + 1 > outlen) {
        free(rp);
        snprintf(err, errlen, "path is too long");
        return -1;
    }
    memcpy(out, rp, strlen(rp) + 1);
    free(rp);
    return 0;
#elif defined(__APPLE__)
    char buf[4096];
    int n = proc_pidpath(pid, buf, sizeof buf);
    if (n <= 0) {
        snprintf(err, errlen, "proc_pidpath failed for %d", pid);
        return -1;
    }
    if (strlen(buf) + 1 > outlen) {
        snprintf(err, errlen, "path is too long");
        return -1;
    }
    memcpy(out, buf, strlen(buf) + 1);
    return 0;
#else
    (void)pid;
    (void)out;
    (void)outlen;
    snprintf(err, errlen, "detect is not implemented on this platform");
    return -1;
#endif
}

static int linux_handoff_target(int pid, char *out, size_t outlen) {
#ifdef __linux__
    char path[64];
    unsigned char *data;
    size_t cap = 8192, len = 0;
    int fd;
    const char *args[8];
    int nargs = 0;
    size_t i;
    snprintf(path, sizeof path, "/proc/%d/cmdline", pid);
    fd = open(path, O_RDONLY);
    if (fd < 0) return 0;
    data = malloc(cap);
    if (!data) {
        close(fd);
        return 0;
    }
    for (;;) {
        ssize_t n;
        if (len + 1 >= cap) break;
        n = read(fd, data + len, cap - len);
        if (n < 0) {
            if (errno == EINTR) continue;
            break;
        }
        if (n == 0) break;
        len += (size_t)n;
    }
    close(fd);
    i = 0;
    while (i < len && nargs < 4) {
        size_t start = i;
        while (i < len && data[i] != 0) i++;
        if (i > start) {
            data[i < len ? i : len] = 0;
            args[nargs++] = (char *)(data + start);
        }
        if (i < len && data[i] == 0) i++;
    }
    if (nargs >= 4 && strcmp(args[1], "--argv0") == 0 && args[3][0] == '/' && is_reg(args[3]) &&
        madelf_is_madelf_elf(args[3])) {
        if (strlen(args[3]) + 1 <= outlen) {
            memcpy(out, args[3], strlen(args[3]) + 1);
            free(data);
            return 1;
        }
    }
    free(data);
    return 0;
#else
    (void)pid;
    (void)out;
    (void)outlen;
    return 0;
#endif
}

static int cmd_detect(int pid) {
    char exe[4096];
    char err[ERR_MAX];
    char handoff[4096];
    const char *kind;
    const char *patched = NULL;
    int marker;

    if (executable_for_pid(pid, exe, sizeof exe, err, sizeof err) != 0) {
        fprintf(stderr, "mad-elf: cannot inspect pid %d: %s\n", pid, err);
        return 2;
    }
    kind = "other";
    if (is_reg(exe)) {
        const char *k = file_kind(exe);
        if (k) kind = k;
    }
    if (strcmp(kind, "elf") == 0 && madelf_is_madelf_elf(exe)) patched = exe;
    else if (strcmp(kind, "macho") == 0 && madelf_is_madelf_macho(exe)) patched = exe;
    else if (linux_handoff_target(pid, handoff, sizeof handoff)) patched = handoff;
    marker = marker_in_environ(pid);
    if (patched && marker) {
        printf("mad-elf: yes  pid %d is running patched binary %s\n", pid, patched);
        printf("mad-elf: MADELF_SHIM=1 is set in the process environment\n");
        return 0;
    }
    if (patched) {
        printf("mad-elf: yes  pid %d executable %s is a mad-elf binary; "
               "MADELF_SHIM is not currently in its environment\n",
               pid, patched);
        return 0;
    }
    if (marker) {
        fprintf(stderr,
                "mad-elf: no   pid %d has MADELF_SHIM set, but %s is not a mad-elf binary "
                "(the variable was inherited)\n",
                pid, exe);
        return 1;
    }
    fprintf(stderr, "mad-elf: no   pid %d (%s) was not launched through mad-elf\n", pid, exe);
    return 1;
}

static void print_config_block(const char *text) {
    if (!text || !text[0]) return;
    printf("--- config ---\n");
    if (text[strlen(text) - 1] == '\n') fputs(text, stdout);
    else printf("%s\n", text);
}

static int cmd_inspect(const char *path) {
    const char *kind = file_kind(path);
    char err[ERR_MAX];
    if (!kind) {
        fprintf(stderr, "mad-elf: cannot read %s: %s\n", path, strerror(errno));
        return 1;
    }
    printf("file: %s\n", path);
    printf("kind: %s\n", kind);
    if (strcmp(kind, "elf") == 0) {
        char interp[4096];
        char *text = NULL;
        int rc = madelf_read_interpreter(path, interp, sizeof interp, err, sizeof err);
        char sidecar[4200];
        if (rc < 0) {
            printf("elf: %s\n", err);
            return 1;
        }
        if (rc == 1 || interp[0] == 0) printf("interpreter: (none — static)\n");
        else printf("interpreter: %s\n", interp);
        snprintf(sidecar, sizeof sidecar, "%s.madelf", path);
        if (is_reg(sidecar)) printf("config: %s\n", sidecar);
        else printf("config: (no sidecar)\n");
        rc = madelf_read_config_text(path, &text, err, sizeof err);
        if (rc < 0) {
            printf("elf: %s\n", err);
            return 1;
        }
        if (rc == 0 && text && text[0]) {
            char loader[4096];
            if (madelf_first_loader(text, loader, sizeof loader) == 0 && loader[0])
                printf("recorded-loader: %s\n", loader);
            else printf("recorded-loader: (none)\n");
            print_config_block(text);
        }
        free(text);
        printf("mad-elf: %s\n", madelf_is_madelf_elf(path) ? "yes" : "no");
        return 0;
    }
    if (strcmp(kind, "macho") == 0) {
        char **libs = NULL;
        int n = 0, i;
        char sidecar[4200];
        if (madelf_load_dylibs(path, &libs, &n, err, sizeof err) != 0) {
            printf("macho: %s\n", err);
            return 1;
        }
        printf("load-dylibs:\n");
        for (i = 0; i < n; i++) {
            size_t ln = strlen(libs[i]);
            int mark = libs[i][0] == '/' && ln >= strlen("/libmadelf.dylib") &&
                       strcmp(libs[i] + ln - strlen("/libmadelf.dylib"), "/libmadelf.dylib") == 0;
            printf("  %s%s\n", libs[i], mark ? "  [mad-elf]" : "");
        }
        madelf_free_dylibs(libs, n);
        snprintf(sidecar, sizeof sidecar, "%s.madelf", path);
        if (is_reg(sidecar)) {
            char *text = NULL;
            if (madelf_read_config_text(path, &text, err, sizeof err) == 0 && text && text[0])
                print_config_block(text);
            free(text);
        }
        printf("mad-elf: %s\n", madelf_is_madelf_macho(path) ? "yes" : "no");
        return 0;
    }
    printf("not an ELF or Mach-O file\n");
    return 1;
}

static void usage_all(FILE *fp) {
    fprintf(fp,
            "usage: mad-elf <install|detect|inspect> ...\n"
            "Launch a binary with enforced flags and environment.\n"
            "\n"
            "  install src dst    copy a binary and attach the shim\n"
            "  detect <pid>       report whether a pid is running a mad-elf binary\n"
            "  inspect <file>     show interpreter / load commands / config\n");
}

static void usage_install(FILE *fp) {
    fprintf(fp,
            "usage: mad-elf install [options] src dst\n"
            "\n"
            "  --shim PATH         absolute path to the Linux mad-elf-shim\n"
            "                      (default: mad-elf-shim next to this program)\n"
            "  --dylib PATH        absolute path ending in /libmadelf.dylib (macOS)\n"
            "  --flag VALUE        argv flag to insert if missing (repeatable)\n"
            "  --setenv KEY=VALUE  set if the variable is absent\n"
            "  --forceenv KEY=VALUE  set even if the variable is present\n"
            "  --mergeenv KEY=VALUE  append missing whitespace-separated tokens\n"
            "  --marker-file PATH  constructor/shim proof file (macOS ctor writes ctor\\n)\n"
            "  --config PATH       extra config lines (loader= is ignored)\n"
            "  --embed             also embed the config in a .madelf ELF section\n"
            "  --embed-only        embed the config and do not write a sidecar file\n");
}

struct install_opts {
    const char *shim;
    const char *dylib;
    const char *marker_file;
    const char *config;
    int embed;
    int embed_only;
    const char *flags[MAX_DIRECTIVES];
    int nflags;
    const char *setenv[MAX_DIRECTIVES];
    int nset;
    const char *forceenv[MAX_DIRECTIVES];
    int nforce;
    const char *mergeenv[MAX_DIRECTIVES];
    int nmerge;
    const char *src;
    const char *dst;
};

static int push_opt(const char **slot, int *n, const char *val) {
    if (*n >= MAX_DIRECTIVES) return -1;
    slot[(*n)++] = val;
    return 0;
}

/* Same order as the historical CLI: flags, setenv, forceenv, mergeenv, marker, then config file. */
static int build_directives(struct install_opts *opt, char **directives, int *nd) {
    char line[4200];
    char repr[512];
    int i;
    *nd = 0;
    for (i = 0; i < opt->nflags; i++) {
        if (!opt->flags[i][0]) {
            fprintf(stderr, "empty --flag\n");
            return -1;
        }
        if (snprintf(line, sizeof line, "flag=%s", opt->flags[i]) >= (int)sizeof line) {
            fprintf(stderr, "mad-elf: flag is too long\n");
            return -1;
        }
        if (add_directive(directives, nd, line) != 0) return -1;
    }
    for (i = 0; i < opt->nset; i++) {
        if (!strchr(opt->setenv[i], '=')) {
            py_repr(opt->setenv[i], repr, sizeof repr);
            fprintf(stderr, "--setenv needs KEY=VALUE, got %s\n", repr);
            return -1;
        }
        if (snprintf(line, sizeof line, "setenv=%s", opt->setenv[i]) >= (int)sizeof line) return -1;
        if (add_directive(directives, nd, line) != 0) return -1;
    }
    for (i = 0; i < opt->nforce; i++) {
        if (!strchr(opt->forceenv[i], '=')) {
            py_repr(opt->forceenv[i], repr, sizeof repr);
            fprintf(stderr, "--forceenv needs KEY=VALUE, got %s\n", repr);
            return -1;
        }
        if (snprintf(line, sizeof line, "forceenv=%s", opt->forceenv[i]) >= (int)sizeof line) return -1;
        if (add_directive(directives, nd, line) != 0) return -1;
    }
    for (i = 0; i < opt->nmerge; i++) {
        if (!strchr(opt->mergeenv[i], '=')) {
            py_repr(opt->mergeenv[i], repr, sizeof repr);
            fprintf(stderr, "--mergeenv needs KEY=VALUE, got %s\n", repr);
            return -1;
        }
        if (snprintf(line, sizeof line, "mergeenv=%s", opt->mergeenv[i]) >= (int)sizeof line) return -1;
        if (add_directive(directives, nd, line) != 0) return -1;
    }
    if (opt->marker_file) {
        if (snprintf(line, sizeof line, "markerfile=%s", opt->marker_file) >= (int)sizeof line) return -1;
        if (add_directive(directives, nd, line) != 0) return -1;
    }
    return 0;
}

static int take_val(int argc, char **argv, int *i, const char *arg, const char *name, const char **out) {
    const char *eq = strchr(arg, '=');
    if (eq) {
        *out = eq + 1;
        return 0;
    }
    if (*i + 1 >= argc) {
        fprintf(stderr, "mad-elf: %s needs a value\n", name);
        return -1;
    }
    *i += 1;
    *out = argv[*i];
    return 0;
}

static int cmd_install(int argc, char **argv, const char *argv0) {
    struct install_opts opt;
    char err[ERR_MAX];
    char src[4096], dst[4096];
    char *directives[MAX_DIRECTIVES];
    int nd = 0;
    int i;
    const char *kind;
    memset(&opt, 0, sizeof opt);
    memset(directives, 0, sizeof directives);
    for (i = 0; i < argc; i++) {
        const char *a = argv[i];
        const char *val = NULL;
        if (strcmp(a, "-h") == 0 || strcmp(a, "--help") == 0) {
            usage_install(stdout);
            return 0;
        }
        if (strncmp(a, "--shim", 6) == 0 && (a[6] == 0 || a[6] == '=')) {
            if (take_val(argc, argv, &i, a, "--shim", &val) != 0) return 2;
            opt.shim = val;
            continue;
        }
        if (strncmp(a, "--dylib", 7) == 0 && (a[7] == 0 || a[7] == '=')) {
            if (take_val(argc, argv, &i, a, "--dylib", &val) != 0) return 2;
            opt.dylib = val;
            continue;
        }
        if (strncmp(a, "--flag", 6) == 0 && (a[6] == 0 || a[6] == '=')) {
            if (take_val(argc, argv, &i, a, "--flag", &val) != 0) return 2;
            if (push_opt(opt.flags, &opt.nflags, val) != 0) {
                fprintf(stderr, "mad-elf: too many directives\n");
                return 1;
            }
            continue;
        }
        if (strncmp(a, "--setenv", 8) == 0 && (a[8] == 0 || a[8] == '=')) {
            if (take_val(argc, argv, &i, a, "--setenv", &val) != 0) return 2;
            if (push_opt(opt.setenv, &opt.nset, val) != 0) return 1;
            continue;
        }
        if (strncmp(a, "--forceenv", 10) == 0 && (a[10] == 0 || a[10] == '=')) {
            if (take_val(argc, argv, &i, a, "--forceenv", &val) != 0) return 2;
            if (push_opt(opt.forceenv, &opt.nforce, val) != 0) return 1;
            continue;
        }
        if (strncmp(a, "--mergeenv", 10) == 0 && (a[10] == 0 || a[10] == '=')) {
            if (take_val(argc, argv, &i, a, "--mergeenv", &val) != 0) return 2;
            if (push_opt(opt.mergeenv, &opt.nmerge, val) != 0) return 1;
            continue;
        }
        if (strcmp(a, "--marker-file") == 0 || strncmp(a, "--marker-file=", 14) == 0) {
            if (take_val(argc, argv, &i, a, "--marker-file", &val) != 0) return 2;
            opt.marker_file = val;
            continue;
        }
        if (strncmp(a, "--config", 8) == 0 && (a[8] == 0 || a[8] == '=')) {
            if (take_val(argc, argv, &i, a, "--config", &val) != 0) return 2;
            opt.config = val;
            continue;
        }
        if (strcmp(a, "--embed") == 0) {
            opt.embed = 1;
            continue;
        }
        if (strcmp(a, "--embed-only") == 0) {
            opt.embed_only = 1;
            continue;
        }
        if (a[0] == '-') {
            fprintf(stderr, "mad-elf: unknown option %s\n", a);
            return 2;
        }
        if (!opt.src) opt.src = a;
        else if (!opt.dst) opt.dst = a;
        else {
            fprintf(stderr, "mad-elf: unexpected argument %s\n", a);
            return 2;
        }
    }
    if (!opt.src || !opt.dst) {
        usage_install(stderr);
        fprintf(stderr, "mad-elf: install needs src and dst\n");
        return 2;
    }
    if (abs_norm(opt.src, src, sizeof src) != 0 || abs_norm(opt.dst, dst, sizeof dst) != 0) {
        fprintf(stderr, "mad-elf: path is too long\n");
        return 1;
    }
    if (!is_reg(src)) {
        fprintf(stderr, "mad-elf: not a file: %s\n", src);
        return 1;
    }
    if (build_directives(&opt, directives, &nd) != 0) {
        free_directives(directives, nd);
        return 1;
    }
    if (opt.config) {
        if (read_config_directives(opt.config, directives, &nd, err, sizeof err) != 0) {
            fprintf(stderr, "mad-elf: %s\n", err);
            free_directives(directives, nd);
            return 1;
        }
    }
    kind = file_kind(src);
    if (!kind) {
        fprintf(stderr, "mad-elf: cannot read %s: %s\n", src, strerror(errno));
        free_directives(directives, nd);
        return 1;
    }
    if (strcmp(kind, "elf") == 0) {
        char shim[4096];
        const char *shim_use = opt.shim;
        if (!shim_use) {
            if (default_shim(argv0, shim, sizeof shim, err, sizeof err) != 0) {
                fprintf(stderr, "mad-elf: %s\n", err);
                free_directives(directives, nd);
                return 1;
            }
            shim_use = shim;
        }
        if (install_elf(src, dst, shim_use, directives, nd, opt.embed, opt.embed_only, err,
                        sizeof err) != 0) {
            fprintf(stderr, "mad-elf: %s\n", err);
            free_directives(directives, nd);
            return 1;
        }
        free_directives(directives, nd);
        return 0;
    }
    if (strcmp(kind, "macho") == 0) {
        if (!opt.dylib) {
            fprintf(stderr, "mad-elf: Mach-O install needs --dylib /absolute/path/libmadelf.dylib\n");
            free_directives(directives, nd);
            return 1;
        }
        if (install_macho(src, dst, opt.dylib, directives, nd, err, sizeof err) != 0) {
            fprintf(stderr, "mad-elf: %s\n", err);
            free_directives(directives, nd);
            return 1;
        }
        free_directives(directives, nd);
        return 0;
    }
    fprintf(stderr, "mad-elf: %s is not an ELF or Mach-O executable\n", src);
    free_directives(directives, nd);
    return 1;
}

static int parse_pid(const char *s, int *out) {
    char *end = NULL;
    long v;
    if (!s || !s[0]) return -1;
    errno = 0;
    v = strtol(s, &end, 10);
    if (errno || !end || *end || end == s) return -1;
    if (v < INT_MIN || v > INT_MAX) return -1;
    *out = (int)v;
    return 0;
}

int main(int argc, char **argv) {
    int i;
    if (argc < 2) {
        usage_all(stderr);
        return 2;
    }
    if (strcmp(argv[1], "-h") == 0 || strcmp(argv[1], "--help") == 0) {
        usage_all(stdout);
        return 0;
    }
    if (strcmp(argv[1], "install") == 0) return cmd_install(argc - 2, argv + 2, argv[0]);
    if (strcmp(argv[1], "detect") == 0) {
        int pid;
        for (i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                fprintf(stdout, "usage: mad-elf detect <pid>\n");
                return 0;
            }
        }
        if (argc != 3) {
            fprintf(stderr, "usage: mad-elf detect <pid>\n");
            return 2;
        }
        if (parse_pid(argv[2], &pid) != 0) {
            fprintf(stderr, "mad-elf: detect: pid must be an integer\n");
            return 2;
        }
        return cmd_detect(pid);
    }
    if (strcmp(argv[1], "inspect") == 0) {
        for (i = 2; i < argc; i++) {
            if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
                fprintf(stdout, "usage: mad-elf inspect <file>\n");
                return 0;
            }
        }
        if (argc != 3) {
            fprintf(stderr, "usage: mad-elf inspect <file>\n");
            return 2;
        }
        return cmd_inspect(argv[2]);
    }
    fprintf(stderr, "mad-elf: unknown command '%s'\n", argv[1]);
    usage_all(stderr);
    return 2;
}
