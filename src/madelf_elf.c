#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "madelf_elf.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>

#define PT_INTERP 3

static void set_err(char *err, size_t errlen, const char *msg) {
    size_t i;
    if (!err || errlen == 0) return;
    if (!msg) msg = "unknown error";
    for (i = 0; i + 1 < errlen && msg[i]; i++) err[i] = msg[i];
    err[i] = 0;
}

static void set_errf(char *err, size_t errlen, const char *fmt, const char *a) {
    if (!err || errlen == 0) return;
    snprintf(err, errlen, fmt, a ? a : "");
}

static uint16_t rd16(const unsigned char *p) {
    return (uint16_t)p[0] | ((uint16_t)p[1] << 8);
}

static uint32_t rd32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const unsigned char *p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static void wr64(unsigned char *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++) p[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}

static int read_full(int fd, void *buf, size_t n) {
    unsigned char *p = buf;
    size_t off = 0;
    while (off < n) {
        ssize_t k = read(fd, p + off, n - off);
        if (k < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (k == 0) return -1;
        off += (size_t)k;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t n) {
    const unsigned char *p = buf;
    size_t off = 0;
    while (off < n) {
        ssize_t k = write(fd, p + off, n - off);
        if (k < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (k == 0) return -1;
        off += (size_t)k;
    }
    return 0;
}

static int pread_full(int fd, void *buf, size_t n, off_t at) {
    unsigned char *p = buf;
    size_t off = 0;
    while (off < n) {
        ssize_t k = pread(fd, p + off, n - off, at + (off_t)off);
        if (k < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (k == 0) return -1;
        off += (size_t)k;
    }
    return 0;
}

struct elf64_hdr {
    uint64_t phoff;
    uint64_t shoff;
    uint16_t phentsize;
    uint16_t phnum;
    uint16_t shentsize;
    uint16_t shnum;
    uint16_t shstrndx;
};

static int parse_ehdr(const unsigned char *b, size_t n, struct elf64_hdr *h,
                      char *err, size_t errlen) {
    if (n < 64 || b[0] != 0x7f || b[1] != 'E' || b[2] != 'L' || b[3] != 'F') {
        set_err(err, errlen, "not an ELF file");
        return -1;
    }
    if (b[4] != 2 || b[5] != 1) {
        set_err(err, errlen, "only ELF64 little-endian is supported");
        return -1;
    }
    h->phoff = rd64(b + 32);
    h->shoff = rd64(b + 40);
    h->phentsize = rd16(b + 54);
    h->phnum = rd16(b + 56);
    h->shentsize = rd16(b + 58);
    h->shnum = rd16(b + 60);
    h->shstrndx = rd16(b + 62);
    return 0;
}

static int load_phdrs(int fd, const struct elf64_hdr *h, unsigned char **out,
                      char *err, size_t errlen) {
    size_t nbytes;
    unsigned char *buf;
    if (h->phentsize < 56 || h->phnum > 512) {
        set_err(err, errlen, "unreasonable program header table");
        return -1;
    }
    nbytes = (size_t)h->phentsize * (size_t)h->phnum;
    buf = malloc(nbytes ? nbytes : 1);
    if (!buf) {
        set_err(err, errlen, "out of memory");
        return -1;
    }
    if (nbytes && pread_full(fd, buf, nbytes, (off_t)h->phoff) != 0) {
        free(buf);
        set_err(err, errlen, "truncated program header table");
        return -1;
    }
    *out = buf;
    return 0;
}

static int find_interp(const unsigned char *phdrs, const struct elf64_hdr *h,
                       int *slot, char *err, size_t errlen) {
    int i;
    int found = -1;
    for (i = 0; i < (int)h->phnum; i++) {
        const unsigned char *ph = phdrs + (size_t)i * h->phentsize;
        if (rd32(ph) != PT_INTERP) continue;
        if (found >= 0) {
            set_err(err, errlen, "multiple PT_INTERP headers");
            return -1;
        }
        found = i;
    }
    *slot = found;
    return 0;
}

int madelf_read_interpreter(const char *path, char *out, size_t outcap,
                            char *err, size_t errlen) {
    int fd;
    unsigned char ehdr[64];
    struct elf64_hdr h;
    unsigned char *phdrs = NULL;
    int slot = -1;
    uint64_t p_offset, p_filesz;
    unsigned char *raw = NULL;
    size_t n;
    int rc = -1;

    if (outcap) out[0] = 0;
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        set_errf(err, errlen, "%s", strerror(errno));
        return -1;
    }
    if (read_full(fd, ehdr, sizeof ehdr) != 0) {
        set_err(err, errlen, "not an ELF file");
        goto done;
    }
    if (parse_ehdr(ehdr, sizeof ehdr, &h, err, errlen) != 0) goto done;
    if (load_phdrs(fd, &h, &phdrs, err, errlen) != 0) goto done;
    if (find_interp(phdrs, &h, &slot, err, errlen) != 0) goto done;
    if (slot < 0) {
        rc = 1;
        goto done;
    }
    p_offset = rd64(phdrs + (size_t)slot * h.phentsize + 8);
    p_filesz = rd64(phdrs + (size_t)slot * h.phentsize + 32);
    if (p_filesz == 0 || p_filesz > 4096) {
        set_err(err, errlen, "PT_INTERP size is unreasonable");
        goto done;
    }
    raw = malloc((size_t)p_filesz + 1);
    if (!raw) {
        set_err(err, errlen, "out of memory");
        goto done;
    }
    if (pread_full(fd, raw, (size_t)p_filesz, (off_t)p_offset) != 0) {
        set_err(err, errlen, "truncated PT_INTERP");
        goto done;
    }
    n = 0;
    while (n < (size_t)p_filesz && raw[n] != 0) n++;
    if (n + 1 > outcap) {
        set_err(err, errlen, "interpreter path is too long");
        goto done;
    }
    memcpy(out, raw, n);
    out[n] = 0;
    rc = 0;

done:
    free(raw);
    free(phdrs);
    close(fd);
    return rc;
}

int madelf_set_interpreter(const char *path, const char *interp,
                           char *err, size_t errlen) {
    size_t ilen, rawlen;
    unsigned char raw[4097];
    int fd = -1;
    unsigned char ehdr[64];
    struct elf64_hdr h;
    unsigned char *phdrs = NULL;
    int slot = -1;
    unsigned char *ph;
    uint64_t p_offset, p_filesz;
    off_t end;
    size_t table;
    int rc = -1;

    if (!interp || interp[0] != '/') {
        set_errf(err, errlen, "interpreter path must be absolute: %s", interp ? interp : "");
        return -1;
    }
    ilen = strlen(interp);
    rawlen = ilen + 1;
    if (rawlen > 4096) {
        set_err(err, errlen, "interpreter path is too long");
        return -1;
    }
    memcpy(raw, interp, ilen);
    raw[ilen] = 0;

    fd = open(path, O_RDWR);
    if (fd < 0) {
        set_errf(err, errlen, "%s", strerror(errno));
        return -1;
    }
    if (read_full(fd, ehdr, sizeof ehdr) != 0) {
        set_err(err, errlen, "not an ELF file");
        goto done;
    }
    if (parse_ehdr(ehdr, sizeof ehdr, &h, err, errlen) != 0) goto done;
    if (load_phdrs(fd, &h, &phdrs, err, errlen) != 0) goto done;
    if (find_interp(phdrs, &h, &slot, err, errlen) != 0) goto done;
    if (slot < 0) {
        set_err(err, errlen, "no PT_INTERP; this is a static binary and cannot be patched");
        goto done;
    }
    ph = phdrs + (size_t)slot * h.phentsize;
    p_offset = rd64(ph + 8);
    p_filesz = rd64(ph + 32);

    if (rawlen <= p_filesz) {
        size_t pad;
        if (p_filesz > 4096) {
            set_err(err, errlen, "PT_INTERP size is unreasonable");
            goto done;
        }
        if (pwrite(fd, raw, rawlen, (off_t)p_offset) != (ssize_t)rawlen) {
            set_errf(err, errlen, "%s", strerror(errno));
            goto done;
        }
        pad = (size_t)p_filesz - rawlen;
        if (pad) {
            unsigned char zeros[4096];
            memset(zeros, 0, pad);
            if (pwrite(fd, zeros, pad, (off_t)p_offset + (off_t)rawlen) != (ssize_t)pad) {
                set_errf(err, errlen, "%s", strerror(errno));
                goto done;
            }
        }
        wr64(ph + 32, rawlen);
        wr64(ph + 40, rawlen);
    } else {
        end = lseek(fd, 0, SEEK_END);
        if (end < 0) {
            set_errf(err, errlen, "%s", strerror(errno));
            goto done;
        }
        if (write_full(fd, raw, rawlen) != 0) {
            set_errf(err, errlen, "%s", strerror(errno));
            goto done;
        }
        wr64(ph + 8, (uint64_t)end);
        wr64(ph + 32, rawlen);
        wr64(ph + 40, rawlen);
    }
    table = (size_t)h.phentsize * (size_t)h.phnum;
    if (pwrite(fd, phdrs, table, (off_t)h.phoff) != (ssize_t)table) {
        set_errf(err, errlen, "%s", strerror(errno));
        goto done;
    }
    rc = 0;

done:
    free(phdrs);
    if (fd >= 0) close(fd);
    return rc;
}

static int read_entire(const char *path, unsigned char **out, size_t *outlen,
                       char *err, size_t errlen) {
    int fd;
    struct stat st;
    unsigned char *buf;
    fd = open(path, O_RDONLY);
    if (fd < 0) {
        set_errf(err, errlen, "%s", strerror(errno));
        return -1;
    }
    if (fstat(fd, &st) != 0) {
        set_errf(err, errlen, "%s", strerror(errno));
        close(fd);
        return -1;
    }
    if (st.st_size < 0 || (unsigned long long)st.st_size > 512ull * 1024ull * 1024ull) {
        set_err(err, errlen, "file is too large");
        close(fd);
        return -1;
    }
    buf = malloc((size_t)st.st_size + 1);
    if (!buf) {
        set_err(err, errlen, "out of memory");
        close(fd);
        return -1;
    }
    if (st.st_size && read_full(fd, buf, (size_t)st.st_size) != 0) {
        set_err(err, errlen, "truncated file");
        free(buf);
        close(fd);
        return -1;
    }
    buf[st.st_size] = 0;
    close(fd);
    *out = buf;
    *outlen = (size_t)st.st_size;
    return 0;
}

static int range_ok(size_t len, uint64_t off, uint64_t n) {
    if (n > (uint64_t)len) return 0;
    if (off > (uint64_t)len) return 0;
    if (off + n > (uint64_t)len) return 0;
    return 1;
}

/* Returns 0 and malloc'd bytes (possibly empty) when the section exists.
 * 1 when the section is absent or the file has no section table.
 * -1 on a truncated ELF. */
static int read_section(const char *path, const char *name, unsigned char **out,
                        size_t *outlen, char *err, size_t errlen) {
    unsigned char *blob = NULL;
    size_t len = 0;
    struct elf64_hdr h;
    uint64_t shoff, str_off, str_size, off, size;
    uint16_t entsize;
    const unsigned char *names;
    const unsigned char *target;
    size_t tlen;
    int i;
    int rc = -1;

    *out = NULL;
    *outlen = 0;
    if (read_entire(path, &blob, &len, err, errlen) != 0) return -1;
    if (parse_ehdr(blob, len < 64 ? len : 64, &h, err, errlen) != 0) {
        /* Non-ELF: treat as no section, matching read_section's Python caller. */
        rc = 1;
        goto done;
    }
    if (!h.shoff || !h.shnum || h.shentsize < 64 || h.shstrndx >= h.shnum) {
        rc = 1;
        goto done;
    }
    shoff = h.shoff;
    entsize = h.shentsize;
    if (!range_ok(len, shoff, (uint64_t)entsize * h.shnum)) {
        set_err(err, errlen, "section header table is outside the file");
        goto done;
    }
    str_off = rd64(blob + shoff + (uint64_t)h.shstrndx * entsize + 24);
    str_size = rd64(blob + shoff + (uint64_t)h.shstrndx * entsize + 32);
    if (!range_ok(len, str_off, str_size)) {
        set_err(err, errlen, "section name table is outside the file");
        goto done;
    }
    names = blob + str_off;
    target = (const unsigned char *)name;
    tlen = strlen(name);
    for (i = 0; i < (int)h.shnum; i++) {
        const unsigned char *sh = blob + shoff + (uint64_t)i * entsize;
        uint32_t name_off = rd32(sh);
        size_t end;
        if (name_off >= str_size) continue;
        end = name_off;
        while (end < str_size && names[end] != 0) end++;
        if (end >= str_size) continue;
        if (end - name_off != tlen) continue;
        if (memcmp(names + name_off, target, tlen) != 0) continue;
        off = rd64(sh + 24);
        size = rd64(sh + 32);
        if (!range_ok(len, off, size)) {
            set_errf(err, errlen, "section %s is outside the file", name);
            goto done;
        }
        *out = malloc((size_t)size + 1);
        if (!*out) {
            set_err(err, errlen, "out of memory");
            goto done;
        }
        memcpy(*out, blob + off, (size_t)size);
        (*out)[size] = 0;
        *outlen = (size_t)size;
        rc = 0;
        goto done;
    }
    rc = 1;

done:
    free(blob);
    return rc;
}

static int read_text_file(const char *path, char **out, char *err, size_t errlen) {
    unsigned char *buf = NULL;
    size_t len = 0;
    if (read_entire(path, &buf, &len, err, errlen) != 0) return -1;
    *out = (char *)buf;
    return 0;
}

int madelf_read_config_text(const char *path, char **out, char *err, size_t errlen) {
    char sidecar[4096];
    int n;
    struct stat st;
    unsigned char *sec = NULL;
    size_t seclen = 0;
    int rc;

    *out = NULL;
    n = snprintf(sidecar, sizeof sidecar, "%s.madelf", path);
    if (n < 0 || (size_t)n >= sizeof sidecar) {
        set_err(err, errlen, "path is too long");
        return -1;
    }
    if (stat(sidecar, &st) == 0 && S_ISREG(st.st_mode)) {
        return read_text_file(sidecar, out, err, errlen);
    }
    rc = read_section(path, ".madelf", &sec, &seclen, err, errlen);
    if (rc != 0) return rc;
    *out = (char *)sec;
    return 0;
}

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
        if (dlen == 0) {
            nn = snprintf(buf, sizeof buf, "%s", name);
        } else {
            nn = snprintf(buf, sizeof buf, "%.*s/%s", (int)dlen, p, name);
        }
        if (nn > 0 && (size_t)nn < sizeof buf && access(buf, X_OK) == 0) return 1;
        if (!colon) break;
        p = colon + 1;
    }
    return 0;
}

static int run_capture(char *const argv[], char *errbuf, size_t errcap) {
    int pipefd[2];
    pid_t pid;
    int status;
    size_t got = 0;
    if (errbuf && errcap) errbuf[0] = 0;
    if (pipe(pipefd) != 0) return -1;
    pid = fork();
    if (pid < 0) {
        close(pipefd[0]);
        close(pipefd[1]);
        return -1;
    }
    if (pid == 0) {
        int dn = open("/dev/null", O_RDONLY);
        if (dn >= 0) dup2(dn, STDIN_FILENO);
        dup2(pipefd[1], STDOUT_FILENO);
        dup2(pipefd[1], STDERR_FILENO);
        close(pipefd[0]);
        close(pipefd[1]);
        execvp(argv[0], argv);
        _exit(127);
    }
    close(pipefd[1]);
    if (errbuf && errcap > 1) {
        while (got + 1 < errcap) {
            ssize_t k = read(pipefd[0], errbuf + got, errcap - 1 - got);
            if (k < 0) {
                if (errno == EINTR) continue;
                break;
            }
            if (k == 0) break;
            got += (size_t)k;
        }
        errbuf[got] = 0;
    }
    close(pipefd[0]);
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

int madelf_embed_config_section(const char *path, const char *text,
                                char *err, size_t errlen) {
    char tmpl[] = "/tmp/madelf-cfg-XXXXXX";
    int fd;
    size_t len, off;
    char arg_add[4200];
    char captured[1024];
    int rc;
    char *rm_argv[5];
    char *add_argv[7];

    if (!command_exists("objcopy")) {
        set_err(err, errlen, "objcopy is required to embed a .madelf section");
        return -1;
    }
    fd = mkstemp(tmpl);
    if (fd < 0) {
        set_errf(err, errlen, "%s", strerror(errno));
        return -1;
    }
    len = text ? strlen(text) : 0;
    off = 0;
    while (off < len) {
        ssize_t k = write(fd, text + off, len - off);
        if (k < 0) {
            if (errno == EINTR) continue;
            set_errf(err, errlen, "%s", strerror(errno));
            close(fd);
            unlink(tmpl);
            return -1;
        }
        off += (size_t)k;
    }
    if (close(fd) != 0) {
        set_errf(err, errlen, "%s", strerror(errno));
        unlink(tmpl);
        return -1;
    }

    rm_argv[0] = "objcopy";
    rm_argv[1] = "--remove-section";
    rm_argv[2] = ".madelf";
    rm_argv[3] = (char *)path;
    rm_argv[4] = NULL;
    /* Absent section is not an error on every objcopy. */
    (void)run_capture(rm_argv, captured, sizeof captured);

    if (snprintf(arg_add, sizeof arg_add, ".madelf=%s", tmpl) >= (int)sizeof arg_add) {
        set_err(err, errlen, "temporary path is too long");
        unlink(tmpl);
        return -1;
    }
    add_argv[0] = "objcopy";
    add_argv[1] = "--add-section";
    add_argv[2] = arg_add;
    add_argv[3] = "--set-section-flags";
    add_argv[4] = ".madelf=noload,readonly,contents";
    add_argv[5] = (char *)path;
    add_argv[6] = NULL;
    rc = run_capture(add_argv, captured, sizeof captured);
    unlink(tmpl);
    if (rc != 0) {
        while (captured[0] && (captured[strlen(captured) - 1] == '\n' ||
                               captured[strlen(captured) - 1] == '\r')) {
            captured[strlen(captured) - 1] = 0;
        }
        if (captured[0]) set_errf(err, errlen, "objcopy failed: %s", captured);
        else set_err(err, errlen, "objcopy failed");
        return -1;
    }
    return 0;
}

static const char *skip_ws(const char *s) {
    while (*s == ' ' || *s == '\t' || *s == '\r') s++;
    return s;
}

static void rtrim(char *s) {
    size_t n = strlen(s);
    while (n > 0 && (s[n - 1] == ' ' || s[n - 1] == '\t' || s[n - 1] == '\r')) {
        s[--n] = 0;
    }
}

int madelf_first_loader(const char *text, char *out, size_t outcap) {
    const char *p;
    if (!text || !out || outcap == 0) return 1;
    out[0] = 0;
    p = text;
    while (*p) {
        char line[4096];
        size_t n = 0;
        const char *s;
        while (*p && *p != '\n' && n + 1 < sizeof line) line[n++] = *p++;
        line[n] = 0;
        if (*p == '\n') p++;
        else if (*p) return 1;
        rtrim(line);
        s = skip_ws(line);
        if (strncmp(s, "loader=", 7) == 0 && strncmp(s, "loader=#", 8) != 0) {
            snprintf(out, outcap, "%s", s + 7);
            return 0;
        }
    }
    return 1;
}

int madelf_is_madelf_elf(const char *path) {
    char interp[4096];
    char err[512];
    char *text = NULL;
    char loader[4096];
    const char *base;
    const char *p;
    int rc;

    rc = madelf_read_interpreter(path, interp, sizeof interp, err, sizeof err);
    if (rc != 0 || interp[0] == 0) return 0;
    base = interp;
    for (p = interp; *p; p++) {
        if (*p == '/') base = p + 1;
    }
    if (strcmp(base, "mad-elf-shim") == 0) return 1;
    if (madelf_read_config_text(path, &text, err, sizeof err) != 0 || !text || !text[0]) {
        free(text);
        return 0;
    }
    rc = madelf_first_loader(text, loader, sizeof loader);
    free(text);
    if (rc == 0 && loader[0] && strcmp(loader, interp) != 0) return 1;
    return 0;
}
