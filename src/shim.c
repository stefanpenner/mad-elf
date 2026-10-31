#include "logic.h"

/* Freestanding on purpose. A glibc static-pie uses the auxiliary vector to
 * relocate itself; when the kernel runs us as PT_INTERP that vector describes
 * the main executable, and glibc faults. This file uses only RIP-relative
 * code and syscalls, then execs the real ld.so. */

static long syscall3(long n, long a, long b, long c) {
    long ret;
    __asm__ volatile ("syscall"
                      : "=a"(ret)
                      : "a"(n), "D"(a), "S"(b), "d"(c)
                      : "rcx", "r11", "memory");
    return ret;
}

static long syscall4(long n, long a, long b, long c, long d) {
    long ret;
    register long r10 __asm__("r10") = d;
    __asm__ volatile ("syscall"
                      : "=a"(ret)
                      : "a"(n), "D"(a), "S"(b), "d"(c), "r"(r10)
                      : "rcx", "r11", "memory");
    return ret;
}

static void wr(const char *s) {
    unsigned long n = 0;
    while (s[n]) n++;
    syscall3(1, 2, (long)s, (long)n);
}

static void wr_num(long v) {
    char buf[32];
    int i = 0;
    unsigned long u;
    if (v < 0) {
        wr("-");
        u = (unsigned long)(-v);
    } else {
        u = (unsigned long)v;
    }
    if (u == 0) { wr("0"); return; }
    while (u && i < (int)sizeof buf) {
        buf[i++] = (char)('0' + (u % 10));
        u /= 10;
    }
    while (i > 0) {
        char c[2];
        c[0] = buf[--i];
        c[1] = 0;
        wr(c);
    }
}

static size_t slen(const char *s) {
    size_t n = 0;
    while (s[n]) n++;
    return n;
}

static int seq(const char *a, const char *b) {
    while (*a && *a == *b) { a++; b++; }
    return *a == 0 && *b == 0;
}

#define AT_FDCWD (-100)
#define O_RDONLY 0

static int read_entire(const char *path, char *buf, size_t cap, size_t *out) {
    long fd = syscall4(257, AT_FDCWD, (long)path, O_RDONLY, 0);
    size_t got = 0;
    if (fd < 0) return -1;
    while (got + 1 < cap) {
        long n = syscall3(0, fd, (long)(buf + got), (long)(cap - 1 - got));
        if (n < 0) { syscall3(3, fd, 0, 0); return -1; }
        if (n == 0) break;
        got += (size_t)n;
    }
    if (got + 1 >= cap) {
        char extra;
        long n = syscall3(0, fd, (long)&extra, 1);
        if (n > 0) { syscall3(3, fd, 0, 0); return -1; }
    }
    buf[got] = 0;
    *out = got;
    syscall3(3, fd, 0, 0);
    return 0;
}

static int pread_all(long fd, char *buf, size_t n, unsigned long off) {
    size_t got = 0;
    if (syscall3(8, fd, (long)off, 0) < 0) return -1; /* lseek SET */
    while (got < n) {
        long r = syscall3(0, fd, (long)(buf + got), (long)(n - got));
        if (r < 0) return -1;
        if (r == 0) return -1;
        got += (size_t)r;
    }
    return 0;
}

static unsigned short ru16(const unsigned char *p) {
    return (unsigned short)(p[0] | (p[1] << 8));
}
static unsigned int ru32(const unsigned char *p) {
    return (unsigned int)p[0] | ((unsigned int)p[1] << 8) |
           ((unsigned int)p[2] << 16) | ((unsigned int)p[3] << 24);
}
static unsigned long ru64(const unsigned char *p) {
    return (unsigned long)ru32(p) | ((unsigned long)ru32(p + 4) << 32);
}

static int elf_inspect(const char *path, char *section, size_t section_cap, size_t *section_len) {
    unsigned char ehdr[64];
    long fd;
    unsigned long shoff;
    unsigned short shentsize, shnum, shstrndx;
    unsigned short i;
    if (section_len) *section_len = 0;
    fd = syscall4(257, AT_FDCWD, (long)path, O_RDONLY, 0);
    if (fd < 0) return -1;
    if (pread_all(fd, (char *)ehdr, 64, 0)) { syscall3(3, fd, 0, 0); return -1; }
    if (!(ehdr[0] == 0x7f && ehdr[1] == 'E' && ehdr[2] == 'L' && ehdr[3] == 'F')) {
        syscall3(3, fd, 0, 0);
        return -1;
    }
    if (ehdr[4] != 2 || ehdr[5] != 1) { /* ELFCLASS64, ELFDATA2LSB */
        syscall3(3, fd, 0, 0);
        return -1;
    }
    shoff = ru64(ehdr + 40);
    shentsize = ru16(ehdr + 58);
    shnum = ru16(ehdr + 60);
    shstrndx = ru16(ehdr + 62);
    if (section && section_cap && shoff && shentsize >= 64 && shnum && shnum < 512 &&
        shstrndx < shnum) {
        unsigned char shdr[64];
        unsigned long str_off = 0, str_size = 0;
        char namebuf[4096];
        if (pread_all(fd, (char *)shdr, 64, shoff + (unsigned long)shstrndx * shentsize)) {
            syscall3(3, fd, 0, 0);
            return 0;
        }
        str_off = ru64(shdr + 24);
        str_size = ru64(shdr + 32);
        if (str_size > sizeof namebuf) str_size = sizeof namebuf;
        if (str_size && pread_all(fd, namebuf, (size_t)str_size, str_off) == 0) {
            for (i = 0; i < shnum; i++) {
                unsigned int name_off;
                unsigned long off, size;
                const char *name;
                if (pread_all(fd, (char *)shdr, 64, shoff + (unsigned long)i * shentsize)) break;
                name_off = ru32(shdr);
                off = ru64(shdr + 24);
                size = ru64(shdr + 32);
                if ((unsigned long)name_off + 8 > str_size) continue;
                name = namebuf + name_off;
                if (name[0] == '.' && name[1] == 'm' && name[2] == 'a' && name[3] == 'd' &&
                    name[4] == 'e' && name[5] == 'l' && name[6] == 'f' && name[7] == 0) {
                    if (size >= section_cap) size = section_cap - 1;
                    if (pread_all(fd, section, (size_t)size, off) == 0) {
                        section[size] = 0;
                        if (section_len) *section_len = (size_t)size;
                    }
                    break;
                }
            }
        }
    }
    syscall3(3, fd, 0, 0);
    return 0;
}

static int elf_read_interp(const char *path, char *out, size_t cap) {
    unsigned char ehdr[64];
    long fd;
    unsigned long phoff;
    unsigned short phentsize, phnum, i;
    fd = syscall4(257, AT_FDCWD, (long)path, O_RDONLY, 0);
    if (fd < 0) return -1;
    if (pread_all(fd, (char *)ehdr, 64, 0)) { syscall3(3, fd, 0, 0); return -1; }
    if (!(ehdr[0] == 0x7f && ehdr[1] == 'E' && ehdr[2] == 'L' && ehdr[3] == 'F' &&
          ehdr[4] == 2 && ehdr[5] == 1)) {
        syscall3(3, fd, 0, 0);
        return -1;
    }
    phoff = ru64(ehdr + 32);
    phentsize = ru16(ehdr + 54);
    phnum = ru16(ehdr + 56);
    if (phentsize < 56 || phnum > 128) { syscall3(3, fd, 0, 0); return -1; }
    for (i = 0; i < phnum; i++) {
        unsigned char ph[56];
        unsigned int p_type;
        unsigned long p_offset, p_filesz;
        if (pread_all(fd, (char *)ph, 56, phoff + (unsigned long)i * phentsize)) {
            syscall3(3, fd, 0, 0);
            return -1;
        }
        p_type = ru32(ph);
        if (p_type != 3) continue;
        p_offset = ru64(ph + 8);
        p_filesz = ru64(ph + 32);
        if (p_filesz == 0 || p_filesz >= cap) {
            syscall3(3, fd, 0, 0);
            return -1;
        }
        if (pread_all(fd, out, (size_t)p_filesz, p_offset)) {
            syscall3(3, fd, 0, 0);
            return -1;
        }
        out[p_filesz - 1] = 0;
        /* ensure a terminator even if the file omitted one inside filesz */
        {
            size_t n = 0;
            while (n < p_filesz && out[n]) n++;
            out[n] = 0;
        }
        syscall3(3, fd, 0, 0);
        return 0;
    }
    syscall3(3, fd, 0, 0);
    out[0] = 0;
    return 0;
}

static char g_file[65536];
static char g_section[65536];
static char g_arena[262144];
static char *g_env[4096];
static char *g_argv[4096];

static int paths_same(const char *a, const char *b) {
    return seq(a, b);
}

int madelf_main(unsigned long *sp) {
    unsigned long argc = sp[0];
    char **argv = (char **)(sp + 1);
    char **envp = argv + argc + 1;
    char exe[4096];
    char interp[MADELF_PATH_MAX];
    char err[256];
    long n;
    size_t flen = 0, slen_sec = 0;
    struct madelf_config cfg;
    const char *text = 0;
    int built_argc;
    char cfgpath[4096];
    size_t elen;
    size_t i;

    n = syscall3(89, (long)"/proc/self/exe", (long)exe, (long)(sizeof exe - 1));
    if (n <= 0) {
        wr("mad-elf-shim: readlink /proc/self/exe failed\n");
        return 127;
    }
    exe[n] = 0;

    elen = slen(exe);
    if (elen + 8 >= sizeof cfgpath) {
        wr("mad-elf-shim: executable path too long\n");
        return 127;
    }
    for (i = 0; i < elen; i++) cfgpath[i] = exe[i];
    cfgpath[elen] = '.';
    cfgpath[elen + 1] = 'm';
    cfgpath[elen + 2] = 'a';
    cfgpath[elen + 3] = 'd';
    cfgpath[elen + 4] = 'e';
    cfgpath[elen + 5] = 'l';
    cfgpath[elen + 6] = 'f';
    cfgpath[elen + 7] = 0;

    if (read_entire(cfgpath, g_file, sizeof g_file, &flen) == 0) {
        text = g_file;
    } else {
        if (elf_inspect(exe, g_section, sizeof g_section, &slen_sec) == 0 && slen_sec > 0) {
            text = g_section;
        }
    }

    interp[0] = 0;
    if (elf_read_interp(exe, interp, sizeof interp) != 0) {
        wr("mad-elf-shim: ");
        wr(exe);
        wr(" is not a readable ELF64 file\n");
        return 127;
    }

    if (!text) {
        if (interp[0] == 0) {
            wr("mad-elf-shim: ");
            wr(exe);
            wr("\nThis program is the PT_INTERP shim. The kernel runs it when a patched\n");
            wr("binary is exec'd. Install with: mad-elf install <binary> <copy>\n");
            return 2;
        }
        wr("mad-elf-shim: no config for ");
        wr(exe);
        wr("\nLooked for a sibling .madelf file and an embedded .madelf section.\n");
        wr("The original dynamic loader path is only stored in that config.\n");
        return 127;
    }

    err[0] = 0;
    if (madelf_parse_config(text, &cfg, err, sizeof err) != 0) {
        wr("mad-elf-shim: bad config: ");
        wr(err[0] ? err : "parse error");
        wr("\n");
        return 127;
    }
    if (!cfg.loader[0]) {
        wr("mad-elf-shim: config has no loader= line, so the original ld.so path is unknown\n");
        return 127;
    }
    if (paths_same(cfg.loader, exe) || paths_same(cfg.loader, interp)) {
        wr("mad-elf-shim: refusing to exec the loader (");
        wr(cfg.loader);
        wr(") because it would loop back into the shim\n");
        return 127;
    }

    err[0] = 0;
    built_argc = madelf_build_argv((int)argc, argv, cfg.loader, exe, &cfg,
                                   g_argv, (int)(sizeof g_argv / sizeof g_argv[0]),
                                   err, sizeof err);
    if (built_argc < 0) {
        wr("mad-elf-shim: ");
        wr(err[0] ? err : "argv build failed");
        wr("\n");
        return 127;
    }
    err[0] = 0;
    if (madelf_build_env(envp, &cfg, g_env, (int)(sizeof g_env / sizeof g_env[0]),
                         g_arena, sizeof g_arena, err, sizeof err) < 0) {
        wr("mad-elf-shim: ");
        wr(err[0] ? err : "env build failed");
        wr("\n");
        return 127;
    }

    n = syscall3(59, (long)cfg.loader, (long)g_argv, (long)g_env);
    wr("mad-elf-shim: execve ");
    wr(cfg.loader);
    wr(" failed errno=");
    wr_num(n < 0 ? -n : n);
    wr("\n");
    return 127;
}
