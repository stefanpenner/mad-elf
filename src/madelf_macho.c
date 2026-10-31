#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "madelf_macho.h"

#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define MH_MAGIC_64 0xFEEDFACFu
#define FAT_MAGIC 0xCAFEBABEu
#define LC_SEGMENT_64 0x19u
#define LC_SYMTAB 0x2u
#define LC_DYSYMTAB 0xBu
#define LC_LOAD_DYLIB 0xCu
#define LC_LOAD_WEAK_DYLIB 0x80000018u
#define LC_CODE_SIGNATURE 0x1Du
#define LC_FUNCTION_STARTS 0x26u
#define LC_DATA_IN_CODE 0x29u
#define LC_DYLIB_CODE_SIGN_DRS 0x2Au
#define LC_LINKER_OPTIMIZATION_HINT 0x2Bu
#define LC_DYLD_EXPORTS_TRIE 0x2Cu
#define LC_DYLD_CHAINED_FIXUPS 0x2Du
#define S_ZEROFILL 1u

static void set_err(char *err, size_t errlen, const char *msg) {
    size_t i;
    if (!err || errlen == 0) return;
    if (!msg) msg = "unknown error";
    for (i = 0; i + 1 < errlen && msg[i]; i++) err[i] = msg[i];
    err[i] = 0;
}

static uint32_t rd32le(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static uint64_t rd64le(const unsigned char *p) {
    return (uint64_t)rd32le(p) | ((uint64_t)rd32le(p + 4) << 32);
}

static uint32_t rd32be(const unsigned char *p) {
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) |
           (uint32_t)p[3];
}

static void wr32le(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
    p[2] = (unsigned char)((v >> 16) & 0xff);
    p[3] = (unsigned char)((v >> 24) & 0xff);
}

static int is_dataoff_cmd(uint32_t cmd) {
    return cmd == LC_CODE_SIGNATURE || cmd == LC_DATA_IN_CODE || cmd == LC_FUNCTION_STARTS ||
           cmd == LC_DYLIB_CODE_SIGN_DRS || cmd == LC_LINKER_OPTIMIZATION_HINT ||
           cmd == LC_DYLD_EXPORTS_TRIE || cmd == LC_DYLD_CHAINED_FIXUPS;
}

int madelf_validate_dylib_path(const char *path, char *err, size_t errlen) {
    static const char *tokens[] = {"@executable_path", "@loader_path", "@rpath"};
    size_t i;
    if (!path || path[0] != '/') {
        snprintf(err, errlen,
                 "LC_LOAD_DYLIB path must be absolute (got %s). "
                 "@executable_path, @loader_path, and @rpath are rejected "
                 "so every launch resolves the same file.",
                 path ? path : "");
        return -1;
    }
    for (i = 0; i < sizeof tokens / sizeof tokens[0]; i++) {
        if (strstr(path, tokens[i])) {
            snprintf(err, errlen, "LC_LOAD_DYLIB path must not contain %s: %s", tokens[i], path);
            return -1;
        }
    }
    {
        size_t n = strlen(path);
        const char *suf = "/libmadelf.dylib";
        size_t sn = strlen(suf);
        if (n < sn || strcmp(path + n - sn, suf) != 0) {
            snprintf(err, errlen,
                     "the injected library path must end with /libmadelf.dylib "
                     "so detection can recognize it (got %s)",
                     path);
            return -1;
        }
    }
    return 0;
}

static int ends_with(const char *s, const char *suf) {
    size_t n, m;
    if (!s || !suf) return 0;
    n = strlen(s);
    m = strlen(suf);
    return n >= m && memcmp(s + n - m, suf, m) == 0;
}

struct slice {
    uint64_t base;
    uint64_t size;
};

static int slices_of(const unsigned char *data, size_t len, struct slice *out, int *out_n,
                     char *err, size_t errlen) {
    uint32_t magic, nfat, i;
    if (len >= 8 && rd32be(data) == FAT_MAGIC) {
        nfat = rd32be(data + 4);
        if (nfat == 0 || nfat > 8) {
            snprintf(err, errlen, "unreasonable fat arch count %u", nfat);
            return -1;
        }
        if (len < 8u + (size_t)nfat * 20u) {
            set_err(err, errlen, "truncated fat header");
            return -1;
        }
        for (i = 0; i < nfat; i++) {
            const unsigned char *a = data + 8 + i * 20;
            uint32_t offset = rd32be(a + 8);
            uint32_t size = rd32be(a + 12);
            if ((uint64_t)offset + size > len) {
                set_err(err, errlen, "fat slice extends past the file");
                return -1;
            }
            out[i].base = offset;
            out[i].size = size;
        }
        *out_n = (int)nfat;
        return 0;
    }
    magic = len >= 4 ? rd32le(data) : 0;
    if (magic != MH_MAGIC_64) {
        set_err(err, errlen, "not a 64-bit little-endian Mach-O (or fat) file");
        return -1;
    }
    out[0].base = 0;
    out[0].size = len;
    *out_n = 1;
    return 0;
}

struct cmd {
    uint64_t pos;
    uint32_t cmd;
    uint32_t cmdsize;
};

static int walk_commands(const unsigned char *data, uint64_t base, uint64_t size,
                         uint32_t *ncmds_out, uint32_t *sizeofcmds_out,
                         struct cmd *cmds, int cap, int *ncmds_list,
                         char *err, size_t errlen) {
    uint32_t ncmds, sizeofcmds, i;
    uint64_t pos, end;
    if (size < 32) {
        set_err(err, errlen, "Mach-O slice is too small");
        return -1;
    }
    if (rd32le(data + base) != MH_MAGIC_64) {
        set_err(err, errlen, "only 64-bit little-endian Mach-O slices are supported");
        return -1;
    }
    ncmds = rd32le(data + base + 16);
    sizeofcmds = rd32le(data + base + 20);
    if ((uint64_t)sizeofcmds > size - 32 || ncmds > 4096) {
        set_err(err, errlen, "unreasonable Mach-O load commands");
        return -1;
    }
    pos = base + 32;
    end = pos + sizeofcmds;
    *ncmds_list = 0;
    for (i = 0; i < ncmds; i++) {
        uint32_t cmd, cmdsize;
        if (pos + 8 > end) {
            set_err(err, errlen, "load command overruns sizeofcmds");
            return -1;
        }
        cmd = rd32le(data + pos);
        cmdsize = rd32le(data + pos + 4);
        if (cmdsize < 8 || pos + cmdsize > end) {
            set_err(err, errlen, "invalid load command size");
            return -1;
        }
        if (*ncmds_list < cap) {
            cmds[*ncmds_list].pos = pos;
            cmds[*ncmds_list].cmd = cmd;
            cmds[*ncmds_list].cmdsize = cmdsize;
            (*ncmds_list)++;
        }
        pos += cmdsize;
    }
    *ncmds_out = ncmds;
    *sizeofcmds_out = sizeofcmds;
    return 0;
}

static int push_off(uint64_t *found, int *n, int cap, uint64_t off) {
    if (off == 0) return 0;
    if (*n >= cap) return -1;
    found[(*n)++] = off;
    return 0;
}

static int content_offsets(const unsigned char *data, struct cmd *cmds, int ncmds,
                           uint64_t *found, int cap, int *nfound, char *err, size_t errlen) {
    int i;
    *nfound = 0;
    for (i = 0; i < ncmds; i++) {
        uint64_t pos = cmds[i].pos;
        uint32_t cmd = cmds[i].cmd;
        uint32_t cmdsize = cmds[i].cmdsize;
        if (cmd == LC_SEGMENT_64 && cmdsize >= 72) {
            uint64_t fileoff = rd64le(data + pos + 40);
            uint32_t nsects = rd32le(data + pos + 64);
            uint32_t s;
            uint64_t sec;
            if (push_off(found, nfound, cap, fileoff) != 0) {
                set_err(err, errlen, "too many Mach-O content offsets");
                return -1;
            }
            sec = pos + 72;
            for (s = 0; s < nsects; s++) {
                uint32_t offset, flags;
                if (sec + 80 > pos + cmdsize) break;
                offset = rd32le(data + sec + 48);
                flags = rd32le(data + sec + 64);
                if (offset > 0 && (flags & 0xffu) != S_ZEROFILL) {
                    if (push_off(found, nfound, cap, offset) != 0) {
                        set_err(err, errlen, "too many Mach-O content offsets");
                        return -1;
                    }
                }
                sec += 80;
            }
        } else if (cmd == LC_SYMTAB && cmdsize >= 24) {
            uint32_t symoff = rd32le(data + pos + 8);
            uint32_t stroff = rd32le(data + pos + 16);
            if (push_off(found, nfound, cap, symoff) != 0 ||
                push_off(found, nfound, cap, stroff) != 0) {
                set_err(err, errlen, "too many Mach-O content offsets");
                return -1;
            }
        } else if (cmd == LC_DYSYMTAB && cmdsize >= 80) {
            static const int rels[] = {32, 40, 48, 56, 64, 72};
            size_t r;
            for (r = 0; r < sizeof rels / sizeof rels[0]; r++) {
                uint32_t off = rd32le(data + pos + rels[r]);
                if (push_off(found, nfound, cap, off) != 0) {
                    set_err(err, errlen, "too many Mach-O content offsets");
                    return -1;
                }
            }
        } else if (is_dataoff_cmd(cmd) && cmdsize >= 16) {
            uint32_t dataoff = rd32le(data + pos + 8);
            if (push_off(found, nfound, cap, dataoff) != 0) {
                set_err(err, errlen, "too many Mach-O content offsets");
                return -1;
            }
        }
    }
    return 0;
}

static int dylib_paths_in_slice(const unsigned char *data, uint64_t base, uint64_t size,
                                char ***out, int *count, char *err, size_t errlen) {
    struct cmd cmds[4096];
    int ncmds_list = 0;
    uint32_t ncmds = 0, sizeofcmds = 0;
    int i, n = 0;
    char **list;
    if (walk_commands(data, base, size, &ncmds, &sizeofcmds, cmds, 4096, &ncmds_list, err,
                      errlen) != 0) {
        return -1;
    }
    list = calloc((size_t)ncmds_list + 1, sizeof(char *));
    if (!list) {
        set_err(err, errlen, "out of memory");
        return -1;
    }
    for (i = 0; i < ncmds_list; i++) {
        uint32_t name_off;
        const unsigned char *raw;
        size_t avail, k;
        char *s;
        if (cmds[i].cmd != LC_LOAD_DYLIB && cmds[i].cmd != LC_LOAD_WEAK_DYLIB) continue;
        if (cmds[i].cmdsize < 24) continue;
        name_off = rd32le(data + cmds[i].pos + 8);
        if (name_off >= cmds[i].cmdsize) continue;
        raw = data + cmds[i].pos + name_off;
        avail = cmds[i].cmdsize - name_off;
        k = 0;
        while (k < avail && raw[k] != 0) k++;
        s = malloc(k + 1);
        if (!s) {
            madelf_free_dylibs(list, n);
            set_err(err, errlen, "out of memory");
            return -1;
        }
        memcpy(s, raw, k);
        s[k] = 0;
        list[n++] = s;
    }
    *out = list;
    *count = n;
    return 0;
}

int madelf_load_dylibs(const char *path, char ***out, int *count, char *err, size_t errlen) {
    unsigned char *data = NULL;
    size_t len = 0;
    FILE *f;
    struct stat st;
    struct slice slices[8];
    int ns = 0, i, total = 0;
    char **all = NULL;
    int rc = -1;

    *out = NULL;
    *count = 0;
    f = fopen(path, "rb");
    if (!f) {
        snprintf(err, errlen, "%s", strerror(errno));
        return -1;
    }
    if (fstat(fileno(f), &st) != 0) {
        snprintf(err, errlen, "%s", strerror(errno));
        fclose(f);
        return -1;
    }
    if (st.st_size < 0 || (unsigned long long)st.st_size > 512ull * 1024ull * 1024ull) {
        set_err(err, errlen, "file is too large");
        fclose(f);
        return -1;
    }
    len = (size_t)st.st_size;
    data = malloc(len ? len : 1);
    if (!data) {
        set_err(err, errlen, "out of memory");
        fclose(f);
        return -1;
    }
    if (len && fread(data, 1, len, f) != len) {
        set_err(err, errlen, "truncated file");
        free(data);
        fclose(f);
        return -1;
    }
    fclose(f);
    if (slices_of(data, len, slices, &ns, err, errlen) != 0) {
        free(data);
        return -1;
    }
    all = NULL;
    for (i = 0; i < ns; i++) {
        char **part = NULL;
        int pn = 0, j;
        char **grown;
        if (dylib_paths_in_slice(data, slices[i].base, slices[i].size, &part, &pn, err, errlen) !=
            0) {
            madelf_free_dylibs(all, total);
            free(data);
            return -1;
        }
        if (pn == 0) {
            free(part);
            continue;
        }
        grown = realloc(all, (size_t)(total + pn) * sizeof(char *));
        if (!grown) {
            madelf_free_dylibs(part, pn);
            madelf_free_dylibs(all, total);
            set_err(err, errlen, "out of memory");
            free(data);
            return -1;
        }
        all = grown;
        for (j = 0; j < pn; j++) all[total++] = part[j];
        free(part);
    }
    *out = all;
    *count = total;
    rc = 0;
    free(data);
    return rc;
}

void madelf_free_dylibs(char **list, int count) {
    int i;
    if (!list) return;
    for (i = 0; i < count; i++) free(list[i]);
    free(list);
}

static int build_dylib_cmd(const char *path, unsigned char **out, size_t *outlen,
                           char *err, size_t errlen) {
    size_t rawlen = strlen(path) + 1;
    size_t size;
    unsigned char *buf;
    if (rawlen > 8192) {
        set_err(err, errlen, "dylib path is too long");
        return -1;
    }
    size = (24 + rawlen + 7) & ~(size_t)7;
    buf = calloc(1, size);
    if (!buf) {
        set_err(err, errlen, "out of memory");
        return -1;
    }
    wr32le(buf + 0, LC_LOAD_DYLIB);
    wr32le(buf + 4, (uint32_t)size);
    wr32le(buf + 8, 24);
    wr32le(buf + 12, 0);
    wr32le(buf + 16, 0x00010000u);
    wr32le(buf + 20, 0x00010000u);
    memcpy(buf + 24, path, rawlen);
    *out = buf;
    *outlen = size;
    return 0;
}

struct plan {
    int skip;
    uint64_t base;
    uint32_t ncmds;
    uint32_t sizeofcmds;
    uint64_t header_end;
};

int madelf_inject_load_dylib(const char *path, const char *dylib, char *err, size_t errlen) {
    unsigned char *data = NULL;
    size_t len = 0;
    FILE *f;
    struct stat st;
    struct slice slices[8];
    int ns = 0, i;
    unsigned char *cmd = NULL;
    size_t cmdlen = 0;
    struct plan plans[8];
    int any = 0;
    int rc = -1;

    if (madelf_validate_dylib_path(dylib, err, errlen) != 0) return -1;
    f = fopen(path, "rb");
    if (!f) {
        snprintf(err, errlen, "%s", strerror(errno));
        return -1;
    }
    if (fstat(fileno(f), &st) != 0) {
        snprintf(err, errlen, "%s", strerror(errno));
        fclose(f);
        return -1;
    }
    if (st.st_size < 0 || (unsigned long long)st.st_size > 512ull * 1024ull * 1024ull) {
        set_err(err, errlen, "file is too large");
        fclose(f);
        return -1;
    }
    len = (size_t)st.st_size;
    data = malloc(len ? len : 1);
    if (!data) {
        set_err(err, errlen, "out of memory");
        fclose(f);
        return -1;
    }
    if (len && fread(data, 1, len, f) != len) {
        set_err(err, errlen, "truncated file");
        free(data);
        fclose(f);
        return -1;
    }
    fclose(f);

    if (build_dylib_cmd(dylib, &cmd, &cmdlen, err, errlen) != 0) {
        free(data);
        return -1;
    }
    if (slices_of(data, len, slices, &ns, err, errlen) != 0) goto done;

    for (i = 0; i < ns; i++) {
        char **paths = NULL;
        int pn = 0, j;
        int have_exact = 0;
        const char *other = NULL;
        struct cmd cmds[4096];
        int nlist = 0;
        uint32_t ncmds = 0, sizeofcmds = 0;
        uint64_t offsets[4096];
        int noff = 0;
        uint64_t header_end, first;
        uint64_t slack;
        plans[i].skip = 0;
        if (dylib_paths_in_slice(data, slices[i].base, slices[i].size, &paths, &pn, err, errlen) !=
            0) {
            goto done;
        }
        for (j = 0; j < pn; j++) {
            if (!ends_with(paths[j], "/libmadelf.dylib")) continue;
            if (strcmp(paths[j], dylib) == 0) have_exact = 1;
            else if (!other) other = paths[j];
        }
        if (have_exact) {
            plans[i].skip = 1;
            madelf_free_dylibs(paths, pn);
            continue;
        }
        if (other) {
            snprintf(err, errlen,
                     "binary already loads a different mad-elf dylib (%s); "
                     "start from an unmodified copy",
                     other);
            madelf_free_dylibs(paths, pn);
            goto done;
        }
        madelf_free_dylibs(paths, pn);
        if (walk_commands(data, slices[i].base, slices[i].size, &ncmds, &sizeofcmds, cmds, 4096,
                          &nlist, err, errlen) != 0) {
            goto done;
        }
        if (content_offsets(data, cmds, nlist, offsets, 4096, &noff, err, errlen) != 0) goto done;
        header_end = 32 + (uint64_t)sizeofcmds;
        if (noff == 0) {
            set_err(err, errlen, "Mach-O slice has no section past the load commands; no header slack");
            goto done;
        }
        first = offsets[0];
        for (j = 1; j < noff; j++) {
            if (offsets[j] < first) first = offsets[j];
        }
        if (first < header_end) {
            set_err(err, errlen, "Mach-O load commands overlap file content");
            goto done;
        }
        slack = first - header_end;
        if (slack < cmdlen) {
            snprintf(err, errlen,
                     "not enough Mach-O header slack (%llu bytes, need %llu). "
                     "Relink with -Wl,-headerpad_max_install_names or use a binary that has header padding.",
                     (unsigned long long)slack, (unsigned long long)cmdlen);
            goto done;
        }
        plans[i].skip = 0;
        plans[i].base = slices[i].base;
        plans[i].ncmds = ncmds;
        plans[i].sizeofcmds = sizeofcmds;
        plans[i].header_end = header_end;
        any = 1;
    }
    if (!any) {
        rc = 0;
        goto done;
    }
    for (i = 0; i < ns; i++) {
        uint64_t at;
        if (plans[i].skip) continue;
        at = plans[i].base + plans[i].header_end;
        if (at + cmdlen > len) {
            set_err(err, errlen, "Mach-O header slack extends past the file");
            goto done;
        }
        memcpy(data + at, cmd, cmdlen);
        wr32le(data + plans[i].base + 16, plans[i].ncmds + 1);
        wr32le(data + plans[i].base + 20, plans[i].sizeofcmds + (uint32_t)cmdlen);
    }
    f = fopen(path, "r+b");
    if (!f) {
        snprintf(err, errlen, "%s", strerror(errno));
        goto done;
    }
    if (fwrite(data, 1, len, f) != len) {
        snprintf(err, errlen, "%s", strerror(errno));
        fclose(f);
        goto done;
    }
    if (fclose(f) != 0) {
        snprintf(err, errlen, "%s", strerror(errno));
        goto done;
    }
    rc = 0;

done:
    free(cmd);
    free(data);
    return rc;
}

int madelf_is_madelf_macho(const char *path) {
    char **paths = NULL;
    int n = 0, i;
    char err[256];
    int yes = 0;
    if (madelf_load_dylibs(path, &paths, &n, err, sizeof err) != 0) return 0;
    for (i = 0; i < n; i++) {
        if (paths[i][0] == '/' && ends_with(paths[i], "/libmadelf.dylib")) yes = 1;
    }
    madelf_free_dylibs(paths, n);
    return yes;
}
