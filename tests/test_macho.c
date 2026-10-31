/* Mach-O LC_LOAD_DYLIB injection. Runs without macOS. */
#include "madelf_macho.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define MH_MAGIC_64 0xFEEDFACFu
#define LC_SEGMENT_64 0x19u
#define LC_MAIN 0x80000028u
#define CPU_X86_64 0x01000007u
#define CPU_ARM64 0x0100000Cu
#define DYLIB "/usr/local/lib/mad-elf/libmadelf.dylib"

static int g_failed = 0;

static void expect(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_failed = 1;
    }
}

static void wr32le(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
    p[2] = (unsigned char)((v >> 16) & 0xff);
    p[3] = (unsigned char)((v >> 24) & 0xff);
}

static void wr64le(unsigned char *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++) p[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}

static void wr32be(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)((v >> 24) & 0xff);
    p[1] = (unsigned char)((v >> 16) & 0xff);
    p[2] = (unsigned char)((v >> 8) & 0xff);
    p[3] = (unsigned char)(v & 0xff);
}

static unsigned char *section(const char *sectname, const char *segname, uint64_t addr,
                              uint32_t offset, uint64_t size) {
    unsigned char *buf = calloc(1, 80);
    snprintf((char *)buf, 16, "%s", sectname);
    snprintf((char *)buf + 16, 16, "%s", segname);
    wr64le(buf + 32, addr);
    wr64le(buf + 40, size);
    wr32le(buf + 48, offset);
    wr32le(buf + 52, 2);
    return buf;
}

/* Returns malloc'd image. *outlen set. section_off is the first content offset. */
static unsigned char *build_macho(uint32_t cputype, uint32_t section_off, size_t *outlen) {
    const uint32_t seg_size = 72 + 80;
    const uint32_t sizeofcmds = seg_size + 24;
    unsigned char *header = calloc(1, 32);
    unsigned char *seg = calloc(1, 72);
    unsigned char *sec = section("__text", "__TEXT", section_off, section_off, 4);
    unsigned char *main = calloc(1, 24);
    size_t blob_len = 32 + 72 + 80 + 24;
    unsigned char *body;
    uint64_t filesz = section_off + 4;
    if (filesz < 0x100) filesz = 0x100;

    wr32le(header + 0, MH_MAGIC_64);
    wr32le(header + 4, cputype);
    wr32le(header + 8, 3);
    wr32le(header + 12, 2);
    wr32le(header + 16, 2);
    wr32le(header + 20, sizeofcmds);
    wr32le(header + 24, 1);

    wr32le(seg + 0, LC_SEGMENT_64);
    wr32le(seg + 4, seg_size);
    memcpy(seg + 8, "__TEXT", 6);
    wr64le(seg + 24, 0);
    wr64le(seg + 32, 0x1000);
    wr64le(seg + 40, 0);
    wr64le(seg + 48, filesz);
    wr32le(seg + 56, 7);
    wr32le(seg + 60, 5);
    wr32le(seg + 64, 1);
    wr32le(seg + 68, 0);

    wr32le(main + 0, LC_MAIN);
    wr32le(main + 4, 24);
    wr64le(main + 8, section_off);
    wr64le(main + 16, 0);

    if (section_off < blob_len) {
        fprintf(stderr, "section overlaps the header\n");
        exit(1);
    }
    body = calloc(1, section_off + 4);
    memcpy(body, header, 32);
    memcpy(body + 32, seg, 72);
    memcpy(body + 32 + 72, sec, 80);
    memcpy(body + 32 + 72 + 80, main, 24);
    body[section_off] = 0xc3;
    *outlen = section_off + 4;
    free(header);
    free(seg);
    free(sec);
    free(main);
    return body;
}

static unsigned char *build_fat(const unsigned char *a, size_t alen, const unsigned char *b, size_t blen,
                                size_t *outlen) {
    uint32_t off1 = 8 + 40;
    uint32_t off2;
    unsigned char *buf;
    off1 = (off1 + 7u) & ~7u;
    off2 = (uint32_t)((off1 + alen + 7u) & ~(size_t)7);
    *outlen = off2 + blen;
    buf = calloc(1, *outlen);
    wr32be(buf + 0, 0xCAFEBABE);
    wr32be(buf + 4, 2);
    wr32be(buf + 8, CPU_X86_64);
    wr32be(buf + 12, 3);
    wr32be(buf + 16, off1);
    wr32be(buf + 20, (uint32_t)alen);
    wr32be(buf + 24, 3);
    wr32be(buf + 28, CPU_ARM64);
    wr32be(buf + 32, 0);
    wr32be(buf + 36, off2);
    wr32be(buf + 40, (uint32_t)blen);
    wr32be(buf + 44, 3);
    memcpy(buf + off1, a, alen);
    memcpy(buf + off2, b, blen);
    return buf;
}

static char *write_temp(const unsigned char *data, size_t len, char *dir) {
    char *path = malloc(512);
    FILE *f;
    snprintf(path, 512, "%s/host", dir);
    f = fopen(path, "wb");
    if (!f || fwrite(data, 1, len, f) != len) {
        fprintf(stderr, "cannot write temp macho\n");
        exit(1);
    }
    fclose(f);
    return path;
}

static int count_exact(char **libs, int n, const char *path) {
    int i, c = 0;
    for (i = 0; i < n; i++) {
        if (strcmp(libs[i], path) == 0) c++;
    }
    return c;
}

static void test_thin(void) {
    char dir[] = "/tmp/madelf-macho-XXXXXX";
    unsigned char *img;
    size_t len = 0;
    char *path;
    char err[1024];
    char **libs = NULL;
    int n = 0;
    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        exit(1);
    }
    img = build_macho(CPU_X86_64, 0x400, &len);
    path = write_temp(img, len, dir);
    free(img);
    expect(madelf_inject_load_dylib(path, DYLIB, err, sizeof err) == 0, err);
    expect(madelf_load_dylibs(path, &libs, &n, err, sizeof err) == 0, err);
    expect(count_exact(libs, n, DYLIB) == 1, "thin binary missing dylib");
    expect(DYLIB[0] == '/', "path is absolute");
    expect(madelf_is_madelf_macho(path) == 1, "is_madelf_macho");
    madelf_free_dylibs(libs, n);
    libs = NULL;
    expect(madelf_inject_load_dylib(path, DYLIB, err, sizeof err) == 0, "idempotent inject");
    expect(madelf_load_dylibs(path, &libs, &n, err, sizeof err) == 0, err);
    expect(count_exact(libs, n, DYLIB) == 1, "dylib duplicated on second inject");
    madelf_free_dylibs(libs, n);
    unlink(path);
    free(path);
    rmdir(dir);
}

static void test_fat(void) {
    char dir[] = "/tmp/madelf-fat-XXXXXX";
    unsigned char *a, *b, *fat;
    size_t alen = 0, blen = 0, flen = 0;
    char *path;
    char err[1024];
    char **libs = NULL;
    int n = 0, i, marked = 0;
    if (!mkdtemp(dir)) exit(1);
    a = build_macho(CPU_X86_64, 0x400, &alen);
    b = build_macho(CPU_ARM64, 0x400, &blen);
    fat = build_fat(a, alen, b, blen, &flen);
    free(a);
    free(b);
    path = write_temp(fat, flen, dir);
    free(fat);
    expect(madelf_inject_load_dylib(path, DYLIB, err, sizeof err) == 0, err);
    expect(madelf_load_dylibs(path, &libs, &n, err, sizeof err) == 0, err);
    expect(count_exact(libs, n, DYLIB) == 2, "fat binary should load the dylib in both slices");
    for (i = 0; i < n; i++) {
        size_t ln = strlen(libs[i]);
        if (ln >= strlen("/libmadelf.dylib") &&
            strcmp(libs[i] + ln - strlen("/libmadelf.dylib"), "/libmadelf.dylib") == 0) {
            if (libs[i][0] == '/') marked++;
        }
    }
    expect(marked == 2, "mad-elf dylibs must stay absolute");
    madelf_free_dylibs(libs, n);
    unlink(path);
    free(path);
    rmdir(dir);
}

static void test_rejects(void) {
    char dir[] = "/tmp/madelf-bad-XXXXXX";
    unsigned char *img;
    size_t len = 0;
    char *path;
    unsigned char *before;
    const char *bad[] = {
        "libmadelf.dylib",
        "rel/libmadelf.dylib",
        "@executable_path/libmadelf.dylib",
        "@loader_path/libmadelf.dylib",
        "@rpath/libmadelf.dylib",
        "/tmp/libother.dylib",
        "/opt/@rpath/libmadelf.dylib",
    };
    size_t i;
    char err[1024];
    char **libs = NULL;
    int n = 0;
    FILE *f;
    if (!mkdtemp(dir)) exit(1);
    img = build_macho(CPU_X86_64, 0x400, &len);
    path = write_temp(img, len, dir);
    before = malloc(len);
    memcpy(before, img, len);
    free(img);
    for (i = 0; i < sizeof bad / sizeof bad[0]; i++) {
        int rc = madelf_inject_load_dylib(path, bad[i], err, sizeof err);
        if (rc == 0) {
            fprintf(stderr, "FAIL: accepted bad path %s\n", bad[i]);
            g_failed = 1;
        }
    }
    f = fopen(path, "rb");
    img = malloc(len);
    expect(f && fread(img, 1, len, f) == len, "reread host");
    if (f) fclose(f);
    expect(memcmp(img, before, len) == 0, "rejected inject modified the file");
    expect(madelf_load_dylibs(path, &libs, &n, err, sizeof err) == 0, err);
    expect(n == 0, "rejected paths left a load command");
    madelf_free_dylibs(libs, n);
    free(img);
    free(before);
    unlink(path);
    free(path);
    rmdir(dir);
}

static void test_no_slack(void) {
    char dir[] = "/tmp/madelf-slack-XXXXXX";
    unsigned char *img;
    size_t len = 0;
    char *path;
    char err[1024];
    const uint32_t section_off = 208; /* 32 + segment 152 + LC_MAIN 24 */
    if (!mkdtemp(dir)) exit(1);
    img = build_macho(CPU_X86_64, section_off, &len);
    expect(len == section_off + 4, "slack fixture size");
    path = write_temp(img, len, dir);
    free(img);
    err[0] = 0;
    expect(madelf_inject_load_dylib(path, DYLIB, err, sizeof err) != 0, "expected slack failure");
    expect(strstr(err, "slack") != NULL, err[0] ? err : "missing slack in error");
    unlink(path);
    free(path);
    rmdir(dir);
}

static void test_different_dylib(void) {
    char dir[] = "/tmp/madelf-diff-XXXXXX";
    unsigned char *img;
    size_t len = 0;
    char *path;
    char err[1024];
    const char *other = "/opt/other/libmadelf.dylib";
    if (!mkdtemp(dir)) exit(1);
    img = build_macho(CPU_X86_64, 0x400, &len);
    path = write_temp(img, len, dir);
    free(img);
    expect(madelf_inject_load_dylib(path, DYLIB, err, sizeof err) == 0, err);
    err[0] = 0;
    expect(madelf_inject_load_dylib(path, other, err, sizeof err) != 0, "different dylib should fail");
    expect(strstr(err, DYLIB) != NULL, err[0] ? err : "error should name the existing dylib");
    unlink(path);
    free(path);
    rmdir(dir);
}

int main(void) {
    test_thin();
    test_fat();
    test_rejects();
    test_no_slack();
    test_different_dylib();
    if (g_failed) {
        fprintf(stderr, "FAIL: test-macho\n");
        return 1;
    }
    printf("PASS: test-macho\n");
    return 0;
}
