/* ELF64 PT_INTERP rewrite: in place when the new path fits, otherwise append
 * the path and retarget the existing program header. */
#include "madelf_elf.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int g_failed = 0;

static void expect(int cond, const char *msg) {
    if (!cond) {
        fprintf(stderr, "FAIL: %s\n", msg);
        g_failed = 1;
    }
}

static void wr16(unsigned char *p, uint16_t v) {
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)(v >> 8);
}

static void wr32(unsigned char *p, uint32_t v) {
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
    p[2] = (unsigned char)((v >> 16) & 0xff);
    p[3] = (unsigned char)((v >> 24) & 0xff);
}

static void wr64(unsigned char *p, uint64_t v) {
    int i;
    for (i = 0; i < 8; i++) p[i] = (unsigned char)((v >> (8 * i)) & 0xff);
}

static uint32_t rd32(const unsigned char *p) {
    return (uint32_t)p[0] | ((uint32_t)p[1] << 8) | ((uint32_t)p[2] << 16) | ((uint32_t)p[3] << 24);
}

static uint64_t rd64(const unsigned char *p) {
    return (uint64_t)rd32(p) | ((uint64_t)rd32(p + 4) << 32);
}

static void fill_ehdr(unsigned char *eh, uint16_t phnum, uint64_t shoff, uint16_t shnum,
                      uint16_t shstrndx) {
    memset(eh, 0, 64);
    eh[0] = 0x7f;
    eh[1] = 'E';
    eh[2] = 'L';
    eh[3] = 'F';
    eh[4] = 2;
    eh[5] = 1;
    eh[6] = 1;
    wr16(eh + 16, 2);
    wr16(eh + 18, 62);
    wr32(eh + 20, 1);
    wr64(eh + 32, 64);
    wr64(eh + 40, shoff);
    wr16(eh + 52, 64);
    wr16(eh + 54, 56);
    wr16(eh + 56, phnum);
    wr16(eh + 58, shnum ? 64 : 0);
    wr16(eh + 60, shnum);
    wr16(eh + 62, shstrndx);
}

static void fill_interp_ph(unsigned char *ph, uint64_t off, uint64_t filesz) {
    memset(ph, 0, 56);
    wr32(ph, 3);
    wr32(ph + 4, 4);
    wr64(ph + 8, off);
    wr64(ph + 16, 0x400000);
    wr64(ph + 32, filesz);
    wr64(ph + 40, filesz);
    wr64(ph + 48, 1);
}

static char *write_bytes(const char *dir, const char *name, const unsigned char *data, size_t len) {
    char *path = malloc(512);
    FILE *f;
    snprintf(path, 512, "%s/%s", dir, name);
    f = fopen(path, "wb");
    if (!f || fwrite(data, 1, len, f) != len) exit(1);
    fclose(f);
    return path;
}

static int read_interp_ph(const char *path, uint64_t *off, uint64_t *filesz, uint64_t *memsz,
                          uint64_t *vaddr) {
    FILE *f = fopen(path, "rb");
    unsigned char eh[64];
    unsigned char ph[56];
    uint16_t phnum, phentsize;
    uint64_t phoff;
    int i;
    if (!f) return -1;
    if (fread(eh, 1, 64, f) != 64) {
        fclose(f);
        return -1;
    }
    phoff = rd64(eh + 32);
    phentsize = (uint16_t)(eh[54] | (eh[55] << 8));
    phnum = (uint16_t)(eh[56] | (eh[57] << 8));
    for (i = 0; i < phnum; i++) {
        if (fseek(f, (long)(phoff + (uint64_t)i * phentsize), SEEK_SET) != 0) break;
        if (fread(ph, 1, 56, f) != 56) break;
        if (rd32(ph) != 3) continue;
        *off = rd64(ph + 8);
        *vaddr = rd64(ph + 16);
        *filesz = rd64(ph + 32);
        *memsz = rd64(ph + 40);
        fclose(f);
        return 0;
    }
    fclose(f);
    return -1;
}

static void test_inplace_and_append(void) {
    char dir[] = "/tmp/madelf-elf-XXXXXX";
    unsigned char img[256];
    char *path;
    char err[512];
    char got[256];
    uint64_t off, filesz, memsz, vaddr;
    const char *orig = "/lib/ld.so";
    const char *shorter = "/a";
    const char *longer = "/opt/mad-elf/lib/ld-linux-x86-64.so.2";
    size_t orig_len = strlen(orig) + 1;
    uint64_t room = 64;
    uint64_t orig_off;

    if (!mkdtemp(dir)) exit(1);
    memset(img, 0, sizeof img);
    fill_ehdr(img, 1, 0, 0, 0);
    orig_off = 64 + 56;
    fill_interp_ph(img + 64, orig_off, room);
    memcpy(img + orig_off, orig, orig_len);
    path = write_bytes(dir, "bin", img, (size_t)(orig_off + room));

    expect(madelf_read_interpreter(path, got, sizeof got, err, sizeof err) == 0, err);
    expect(strcmp(got, orig) == 0, "initial interpreter");

    expect(madelf_set_interpreter(path, shorter, err, sizeof err) == 0, err);
    expect(read_interp_ph(path, &off, &filesz, &memsz, &vaddr) == 0, "read phdr");
    expect(off == orig_off, "in-place rewrite keeps p_offset");
    expect(filesz == strlen(shorter) + 1, "in-place p_filesz");
    expect(memsz == filesz, "in-place p_memsz follows p_filesz");
    expect(vaddr == 0x400000, "p_vaddr unchanged");
    expect(madelf_read_interpreter(path, got, sizeof got, err, sizeof err) == 0, err);
    expect(strcmp(got, shorter) == 0, "short interpreter readable");

    {
        FILE *f = fopen(path, "rb");
        long sz;
        fseek(f, 0, SEEK_END);
        sz = ftell(f);
        fclose(f);
        expect(madelf_set_interpreter(path, longer, err, sizeof err) == 0, err);
        expect(read_interp_ph(path, &off, &filesz, &memsz, &vaddr) == 0, "read appended phdr");
        expect(off == (uint64_t)sz, "appended path starts at the old end of file");
        expect(filesz == strlen(longer) + 1, "appended p_filesz");
        expect(memsz == filesz, "appended p_memsz");
        expect(vaddr == 0x400000, "append does not invent a new program header");
        expect(madelf_read_interpreter(path, got, sizeof got, err, sizeof err) == 0, err);
        expect(strcmp(got, longer) == 0, "long interpreter readable");
    }

    expect(madelf_set_interpreter(path, "relative/ld.so", err, sizeof err) != 0, "relative path");
    expect(strstr(err, "absolute") != NULL, err);

    unlink(path);
    free(path);
    rmdir(dir);
}

static void test_static_and_multiple(void) {
    char dir[] = "/tmp/madelf-elf2-XXXXXX";
    unsigned char img[256];
    char *path;
    char err[512];
    char got[64];
    if (!mkdtemp(dir)) exit(1);
    memset(img, 0, sizeof img);
    fill_ehdr(img, 1, 0, 0, 0);
    /* PT_LOAD, not PT_INTERP. */
    wr32(img + 64, 1);
    path = write_bytes(dir, "static", img, 64 + 56);
    expect(madelf_read_interpreter(path, got, sizeof got, err, sizeof err) == 1, "static has no interp");
    expect(madelf_set_interpreter(path, "/lib/ld.so", err, sizeof err) != 0, "static cannot be patched");
    expect(strstr(err, "PT_INTERP") != NULL, err);
    unlink(path);
    free(path);

    memset(img, 0, sizeof img);
    fill_ehdr(img, 2, 0, 0, 0);
    fill_interp_ph(img + 64, 64 + 112, 8);
    fill_interp_ph(img + 64 + 56, 64 + 112, 8);
    memcpy(img + 64 + 112, "/ld.so", 6);
    path = write_bytes(dir, "multi", img, 64 + 120);
    expect(madelf_read_interpreter(path, got, sizeof got, err, sizeof err) != 0, "multiple PT_INTERP");
    expect(strstr(err, "multiple") != NULL, err);
    expect(madelf_set_interpreter(path, "/lib/ld.so", err, sizeof err) != 0, "set rejects multiple");
    unlink(path);
    free(path);

    path = write_bytes(dir, "text", (const unsigned char *)"hello", 5);
    expect(madelf_read_interpreter(path, got, sizeof got, err, sizeof err) != 0, "non-elf");
    expect(strstr(err, "not an ELF") != NULL, err);
    unlink(path);
    free(path);
    rmdir(dir);
}

static void test_section_and_detect(void) {
    char dir[] = "/tmp/madelf-elf3-XXXXXX";
    unsigned char img[512];
    const char *interp = "/lib/ld-linux.so.2";
    const char *cfg = "loader=/lib/real-ld.so\nsetenv=A=B\n";
    const char shstr[] = "\0.madelf\0.shstrtab";
    char *path;
    char *text = NULL;
    char err[512];
    char loader[256];
    uint64_t interp_off = 0x78;
    uint64_t cfg_off = 0x90;
    uint64_t str_off = 0xC0;
    uint64_t shoff = 0xE0;
    size_t ilen = strlen(interp) + 1;
    size_t clen = strlen(cfg);
    FILE *side;

    if (!mkdtemp(dir)) exit(1);
    memset(img, 0, sizeof img);
    fill_ehdr(img, 1, shoff, 3, 2);
    fill_interp_ph(img + 64, interp_off, ilen);
    memcpy(img + interp_off, interp, ilen);
    memcpy(img + cfg_off, cfg, clen);
    memcpy(img + str_off, shstr, sizeof shstr);

    /* section 1: .madelf name at 1 */
    wr32(img + shoff + 64, 1);
    wr64(img + shoff + 64 + 24, cfg_off);
    wr64(img + shoff + 64 + 32, clen);
    /* section 2: .shstrtab name at 9 */
    wr32(img + shoff + 128, 9);
    wr32(img + shoff + 128 + 4, 3); /* SHT_STRTAB */
    wr64(img + shoff + 128 + 24, str_off);
    wr64(img + shoff + 128 + 32, sizeof shstr);

    path = write_bytes(dir, "withsec", img, 0xE0 + 64 * 3);
    expect(madelf_read_config_text(path, &text, err, sizeof err) == 0, err);
    expect(text && strcmp(text, cfg) == 0, "embedded config");
    expect(madelf_first_loader(text, loader, sizeof loader) == 0, "loader");
    expect(strcmp(loader, "/lib/real-ld.so") == 0, loader);
    free(text);
    text = NULL;
    expect(madelf_is_madelf_elf(path) == 1, "loader differs from PT_INTERP");

    {
        char sidepath[512];
        snprintf(sidepath, sizeof sidepath, "%s.madelf", path);
        side = fopen(sidepath, "wb");
        expect(side != NULL, "sidecar create");
        if (side) {
            fputs("loader=/lib/ld-linux.so.2\n", side);
            fclose(side);
        }
        expect(madelf_read_config_text(path, &text, err, sizeof err) == 0, "sidecar read");
        expect(text && strncmp(text, "loader=/lib/ld-linux.so.2\n", 24) == 0, "sidecar wins");
        free(text);
        expect(madelf_is_madelf_elf(path) == 0, "same loader is not mad-elf");
        unlink(sidepath);
    }

    expect(madelf_set_interpreter(path, "/tmp/mad-elf-shim", err, sizeof err) == 0, err);
    expect(madelf_is_madelf_elf(path) == 1, "basename mad-elf-shim");

    expect(madelf_first_loader("# c\nloader=#skip\nloader=/real\n", loader, sizeof loader) == 0,
           "first loader");
    expect(strcmp(loader, "/real") == 0, loader);

    unlink(path);
    free(path);
    rmdir(dir);
}

static void test_too_long(void) {
    char dir[] = "/tmp/madelf-elf4-XXXXXX";
    unsigned char img[256];
    char *path;
    char err[512];
    char big[5000];
    size_t i;
    if (!mkdtemp(dir)) exit(1);
    memset(img, 0, sizeof img);
    fill_ehdr(img, 1, 0, 0, 0);
    fill_interp_ph(img + 64, 120, 16);
    memcpy(img + 120, "/lib/ld.so", 10);
    path = write_bytes(dir, "bin", img, 160);
    big[0] = '/';
    for (i = 1; i < sizeof big - 1; i++) big[i] = 'a';
    big[sizeof big - 1] = 0;
    expect(madelf_set_interpreter(path, big, err, sizeof err) != 0, "too long");
    expect(strstr(err, "too long") != NULL, err);
    unlink(path);
    free(path);
    rmdir(dir);
}

int main(void) {
    test_inplace_and_append();
    test_static_and_multiple();
    test_section_and_detect();
    test_too_long();
    if (g_failed) {
        fprintf(stderr, "FAIL: test-elf\n");
        return 1;
    }
    printf("PASS: test-elf\n");
    return 0;
}
