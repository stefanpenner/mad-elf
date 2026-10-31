/* mad-elf-es: edit the allowlist and monitor/enforce switch at runtime.
 * The system extension re-reads these files on every exec. */
#include "policy.h"

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static const char *default_dir = "/Library/Application Support/MadElfES";

static void usage(void) {
    fprintf(stderr,
            "usage: mad-elf-es [--dir DIR] <command>\n"
            "  allow path|prefix|teamid|signingid VALUE\n"
            "  remove path|prefix|teamid|signingid VALUE\n"
            "  list\n"
            "  mode monitor|enforce\n"
            "  status\n"
            "DIR defaults to /Library/Application Support/MadElfES\n"
            "or $MADELF_ES_DIR. mode defaults to monitor, which allows every exec.\n");
}

static int ensure_dir(const char *dir) {
    struct stat st;
    if (stat(dir, &st) == 0) {
        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "mad-elf-es: %s is not a directory\n", dir);
            return -1;
        }
        return 0;
    }
    if (mkdir(dir, 0755) != 0) {
        fprintf(stderr, "mad-elf-es: mkdir %s: %s\n", dir, strerror(errno));
        return -1;
    }
    return 0;
}

static int join(char *out, size_t cap, const char *dir, const char *name) {
    int n = snprintf(out, cap, "%s/%s", dir, name);
    if (n < 0 || (size_t)n >= cap) return -1;
    return 0;
}

static int kind_ok(const char *kind) {
    return strcmp(kind, "path") == 0 || strcmp(kind, "prefix") == 0 ||
           strcmp(kind, "teamid") == 0 || strcmp(kind, "signingid") == 0;
}

static int cmd_allow(const char *dir, const char *kind, const char *value) {
    char path[4096];
    char want[2048];
    FILE *in, *out;
    char line[2048];
    if (!kind_ok(kind) || !value || !value[0]) {
        usage();
        return 1;
    }
    if (ensure_dir(dir) != 0) return 1;
    if (join(path, sizeof path, dir, "allowlist") != 0) return 1;
    if (snprintf(want, sizeof want, "%s %s", kind, value) < 0) return 1;
    in = fopen(path, "r");
    if (in) {
        while (fgets(line, sizeof line, in)) {
            size_t len = strlen(line);
            while (len && (line[len - 1] == '\n' || line[len - 1] == '\r')) line[--len] = 0;
            if (strcmp(line, want) == 0) {
                fclose(in);
                return 0;
            }
        }
        fclose(in);
    }
    out = fopen(path, "a");
    if (!out) {
        fprintf(stderr, "mad-elf-es: %s: %s\n", path, strerror(errno));
        return 1;
    }
    if (fprintf(out, "%s\n", want) < 0) {
        fclose(out);
        return 1;
    }
    fclose(out);
    return 0;
}

static int cmd_remove(const char *dir, const char *kind, const char *value) {
    char path[4096], tmp[4096];
    FILE *in, *out;
    char line[2048];
    char want[2048];
    if (!kind_ok(kind) || !value || !value[0]) {
        usage();
        return 1;
    }
    if (join(path, sizeof path, dir, "allowlist") != 0) return 1;
    if (join(tmp, sizeof tmp, dir, "allowlist.tmp") != 0) return 1;
    snprintf(want, sizeof want, "%s %s", kind, value);
    in = fopen(path, "r");
    if (!in) {
        if (errno == ENOENT) return 0;
        fprintf(stderr, "mad-elf-es: %s: %s\n", path, strerror(errno));
        return 1;
    }
    out = fopen(tmp, "w");
    if (!out) {
        fprintf(stderr, "mad-elf-es: %s: %s\n", tmp, strerror(errno));
        fclose(in);
        return 1;
    }
    while (fgets(line, sizeof line, in)) {
        char copy[2048];
        size_t len;
        snprintf(copy, sizeof copy, "%s", line);
        len = strlen(copy);
        while (len && (copy[len - 1] == '\n' || copy[len - 1] == '\r')) copy[--len] = 0;
        if (strcmp(copy, want) == 0) continue;
        if (fputs(line, out) < 0) {
            fclose(in);
            fclose(out);
            return 1;
        }
    }
    fclose(in);
    if (fclose(out) != 0) return 1;
    if (rename(tmp, path) != 0) {
        fprintf(stderr, "mad-elf-es: rename: %s\n", strerror(errno));
        return 1;
    }
    return 0;
}

static int cmd_list(const char *dir) {
    char path[4096];
    FILE *f;
    char line[2048];
    if (join(path, sizeof path, dir, "allowlist") != 0) return 1;
    f = fopen(path, "r");
    if (!f) {
        if (errno == ENOENT) return 0;
        fprintf(stderr, "mad-elf-es: %s: %s\n", path, strerror(errno));
        return 1;
    }
    while (fgets(line, sizeof line, f)) fputs(line, stdout);
    fclose(f);
    return 0;
}

static int cmd_mode(const char *dir, const char *mode) {
    char path[4096];
    FILE *f;
    if (strcmp(mode, "monitor") != 0 && strcmp(mode, "enforce") != 0) {
        usage();
        return 1;
    }
    if (ensure_dir(dir) != 0) return 1;
    if (join(path, sizeof path, dir, "mode") != 0) return 1;
    f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "mad-elf-es: %s: %s\n", path, strerror(errno));
        return 1;
    }
    fprintf(f, "%s\n", mode);
    fclose(f);
    if (strcmp(mode, "enforce") == 0) {
        fprintf(stderr,
                "mad-elf-es: enforce is on. Execs that do not match the allowlist are denied.\n"
                "A short allowlist will block ordinary programs until you switch back:\n"
                "  mad-elf-es mode monitor\n");
    }
    return 0;
}

static int cmd_status(const char *dir) {
    char allow[4096], mode_path[4096];
    madelf_es_policy policy;
    if (join(allow, sizeof allow, dir, "allowlist") != 0) return 1;
    if (join(mode_path, sizeof mode_path, dir, "mode") != 0) return 1;
    if (madelf_es_policy_load(allow, mode_path, &policy) != 0) {
        fprintf(stderr, "mad-elf-es: failed to read %s\n", dir);
        return 1;
    }
    printf("dir: %s\n", dir);
    printf("mode: %s\n", policy.enforce ? "enforce" : "monitor");
    printf("rules: %zu\n", policy.count);
    madelf_es_policy_free(&policy);
    return cmd_list(dir);
}

int main(int argc, char **argv) {
    const char *dir;
    int i = 1;
    dir = getenv("MADELF_ES_DIR");
    if (!dir || !dir[0]) dir = default_dir;
    if (i < argc && strcmp(argv[i], "--dir") == 0) {
        if (i + 1 >= argc) {
            usage();
            return 1;
        }
        dir = argv[i + 1];
        i += 2;
    }
    if (i >= argc || strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
        usage();
        return i >= argc ? 1 : 0;
    }
    if (strcmp(argv[i], "allow") == 0) {
        if (i + 2 >= argc) {
            usage();
            return 1;
        }
        return cmd_allow(dir, argv[i + 1], argv[i + 2]);
    }
    if (strcmp(argv[i], "remove") == 0) {
        if (i + 2 >= argc) {
            usage();
            return 1;
        }
        return cmd_remove(dir, argv[i + 1], argv[i + 2]);
    }
    if (strcmp(argv[i], "list") == 0) return cmd_list(dir);
    if (strcmp(argv[i], "mode") == 0) {
        if (i + 1 >= argc) {
            usage();
            return 1;
        }
        return cmd_mode(dir, argv[i + 1]);
    }
    if (strcmp(argv[i], "status") == 0) return cmd_status(dir);
    usage();
    return 1;
}
