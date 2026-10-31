#include "logic.h"

#include <stdio.h>
#include <string.h>

static int failures;

#define CHECK(cond)                                                                 \
    do {                                                                            \
        if (!(cond)) {                                                              \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);         \
            failures++;                                                             \
        }                                                                           \
    } while (0)

static void test_parse_and_edges(void) {
    struct madelf_config cfg;
    char err[128];
    const char *text =
        "# comment\n"
        "\n"
        "loader=/lib64/ld-linux-x86-64.so.2\n"
        "loader=/should-not-override\n"
        "setenv=MADELF_PROFILE=from-shim\n"
        "forceenv=FORCED=yes\n"
        "mergeenv=NODE_OPTIONS=--zero-fill-buffers\n"
        "flag=--no-warnings\n"
        "markerfile=/tmp/first\n"
        "markerfile=/tmp/second\n";
    CHECK(madelf_parse_config(text, &cfg, err, sizeof err) == 0);
    CHECK(strcmp(cfg.loader, "/lib64/ld-linux-x86-64.so.2") == 0);
    CHECK(strcmp(cfg.marker_file, "/tmp/second") == 0);
    CHECK(cfg.nops == 3);
    CHECK(cfg.nflags == 1);
    CHECK(strcmp(cfg.flags[0], "--no-warnings") == 0);
    CHECK(cfg.ops[0].mode == MADELF_ENV_SET_IF_ABSENT);
    CHECK(strcmp(cfg.ops[0].key, "MADELF_PROFILE") == 0);
    CHECK(strcmp(cfg.ops[0].val, "from-shim") == 0);

    CHECK(madelf_parse_config("nope=1\n", &cfg, err, sizeof err) != 0);
    CHECK(madelf_parse_config("flag=\n", &cfg, err, sizeof err) != 0);
    CHECK(madelf_parse_config("setenv=NOEQUALS\n", &cfg, err, sizeof err) != 0);
}

static void test_argv_insert_and_dedup(void) {
    struct madelf_config cfg;
    char err[128];
    char *argv[] = {"node", "script.js", NULL};
    char *already[] = {"node", "--no-warnings", "script.js", NULL};
    char *out[16];
    int n;
    CHECK(madelf_parse_config("flag=--no-warnings\nflag=--no-warnings\n", &cfg, err, sizeof err) == 0);
    n = madelf_build_argv(2, argv, "/lib64/ld-linux-x86-64.so.2", "/usr/bin/node", &cfg, out, 16, err, sizeof err);
    CHECK(n == 6);
    CHECK(strcmp(out[0], "/lib64/ld-linux-x86-64.so.2") == 0);
    CHECK(strcmp(out[1], "--argv0") == 0);
    CHECK(strcmp(out[2], "node") == 0);
    CHECK(strcmp(out[3], "/usr/bin/node") == 0);
    CHECK(strcmp(out[4], "--no-warnings") == 0);
    CHECK(strcmp(out[5], "script.js") == 0);
    CHECK(out[6] == NULL);
    /* second identical flag is not inserted twice */
    CHECK(strcmp(out[5], "script.js") == 0);

    n = madelf_build_argv(3, already, "/lib64/ld-linux-x86-64.so.2", "/usr/bin/node", &cfg, out, 16, err, sizeof err);
    CHECK(n == 6);
    CHECK(strcmp(out[4], "--no-warnings") == 0);
    CHECK(strcmp(out[5], "script.js") == 0);
    /* only one --no-warnings, the one the user already passed */
    CHECK(strcmp(out[4], out[5]) != 0 || strcmp(out[5], "script.js") == 0);
    {
        int count = 0;
        int i;
        for (i = 0; i < n; i++) if (strcmp(out[i], "--no-warnings") == 0) count++;
        CHECK(count == 1);
    }
    CHECK(madelf_flag_present(3, already, "--no-warnings") == 1);
    CHECK(madelf_flag_present(3, already, "--other") == 0);
    /* argv[0] does not count as a flag */
    {
        char *weird[] = {"--no-warnings", "script.js", NULL};
        CHECK(madelf_flag_present(2, weird, "--no-warnings") == 0);
    }
}

static int env_has(char **env, const char *kv) {
    int i;
    for (i = 0; env[i]; i++) if (strcmp(env[i], kv) == 0) return 1;
    return 0;
}

static const char *env_get(char **env, const char *key) {
    size_t n = strlen(key);
    int i;
    for (i = 0; env[i]; i++) {
        if (strncmp(env[i], key, n) == 0 && env[i][n] == '=') return env[i] + n + 1;
    }
    return NULL;
}

static void test_env_rules(void) {
    struct madelf_config cfg;
    char err[128];
    char *base[] = {"MADELF_PROFILE=from-parent", "NODE_OPTIONS=--throw-deprecation", "KEEP=1", NULL};
    char *out[32];
    char arena[8192];
    const char *text =
        "setenv=MADELF_PROFILE=from-shim\n"
        "setenv=NEW=created\n"
        "forceenv=FORCED=yes\n"
        "mergeenv=NODE_OPTIONS=--zero-fill-buffers --throw-deprecation\n"
        "forceenv=MADELF_SHIM=0\n";
    CHECK(madelf_parse_config(text, &cfg, err, sizeof err) == 0);
    CHECK(madelf_build_env(base, &cfg, out, 32, arena, sizeof arena, err, sizeof err) > 0);
    CHECK(strcmp(env_get(out, "MADELF_PROFILE"), "from-parent") == 0);
    CHECK(strcmp(env_get(out, "NEW"), "created") == 0);
    CHECK(strcmp(env_get(out, "FORCED"), "yes") == 0);
    CHECK(strcmp(env_get(out, "KEEP"), "1") == 0);
    CHECK(strcmp(env_get(out, "NODE_OPTIONS"), "--throw-deprecation --zero-fill-buffers") == 0);
    /* marker is forced to 1 even if a directive tried to set something else */
    CHECK(strcmp(env_get(out, "MADELF_SHIM"), "1") == 0);
    CHECK(env_has(out, "MADELF_SHIM=1"));

    {
        char *empty[] = {NULL};
        CHECK(madelf_build_env(empty, NULL, out, 32, arena, sizeof arena, err, sizeof err) == 1);
        CHECK(strcmp(out[0], "MADELF_SHIM=1") == 0);
    }
}

static void test_argv0_preserved_in_layout(void) {
    struct madelf_config cfg;
    char err[64];
    char *argv[] = {"my-node", "-e", "1", NULL};
    char *out[12];
    int n;
    madelf_config_init(&cfg);
    n = madelf_build_argv(3, argv, "/lib64/ld-linux-x86-64.so.2", "/opt/node", &cfg, out, 12, err, sizeof err);
    CHECK(n == 6);
    CHECK(strcmp(out[1], "--argv0") == 0);
    CHECK(strcmp(out[2], "my-node") == 0);
    CHECK(strcmp(out[3], "/opt/node") == 0);
    CHECK(strcmp(out[4], "-e") == 0);
    CHECK(strcmp(out[5], "1") == 0);
}

int main(void) {
    test_parse_and_edges();
    test_argv_insert_and_dedup();
    test_env_rules();
    test_argv0_preserved_in_layout();
    if (failures) {
        fprintf(stderr, "%d logic check(s) failed\n", failures);
        return 1;
    }
    printf("test_logic: ok\n");
    return 0;
}
