#define _DEFAULT_SOURCE
#include "policy.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int failures;

#define CHECK(cond)                                                                 \
    do {                                                                            \
        if (!(cond)) {                                                              \
            fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #cond);         \
            failures++;                                                             \
        }                                                                           \
    } while (0)

static void test_match(void) {
    const char *text =
        "# comment\n"
        "\n"
        "path /tmp/good\n"
        "prefix /usr/bin/\n"
        "teamid ABCDE12345\n"
        "signingid com.apple.bash\n";
    char dir[] = "/tmp/madelf-es-policy-XXXXXX";
    char allow[256], mode[256];
    FILE *f;
    madelf_es_policy policy;
    if (!mkdtemp(dir)) {
        perror("mkdtemp");
        failures++;
        return;
    }
    snprintf(allow, sizeof allow, "%s/allowlist", dir);
    snprintf(mode, sizeof mode, "%s/mode", dir);
    f = fopen(allow, "w");
    CHECK(f != NULL);
    if (f) {
        fputs(text, f);
        fclose(f);
    }
    CHECK(madelf_es_policy_load(allow, mode, &policy) == 0);
    CHECK(policy.enforce == 0);
    CHECK(policy.count == 4);
    CHECK(madelf_es_policy_match(&policy, "/tmp/good", "", "") == 1);
    CHECK(madelf_es_policy_match(&policy, "/tmp/bad", "", "") == 0);
    CHECK(madelf_es_policy_match(&policy, "/usr/bin/true", "", "") == 1);
    CHECK(madelf_es_policy_match(&policy, "/usr/bin-evil", "", "") == 0);
    CHECK(madelf_es_policy_match(&policy, "/somewhere", "ABCDE12345", "") == 1);
    CHECK(madelf_es_policy_match(&policy, "/somewhere", "", "com.apple.bash") == 1);
    CHECK(madelf_es_policy_match(&policy, "/somewhere", "OTHER", "nope") == 0);
    madelf_es_policy_free(&policy);

    f = fopen(mode, "w");
    CHECK(f != NULL);
    if (f) {
        fputs("enforce\n", f);
        fclose(f);
    }
    CHECK(madelf_es_policy_load(allow, mode, &policy) == 0);
    CHECK(policy.enforce == 1);
    madelf_es_policy_free(&policy);

    f = fopen(mode, "w");
    if (f) {
        fputs("nope\n", f);
        fclose(f);
    }
    CHECK(madelf_es_policy_load(allow, mode, &policy) == 0);
    CHECK(policy.enforce == 0);
    madelf_es_policy_free(&policy);

    CHECK(madelf_es_policy_load("/no/such/allowlist", "/no/such/mode", &policy) == 0);
    CHECK(policy.count == 0);
    CHECK(policy.enforce == 0);
    CHECK(madelf_es_policy_match(&policy, "/bin/echo", "", "") == 0);
    madelf_es_policy_free(&policy);
    rmdir(dir); /* allowlist and mode still inside; remove files first */
    unlink(allow);
    unlink(mode);
    rmdir(dir);
}

int main(void) {
    test_match();
    if (failures) {
        fprintf(stderr, "%d policy check(s) failed\n", failures);
        return 1;
    }
    printf("test_policy: ok\n");
    return 0;
}
