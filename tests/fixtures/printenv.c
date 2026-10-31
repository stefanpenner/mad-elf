#include <stdio.h>
#include <stdlib.h>

int main(int argc, char **argv) {
    const char *s;
    int i;
    printf("argv0=%s\n", (argc > 0 && argv[0]) ? argv[0] : "");
    printf("argc=%d\n", argc);
    for (i = 1; i < argc; i++) printf("arg=%s\n", argv[i]);
    s = getenv("MADELF_SHIM");
    printf("SHIM=%s\n", s ? s : "");
    s = getenv("MADELF_PROFILE");
    printf("PROFILE=%s\n", s ? s : "");
    s = getenv("NODE_OPTIONS");
    printf("NODE_OPTIONS=%s\n", s ? s : "");
    fflush(stdout);
    return 0;
}
