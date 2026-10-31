#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int main(int argc, char **argv) {
    const char *marker = getenv("MADELF_MARKER_FILE");
    int i;
    if (marker && marker[0]) {
        int fd = open(marker, O_CREAT | O_WRONLY | O_APPEND, 0644);
        if (fd >= 0) {
            if (write(fd, "main\n", 5) != 5) {
                close(fd);
                return 3;
            }
            close(fd);
        }
    }
    printf("SHIM=%s\n", getenv("MADELF_SHIM") ? getenv("MADELF_SHIM") : "");
    printf("PROFILE=%s\n", getenv("MADELF_PROFILE") ? getenv("MADELF_PROFILE") : "");
    printf("DYLD=%s\n", getenv("DYLD_INSERT_LIBRARIES") ? getenv("DYLD_INSERT_LIBRARIES") : "");
    for (i = 0; i < argc; i++) printf("arg=%s\n", argv[i]);
    fflush(stdout);
    return 0;
}
