#ifndef MADELF_MACHO_H
#define MADELF_MACHO_H

/* Insert one absolute LC_LOAD_DYLIB into a thin or fat Mach-O, using the
 * unused bytes between the load commands and the first file content.
 * Relative paths and @executable_path / @loader_path / @rpath are rejected. */

#include <stddef.h>

int madelf_validate_dylib_path(const char *path, char *err, size_t errlen);

/* On success (0) *out is a malloc'd array of malloc'd strings, *count set.
 * Caller frees both. */
int madelf_load_dylibs(const char *path, char ***out, int *count,
                       char *err, size_t errlen);

void madelf_free_dylibs(char **list, int count);

/* Idempotent when every slice already loads this exact path.
 * Fails if a slice loads a different libmadelf.dylib, or header slack is short. */
int madelf_inject_load_dylib(const char *path, const char *dylib,
                             char *err, size_t errlen);

/* 1 when some LC_LOAD_DYLIB is absolute and ends with /libmadelf.dylib. */
int madelf_is_madelf_macho(const char *path);

#endif
