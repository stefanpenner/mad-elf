#ifndef MADELF_ELF_H
#define MADELF_ELF_H

/* ELF64 little-endian helpers used by the mad-elf install/inspect CLI.
 * PT_INTERP is rewritten in place when the new path fits. Otherwise the
 * path is appended and the existing PT_INTERP program header is retargeted
 * (p_offset / p_filesz / p_memsz). A second PT_INTERP header is not added. */

#include <stddef.h>

/* 0: path written to out (no trailing NUL from the file).
 * 1: ELF has no PT_INTERP (out is empty).
 * -1: error message in err. */
int madelf_read_interpreter(const char *path, char *out, size_t outcap,
                            char *err, size_t errlen);

/* Point PT_INTERP at an absolute interpreter path. */
int madelf_set_interpreter(const char *path, const char *interp,
                           char *err, size_t errlen);

/* Sidecar <path>.madelf wins over an embedded .madelf section.
 * On success (0) *out is malloc'd and NUL-terminated. Caller frees it.
 * 1: no config. -1: error. */
int madelf_read_config_text(const char *path, char **out,
                            char *err, size_t errlen);

/* Add or replace a .madelf section via objcopy. */
int madelf_embed_config_section(const char *path, const char *text,
                                char *err, size_t errlen);

/* Copy the first loader= value into out. 0 found, 1 absent.
 * A line "loader=#" is ignored, matching the historical CLI. */
int madelf_first_loader(const char *text, char *out, size_t outcap);

/* 1 when PT_INTERP is mad-elf-shim, or the recorded loader differs from it. */
int madelf_is_madelf_elf(const char *path);

#endif
