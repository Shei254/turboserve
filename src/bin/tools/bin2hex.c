/*
 * bin2hex - convert binary files to hexdump
 * Copyright (c) 2017 L. A. F. Pereira <l@tia.mat.br>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "lwan-private.h"

static int bin2hex_mmap(const char *path, const char *identifier)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;
    char *ptr;
    off_t i;

    if (fd < 0)
        return -errno;

    if (fstat(fd, &st) < 0) {
        close(fd);
        return -errno;
    }

    ptr = mmap(NULL, (size_t)st.st_size, PROT_READ, MAP_PRIVATE, fd, 0);
    close(fd);
    if (ptr == (void *)MAP_FAILED)
        return -errno;

    printf("static const unsigned char %s[] = {\n", identifier);
    printf("    ");

    int bytes_in_this_line = 0;
    for (i = 0; i < st.st_size; i++) {
        printf("0x%02x,", ptr[i] & 0xff);

        bytes_in_this_line++;
        if (bytes_in_this_line == 11) {
            printf("\n    ");
            bytes_in_this_line = 0;
        } else {
            printf(" ");
        }
    }

    printf("\n};\n");

    printf("static const struct lwan_value %s_value = {.value = (char *)%s, .len = "
           "sizeof(%s)};\n",
           identifier, identifier, identifier);

    printf("\n");

    munmap(ptr, (size_t)st.st_size);

    return 0;
}

static int bin2hex_incbin(const char *path, const char *identifier)
{
    printf("__asm__(\".section \\\".rodata\\\"\\n\"\n");
    printf("        \"%s_start:\\n\"\n", identifier);
    printf("        \".incbin \\\"%s\\\"\\n\"\n", path);
    printf("        \"%s_end:\\n\"\n", identifier);
    printf("        \".previous\\n\");\n");
    printf("static struct lwan_value %s_value;\n", identifier);
    printf("__attribute__((visibility(\"internal\"))) extern char %s_start[], %s_end[];\n", identifier, identifier);

    return 0;
}

static int bin2hex(const char *path, const char *identifier)
{
    int r = 0;

    printf("\n/* Contents of %s available through %s_value */\n", path, identifier);

    printf("#if defined(__GNUC__) || defined(__clang__)\n");
    r |= bin2hex_incbin(path, identifier);
    printf("#else\n");
    r |= bin2hex_mmap(path, identifier);
    printf("#endif\n\n");

    return r;
}

int main(int argc, char *argv[])
{
    int arg;

    if (argc < 2) {
        fprintf(stderr, "Usage: %s /path/to/file file_identifier [...]\n",
                argv[0]);
        return 1;
    }

    if ((argc - 1) % 2) {
        fprintf(stderr, "%s: Even number of arguments required\n", argv[0]);
        return 1;
    }

    printf("/* Auto generated by %s, do not edit. */\n", argv[0]);
    printf("#pragma once\n\n");
    printf("#include \"lwan-private.h\"\n");

    for (arg = 1; arg < argc; arg += 2) {
        const char *path = argv[arg];
        const char *identifier = argv[arg + 1];
        int r = bin2hex(path, identifier);

        if (r < 0) {
            fprintf(stderr, "Could not dump %s: %s\n", path, strerror(errno));
            return 1;
        }
    }

    printf("#if defined(__GNUC__) || defined(__clang__)\n");
    printf("LWAN_CONSTRUCTOR(bin2hex_%016lx, 0)\n", (uintptr_t)argv);
    printf("{\n");
    for (arg = 1; arg < argc; arg += 2) {
        const char *identifier = argv[arg + 1];

        printf("    %s_value = (struct lwan_value) {.value = (char *)%s_start, "
               ".len = (size_t)(%s_end - %s_start)};\n",
               identifier, identifier, identifier, identifier);
    }
    printf("}\n");
    printf("#endif\n");

    return 0;
}
