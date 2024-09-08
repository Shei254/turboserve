/*
 * turboserve - web server
 * Copyright (c) 2012 L. A. F. Pereira <l@tia.mat.br>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301,
 * USA.
 */

#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/uio.h>
#include <unistd.h>

#include "turboserve-private.h"

static const unsigned int BUFFER_MALLOCD = 1 << 0;
static const unsigned int STRBUF_MALLOCD = 1 << 1;
static const unsigned int BUFFER_FIXED = 1 << 2;
static const unsigned int GROW_BUFFER_FAILED = 1 << 3;

bool turboserve_strbuf_has_grow_buffer_failed_flag(const struct turboserve_strbuf *s)
{
    return s->flags & GROW_BUFFER_FAILED;
}

static inline size_t align_size(size_t unaligned_size)
{
    const size_t aligned_size = turboserve_nextpow2(unaligned_size);

    if (UNLIKELY(unaligned_size >= aligned_size))
        return 0;

    return aligned_size;
}

static ALWAYS_INLINE
bool grow_buffer_if_needed_internal(struct turboserve_strbuf *s, size_t size)
{
    if (s->flags & BUFFER_FIXED)
        return size < s->capacity;

    /* Ensure we always have space for the NUL character! */
    if (UNLIKELY(__builtin_add_overflow(size, 1, &size)))
        return false;

    if (!(s->flags & BUFFER_MALLOCD)) {
        const size_t aligned_size = align_size(turboserve_MAX(size, s->used));
        if (UNLIKELY(!aligned_size))
            return false;

        char *buffer = malloc(aligned_size);
        if (UNLIKELY(!buffer))
            return false;

        memcpy(buffer, s->buffer, s->used);
        buffer[s->used + 1] = '\0';

        s->flags |= BUFFER_MALLOCD;
        s->buffer = buffer;
        s->capacity = aligned_size;

        return true;
    }

    if (UNLIKELY(s->capacity < size)) {
        char *buffer;
        const size_t aligned_size = align_size(size);

        if (UNLIKELY(!aligned_size))
            return false;

        if (s->used == 0) {
            /* Avoid memcpy() inside realloc() if we were not using the
             * allocated buffer at this point.  */
            buffer = malloc(aligned_size);

            if (UNLIKELY(!buffer))
                return false;

            free(s->buffer);
            buffer[0] = '\0';
        } else {
            buffer = realloc(s->buffer, aligned_size);

            if (UNLIKELY(!buffer))
                return false;
        }

        s->buffer = buffer;
        s->capacity = aligned_size;
    }

    return true;
}

static bool grow_buffer_if_needed(struct turboserve_strbuf *s, size_t size)
{
    if (UNLIKELY(!grow_buffer_if_needed_internal(s, size))) {
        s->flags |= GROW_BUFFER_FAILED;
        return false;
    }

    return true;
}

bool turboserve_strbuf_init_with_size(struct turboserve_strbuf *s, size_t size)
{
    if (UNLIKELY(!s))
        return false;

    *s = turboserve_STRBUF_STATIC_INIT;

    if (size) {
        if (UNLIKELY(!grow_buffer_if_needed(s, size)))
            return false;

        s->buffer[0] = '\0';
    }

    return true;
}

bool turboserve_strbuf_init_with_fixed_buffer(struct turboserve_strbuf *s,
                                        void *buffer,
                                        size_t size)
{
    if (UNLIKELY(!s))
        return false;

    *s = (struct turboserve_strbuf) {
        .capacity = size,
        .used = 0,
        .buffer = buffer,
        .flags = BUFFER_FIXED,
    };

    return true;
}

ALWAYS_INLINE bool turboserve_strbuf_init(struct turboserve_strbuf *s)
{
    return turboserve_strbuf_init_with_size(s, 0);
}

struct turboserve_strbuf *turboserve_strbuf_new_with_size(size_t size)
{
    struct turboserve_strbuf *s = malloc(sizeof(*s));

    if (UNLIKELY(!turboserve_strbuf_init_with_size(s, size))) {
        free(s);

        return NULL;
    }

    s->flags |= STRBUF_MALLOCD;

    return s;
}

struct turboserve_strbuf *turboserve_strbuf_new_with_fixed_buffer(size_t size)
{
    struct turboserve_strbuf *s;
    size_t alloc_size;

    if (UNLIKELY(__builtin_add_overflow(sizeof(*s) + 1, size, &alloc_size)))
        return NULL;

    s = malloc(alloc_size);
    if (UNLIKELY(!turboserve_strbuf_init_with_fixed_buffer(s, s + 1, size))) {
        free(s);
        return NULL;
    }

    s->flags |= STRBUF_MALLOCD;

    return s;
}

ALWAYS_INLINE struct turboserve_strbuf *turboserve_strbuf_new(void)
{
    return turboserve_strbuf_new_with_size(0);
}

ALWAYS_INLINE struct turboserve_strbuf *turboserve_strbuf_new_static(const char *str,
                                                         size_t size)
{
    struct turboserve_strbuf *s = malloc(sizeof(*s));

    if (UNLIKELY(!s))
        return NULL;

    *s = (struct turboserve_strbuf) {
        .flags = STRBUF_MALLOCD,
        .buffer = (char *)str,
        .used = size,
        .capacity = size,
    };

    return s;
}

void turboserve_strbuf_free(struct turboserve_strbuf *s)
{
    if (UNLIKELY(!s))
        return;
    if (s->flags & BUFFER_MALLOCD) {
        assert(!(s->flags & BUFFER_FIXED));
        free(s->buffer);
    }
    if (s->flags & STRBUF_MALLOCD)
        free(s);
}

bool turboserve_strbuf_append_char(struct turboserve_strbuf *s, const char c)
{
    size_t grow_size;
    if (UNLIKELY(__builtin_add_overflow(s->used, 1, &grow_size)))
        return false;
    if (UNLIKELY(!grow_buffer_if_needed(s, grow_size)))
        return false;

    s->buffer[s->used++] = c;
    s->buffer[s->used] = '\0';

    return true;
}

bool turboserve_strbuf_append_str(struct turboserve_strbuf *s1, const char *s2, size_t sz)
{
    size_t grow_size;
    if (UNLIKELY(__builtin_add_overflow(s1->used, sz, &grow_size)))
        return false;
    if (UNLIKELY(!grow_buffer_if_needed(s1, grow_size)))
        return false;

    memcpy(s1->buffer + s1->used, s2, sz);
    s1->used += sz;
    s1->buffer[s1->used] = '\0';

    return true;
}

bool turboserve_strbuf_set_static(struct turboserve_strbuf *s1, const char *s2, size_t sz)
{
    if (s1->flags & BUFFER_MALLOCD)
        free(s1->buffer);

    s1->buffer = (char *)s2;
    s1->used = s1->capacity = sz;
    s1->flags &= ~(BUFFER_MALLOCD | BUFFER_FIXED);

    return true;
}

bool turboserve_strbuf_set(struct turboserve_strbuf *s1, const char *s2, size_t sz)
{
    if (UNLIKELY(!grow_buffer_if_needed(s1, sz)))
        return false;

    memcpy(s1->buffer, s2, sz);
    s1->used = sz;
    s1->buffer[sz] = '\0';

    return true;
}

static ALWAYS_INLINE bool
internal_printf(struct turboserve_strbuf *s1,
                bool (*save_str)(struct turboserve_strbuf *, const char *, size_t),
                const char *fmt,
                va_list values)
{
    char *s2;
    int len;

    if (UNLIKELY((len = vasprintf(&s2, fmt, values)) < 0))
        return false;

    bool success = save_str(s1, s2, (size_t)len);
    free(s2);

    return success;
}

bool turboserve_strbuf_vprintf(struct turboserve_strbuf *s, const char *fmt, va_list ap)
{
    return internal_printf(s, turboserve_strbuf_set, fmt, ap);
}

bool turboserve_strbuf_printf(struct turboserve_strbuf *s, const char *fmt, ...)
{
    bool could_printf;
    va_list values;

    va_start(values, fmt);
    could_printf = turboserve_strbuf_vprintf(s, fmt, values);
    va_end(values);

    return could_printf;
}

bool turboserve_strbuf_append_vprintf(struct turboserve_strbuf *s, const char *fmt, va_list ap)
{
    return internal_printf(s, turboserve_strbuf_append_str, fmt, ap);
}

bool turboserve_strbuf_append_printf(struct turboserve_strbuf *s, const char *fmt, ...)
{
    bool could_printf;
    va_list values;

    va_start(values, fmt);
    could_printf = turboserve_strbuf_append_vprintf(s, fmt, values);
    va_end(values);

    return could_printf;
}

bool turboserve_strbuf_grow_to(struct turboserve_strbuf *s, size_t new_size)
{
    return grow_buffer_if_needed(s, new_size);
}

bool turboserve_strbuf_grow_by(struct turboserve_strbuf *s, size_t offset)
{
    size_t new_size;

    if (UNLIKELY(__builtin_add_overflow(offset, s->used, &new_size)))
        return false;

    return turboserve_strbuf_grow_to(s, new_size);
}

void turboserve_strbuf_reset(struct turboserve_strbuf *s)
{
    if (s->flags & BUFFER_MALLOCD) {
        s->buffer[0] = '\0';
    } else {
        s->buffer = "";
        s->capacity = 0;
    }

    s->used = 0;
}

void turboserve_strbuf_reset_trim(struct turboserve_strbuf *s, size_t trim_thresh)
{
    if (s->flags & BUFFER_MALLOCD && s->capacity > trim_thresh) {
        free(s->buffer);
        s->flags &= ~BUFFER_MALLOCD;
    }

    return turboserve_strbuf_reset(s);
}

/* This function is quite dangerous, so the prototype is only in turboserve-private.h */
char *turboserve_strbuf_extend_unsafe(struct turboserve_strbuf *s, size_t by)
{
    if (!turboserve_strbuf_grow_by(s, by))
        return NULL;

    size_t prev_used = s->used;
    s->used += by;

    return s->buffer + prev_used;
}

bool turboserve_strbuf_init_from_file(struct turboserve_strbuf *s, const char *path)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    struct stat st;

    if (UNLIKELY(fd < 0))
        return false;

    if (UNLIKELY(fstat(fd, &st) < 0))
        goto error_close;

    if (UNLIKELY(!turboserve_strbuf_init_with_size(s, (size_t)st.st_size)))
        goto error_close;

    s->used = (size_t)st.st_size;

    for (char *buffer = s->buffer; st.st_size; ) {
        ssize_t n_read = read(fd, buffer, (size_t)st.st_size);

        if (UNLIKELY(n_read < 0)) {
            if (errno == EINTR)
                continue;
            goto error;
        }

        buffer += n_read;
        *buffer = '\0';
        st.st_size -= (off_t)n_read;
    }

    close(fd);
    return true;

error:
    turboserve_strbuf_free(s);
error_close:
    close(fd);
    return false;
}

struct turboserve_strbuf *turboserve_strbuf_new_from_file(const char *path)
{
    struct turboserve_strbuf *strbuf = malloc(sizeof(*strbuf));

    if (!strbuf)
        return NULL;

    if (turboserve_strbuf_init_from_file(strbuf, path)) {
        strbuf->flags |= STRBUF_MALLOCD;
        return strbuf;
    }

    free(strbuf);
    return NULL;
}

struct turboserve_value turboserve_strbuf_to_value(const struct turboserve_strbuf *s)
{
    return (struct turboserve_value){.value = turboserve_strbuf_get_buffer(s),
                               .len = turboserve_strbuf_get_length(s)};
}

struct iovec turboserve_strbuf_to_iovec(const struct turboserve_strbuf *s)
{
    return (struct iovec){.iov_base = turboserve_strbuf_get_buffer(s),
                          .iov_len = turboserve_strbuf_get_length(s)};
}

bool turboserve_strbuf_append_value(struct turboserve_strbuf *s1,
                              const struct turboserve_value *s2)
{
    return turboserve_strbuf_append_str(s1, s2->value, s2->len);
}
