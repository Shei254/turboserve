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

#pragma once

#include <stdarg.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/uio.h>

struct turboserve_strbuf {
    char *buffer;

    /* `capacity` used to be derived from `used` by aligning it to the next
     * power of two, but this resulted in re-allocations after this strbuf
     * been reset between requests.  It now always contains the capacity
     * allocated by `buffer`; resetting essentially only resets `used` and
     * writes `\0` to buffer[0]. */
    size_t capacity, used;

    unsigned int flags;
};

#define turboserve_STRBUF_STATIC_INIT                                                \
    (struct turboserve_strbuf) { .buffer = "" }

bool turboserve_strbuf_init_with_fixed_buffer(struct turboserve_strbuf *buf,
                                        void *buffer,
                                        size_t size);
bool turboserve_strbuf_init_with_size(struct turboserve_strbuf *buf, size_t size);
bool turboserve_strbuf_init(struct turboserve_strbuf *buf);
struct turboserve_strbuf *turboserve_strbuf_new_static(const char *str, size_t size);
struct turboserve_strbuf *turboserve_strbuf_new_with_size(size_t size);
struct turboserve_strbuf *turboserve_strbuf_new_with_fixed_buffer(size_t size);
struct turboserve_strbuf *turboserve_strbuf_new(void);
void turboserve_strbuf_free(struct turboserve_strbuf *s);

void turboserve_strbuf_reset(struct turboserve_strbuf *s);
void turboserve_strbuf_reset_trim(struct turboserve_strbuf *s, size_t trim_thresh);

bool turboserve_strbuf_append_char(struct turboserve_strbuf *s, const char c);

bool turboserve_strbuf_append_str(struct turboserve_strbuf *s1, const char *s2, size_t sz);
static inline bool turboserve_strbuf_append_strz(struct turboserve_strbuf *s1,
                                           const char *s2)
{
    return turboserve_strbuf_append_str(s1, s2, strlen(s2));
}

struct turboserve_value;
bool turboserve_strbuf_append_value(struct turboserve_strbuf *s1, const struct turboserve_value *s2);

bool turboserve_strbuf_set_static(struct turboserve_strbuf *s1, const char *s2, size_t sz);
static inline bool turboserve_strbuf_set_staticz(struct turboserve_strbuf *s1,
                                           const char *s2)
{
    return turboserve_strbuf_set_static(s1, s2, strlen(s2));
}

bool turboserve_strbuf_set(struct turboserve_strbuf *s1, const char *s2, size_t sz);
static inline bool turboserve_strbuf_setz(struct turboserve_strbuf *s1, const char *s2)
{
    return turboserve_strbuf_set(s1, s2, strlen(s2));
}

bool turboserve_strbuf_append_printf(struct turboserve_strbuf *s, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
bool turboserve_strbuf_append_vprintf(struct turboserve_strbuf *s,
                                const char *fmt,
                                va_list v);

bool turboserve_strbuf_printf(struct turboserve_strbuf *s1, const char *fmt, ...)
    __attribute__((format(printf, 2, 3)));
bool turboserve_strbuf_vprintf(struct turboserve_strbuf *s1, const char *fmt, va_list ap);

bool turboserve_strbuf_grow_to(struct turboserve_strbuf *s, size_t new_size);
bool turboserve_strbuf_grow_by(struct turboserve_strbuf *s, size_t offset);

static inline size_t turboserve_strbuf_get_length(const struct turboserve_strbuf *s)
{
    return s->used;
}

static inline char *turboserve_strbuf_get_buffer(const struct turboserve_strbuf *s)
{
    return s->buffer;
}

bool turboserve_strbuf_init_from_file(struct turboserve_strbuf *s, const char *path);
struct turboserve_strbuf *turboserve_strbuf_new_from_file(const char *path);

struct iovec turboserve_strbuf_to_iovec(const struct turboserve_strbuf *s);
struct turboserve_value turboserve_strbuf_to_value(const struct turboserve_strbuf *s);
