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

#include "turboserve-coro.h"
#include "turboserve-strbuf.h"
#include <stddef.h>

enum turboserve_tpl_flag { turboserve_TPL_FLAG_CONST_TEMPLATE = 1 << 0 };

struct turboserve_var_descriptor {
    const char *name;
    const off_t offset;
    const struct turboserve_var_descriptor *list_desc;

    union {
        struct {
            void (*append_to_strbuf)(struct turboserve_strbuf *buf, void *ptr);
            bool (*get_is_empty)(void *ptr);
        };
        struct {
            coro_function_t generator;
        };
        struct {
            void (*lambda)(struct turboserve_strbuf *buf, void *ptr);
        };
    };
};

#define TPL_LAMBDA(var_, lambda_)                                              \
    {                                                                          \
        .name = #var_, .offset = 0x1aabdacb, .lambda = lambda_,                \
        /* 0x1aabdacb = lambda call back */                                    \
    }

#define TPL_VAR_SIMPLE(var_, append_to_turboserve_strbuf_, get_is_empty_)            \
    {                                                                          \
        .name = #var_, .offset = offsetof(TPL_STRUCT, var_),                   \
        .append_to_strbuf = append_to_turboserve_strbuf_,                            \
        .get_is_empty = get_is_empty_                                          \
    }

#define TPL_VAR_SEQUENCE(var_, generator_, seqitem_desc_)                      \
    {                                                                          \
        .name = #var_, .offset = offsetof(TPL_STRUCT, var_.generator),         \
        .generator = generator_, .list_desc = seqitem_desc_                    \
    }

#define TPL_VAR_INT(var_)                                                      \
    TPL_VAR_SIMPLE(var_, turboserve_append_int_to_strbuf, turboserve_tpl_int_is_empty)

#define TPL_VAR_DOUBLE(var_)                                                   \
    TPL_VAR_SIMPLE(var_, turboserve_append_double_to_strbuf, turboserve_tpl_double_is_empty)

#define TPL_VAR_STR(var_)                                                      \
    TPL_VAR_SIMPLE(var_, turboserve_append_str_to_strbuf, turboserve_tpl_str_is_empty)

#define TPL_VAR_STR_ESCAPE(var_)                                               \
    TPL_VAR_SIMPLE(var_, turboserve_append_str_escaped_to_strbuf,                    \
                   turboserve_tpl_str_is_empty)

#define TPL_VAR_SENTINEL                                                       \
    {                                                                          \
        .name = NULL, .offset = 0,                                             \
    }

/*
 * These functions are not meant to be used directly. We do need a pointer to
 * them, though, that's why they're exported. Eventually this will move to
 * something more opaque.
 */
void turboserve_append_int_to_strbuf(struct turboserve_strbuf *buf, void *ptr);
bool turboserve_tpl_int_is_empty(void *ptr);
void turboserve_append_str_to_strbuf(struct turboserve_strbuf *buf, void *ptr);
void turboserve_append_str_escaped_to_strbuf(struct turboserve_strbuf *buf, void *ptr);
bool turboserve_tpl_str_is_empty(void *ptr);
void turboserve_append_double_to_strbuf(struct turboserve_strbuf *buf, void *ptr);
bool turboserve_tpl_double_is_empty(void *ptr);

struct turboserve_tpl *
turboserve_tpl_compile_value_full(struct turboserve_value value,
                            const struct turboserve_var_descriptor *descriptor,
                            enum turboserve_tpl_flag flags);
static inline struct turboserve_tpl *
turboserve_tpl_compile_string_full(const char *string,
                             const struct turboserve_var_descriptor *descriptor,
                             enum turboserve_tpl_flag flags)
{
    struct turboserve_value value = {.value = (char *)string, .len = strlen(string)};
    return turboserve_tpl_compile_value_full(value, descriptor, flags);
}

struct turboserve_tpl *
turboserve_tpl_compile_string(const char *string,
                        const struct turboserve_var_descriptor *descriptor);
struct turboserve_tpl *
turboserve_tpl_compile_file(const char *filename,
                      const struct turboserve_var_descriptor *descriptor);
struct turboserve_strbuf *turboserve_tpl_apply(struct turboserve_tpl *tpl, void *variables);
bool turboserve_tpl_apply_with_buffer(struct turboserve_tpl *tpl,
                                struct turboserve_strbuf *buf,
                                void *variables);
void turboserve_tpl_free(struct turboserve_tpl *tpl);
