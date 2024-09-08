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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#pragma once

#include <stdlib.h>
#include <limits.h>

#include "turboserve.h"

#define N_HEADER_START 64
#define DEFAULT_BUFFER_SIZE 4096
#define DEFAULT_HEADERS_SIZE 2048

struct turboserve_constructor_callback_info {
    void (*func)(struct turboserve *);
    int prio;
};

#define turboserve_CONSTRUCTOR(name_, prio_)                                         \
    __attribute__((no_sanitize_address)) static void turboserve_constructor_##name_( \
        struct turboserve *l __attribute__((unused)));                               \
    static const struct turboserve_constructor_callback_info __attribute__((         \
        used, section(turboserve_SECTION_NAME(                                       \
                  turboserve_constructor)))) turboserve_constructor_info_##name_ = {       \
        .func = turboserve_constructor_##name_,                                      \
        .prio = (prio_),                                                       \
    };                                                                         \
    static ALWAYS_INLINE void turboserve_constructor_##name_(struct turboserve *l)

struct turboserve_request_parser_helper {
    struct turboserve_value *buffer; /* The whole request buffer */
    char *next_request;        /* For pipelined requests */

    struct turboserve_value accept_encoding; /* Accept-Encoding: */

    struct turboserve_value query_string; /* Stuff after ? and before # */

    struct turboserve_value body_data;      /* Request body for POST and PUT */
    struct turboserve_value content_type;   /* Content-Type: for POST and PUT */
    struct turboserve_value content_length; /* Content-Length: */

    struct turboserve_value connection; /* Connection: */

    struct turboserve_value host; /* Host: */

    struct turboserve_key_value_array cookies, query_params, post_params;

    char **header_start;   /* Headers: n: start, n+1: end */
    size_t n_header_start; /* len(header_start) */

    struct { /* If-Modified-Since: */
        struct turboserve_value raw;
        time_t parsed;
    } if_modified_since;

    struct { /* Range: */
        struct turboserve_value raw;
        off_t from, to;
    } range;

    uint64_t request_id; /* Request ID for debugging purposes */

    time_t error_when_time;   /* Time to abort request read */
    int error_when_n_packets; /* Max. number of packets */
    int urls_rewritten;       /* Times URLs have been rewritten */
};


#define turboserve_CONCAT(a_, b_) a_ ## b_
#define turboserve_TMP_ID_DETAIL(n_) turboserve_CONCAT(turboserve_tmp_id, n_)
#define turboserve_TMP_ID turboserve_TMP_ID_DETAIL(__COUNTER__)

#define turboserve_MIN_MAX_DETAIL(a_, b_, name_a_, name_b_, op_)                     \
    ({                                                                         \
        const __typeof__((a_) + 0) name_a_ = (a_);                             \
        const __typeof__((b_) + 0) name_b_ = (b_);                             \
        name_a_ op_ name_b_ ? name_b_ : name_a_;                               \
    })

#define turboserve_MIN(a_, b_) turboserve_MIN_MAX_DETAIL(a_, b_, turboserve_TMP_ID, turboserve_TMP_ID, >)

#define turboserve_MAX(a_, b_) turboserve_MIN_MAX_DETAIL(a_, b_, turboserve_TMP_ID, turboserve_TMP_ID, <)

void turboserve_set_thread_name(const char *name);

void turboserve_response_init(struct turboserve *l);
void turboserve_response_shutdown(struct turboserve *l);

int turboserve_create_listen_socket(const struct turboserve *l,
                              bool print_listening_msg,
                              bool is_https);

void turboserve_thread_init(struct turboserve *l);
void turboserve_thread_shutdown(struct turboserve *l);

void turboserve_status_init(struct turboserve *l);
void turboserve_status_shutdown(struct turboserve *l);

void turboserve_job_thread_init(void);
void turboserve_job_thread_main_loop(void);
void turboserve_job_thread_shutdown(void);
void turboserve_job_add(bool (*cb)(void *data), void *data);
void turboserve_job_del(bool (*cb)(void *data), void *data);

void turboserve_tables_init(void);
void turboserve_tables_shutdown(void);

void turboserve_readahead_init(void);
void turboserve_readahead_shutdown(void);
void turboserve_readahead_queue(int fd, off_t off, size_t size);
void turboserve_madvise_queue(void *addr, size_t size);

char *turboserve_strbuf_extend_unsafe(struct turboserve_strbuf *s, size_t by);
bool turboserve_strbuf_has_grow_buffer_failed_flag(const struct turboserve_strbuf *s);

void turboserve_process_request(struct turboserve *l, struct turboserve_request *request);
size_t turboserve_prepare_response_header_full(struct turboserve_request *request,
     enum turboserve_http_status status, char headers[],
     size_t headers_buf_size, const struct turboserve_key_value *additional_headers);

void turboserve_response(struct turboserve_request *request, enum turboserve_http_status status);
void turboserve_default_response(struct turboserve_request *request,
                           enum turboserve_http_status status);
void turboserve_fill_default_response(struct turboserve_strbuf *buffer,
                                enum turboserve_http_status status);


const char *turboserve_get_config_path(char *path_buf, size_t path_buf_len);

uint8_t turboserve_char_isspace(char ch) __attribute__((pure));
uint8_t turboserve_char_isxdigit(char ch) __attribute__((pure));
uint8_t turboserve_char_isdigit(char ch) __attribute__((pure));
uint8_t turboserve_char_isalpha(char ch) __attribute__((pure));
uint8_t turboserve_char_isalnum(char ch) __attribute__((pure));
uint8_t turboserve_char_iscgiheader(char ch) __attribute__((pure));

static ALWAYS_INLINE __attribute__((pure)) size_t turboserve_nextpow2(size_t number)
{
#if defined(turboserve_HAVE_BUILTIN_CLZLL)
    static const int size_bits = (int)sizeof(number) * CHAR_BIT;

    if (sizeof(size_t) == sizeof(unsigned int)) {
        return (size_t)1 << (size_bits - __builtin_clz((unsigned int)number));
    } else if (sizeof(size_t) == sizeof(unsigned long)) {
        return (size_t)1 << (size_bits - __builtin_clzl((unsigned long)number));
    } else if (sizeof(size_t) == sizeof(unsigned long long)) {
        return (size_t)1 << (size_bits - __builtin_clzll((unsigned long long)number));
    } else {
        (void)size_bits;
    }
#endif

    number--;
    number |= number >> 1;
    number |= number >> 2;
    number |= number >> 4;
    number |= number >> 8;
    number |= number >> 16;
#if __SIZE_WIDTH__ == 64
    number |= number >> 32;
#endif

    return number + 1;
}

#if defined(turboserve_HAVE_MBEDTLS)
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/ssl.h>

struct turboserve_tls_context {
    mbedtls_ssl_config config;
    mbedtls_x509_crt server_cert;
    mbedtls_pk_context server_key;

    mbedtls_entropy_context entropy;

    mbedtls_ctr_drbg_context ctr_drbg;
};
#endif

#ifdef turboserve_HAVE_LUA
#include <lua.h>

lua_State *turboserve_lua_create_state(const char *script_file, const char *script);
void turboserve_lua_state_push_request(lua_State *L, struct turboserve_request *request);
const char *turboserve_lua_state_last_error(lua_State *L);
#endif

/* This macro is used as an attempt to convince the compiler that it should
 * never elide an expression -- for instance, when writing fuzz-test or
 * micro-benchmarks. */
#define turboserve_NO_DISCARD(...)                                                   \
    do {                                                                       \
        __typeof__(__VA_ARGS__) no_discard_ = __VA_ARGS__;                     \
        __asm__ __volatile__("" ::"g"(no_discard_) : "memory");                \
    } while (0)

static inline void turboserve_always_bzero(void *ptr, size_t len)
{
    turboserve_NO_DISCARD(memset(ptr, 0, len));
}

#ifdef __APPLE__
#define SECTION_START(name_) __start_##name_[] __asm("section$start$__DATA$" #name_)
#define SECTION_END(name_)   __stop_##name_[] __asm("section$end$__DATA$" #name_)
#else
#define SECTION_START(name_) __start_##name_[]
#define SECTION_END(name_) __stop_##name_[]
#endif

#define SECTION_START_SYMBOL(section_name_, iter_)                             \
    ({                                                                         \
        extern const typeof(*iter_) SECTION_START(section_name_);              \
        __start_##section_name_;                                               \
    })

#define SECTION_STOP_SYMBOL(section_name_, iter_)                              \
    ({                                                                         \
        extern const typeof(*iter_) SECTION_END(section_name_);                \
        __stop_##section_name_;                                                \
    })

#define turboserve_SECTION_FOREACH(section_name_, iter_)                             \
    for (iter_ = SECTION_START_SYMBOL(section_name_, iter_);                   \
         iter_ < SECTION_STOP_SYMBOL(section_name_, iter_); (iter_)++)

extern clockid_t monotonic_clock_id;

static inline void *
turboserve_aligned_alloc(size_t n, size_t alignment)
{
    void *ret;

    assert((alignment & (alignment - 1)) == 0);
    assert((alignment % (sizeof(void *))) == 0);

    n = (n + alignment - 1) & ~(alignment - 1);
    if (UNLIKELY(posix_memalign(&ret, alignment, n)))
        return NULL;

    return ret;
}

static ALWAYS_INLINE int turboserve_calculate_n_packets(size_t total)
{
    /* 740 = 1480 (a common MTU) / 2, so that turboserve'll optimistically error out
     * after ~2x number of expected packets to fully read the request body.*/
    return turboserve_MAX(5, (int)(total / 740));
}

long int turboserve_getentropy(void *buffer, size_t buffer_len, int flags);
uint64_t turboserve_random_uint64();

const char *turboserve_http_status_as_string(enum turboserve_http_status status)
    __attribute__((const)) __attribute__((warn_unused_result));
const char *turboserve_http_status_as_string_with_code(enum turboserve_http_status status)
    __attribute__((const)) __attribute__((warn_unused_result));
const char *turboserve_http_status_as_descriptive_string(enum turboserve_http_status status)
    __attribute__((const)) __attribute__((warn_unused_result));

static ALWAYS_INLINE __attribute__((pure, warn_unused_result)) int
turboserve_connection_get_fd(const struct turboserve *turboserve,
                       const struct turboserve_connection *conn)
{
    return (int)(intptr_t)(conn - turboserve->conns);
}

int turboserve_format_rfc_time(const time_t in, char out turboserve_ARRAY_PARAM(30));
int turboserve_parse_rfc_time(const char in turboserve_ARRAY_PARAM(30), time_t *out);

void turboserve_straitjacket_enforce_from_config(struct config *c);

uint64_t turboserve_request_get_id(struct turboserve_request *request);

ssize_t turboserve_find_headers(char **header_start, struct turboserve_value *buffer,
                          char **next_request);

sa_family_t turboserve_socket_parse_address(char *listener, char **node, char **port);

void turboserve_request_foreach_header_for_cgi(struct turboserve_request *request,
                                         void (*cb)(const char *header_name,
                                                    size_t header_len,
                                                    const char *value,
                                                    size_t value_len,
                                                    void *user_data),
                                         void *user_data);

bool turboserve_send_websocket_ping_for_tq(struct turboserve_connection *conn);
