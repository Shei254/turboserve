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

#if defined(__cplusplus)
extern "C" {
#endif

#include <netinet/in.h>
#include <pthread.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <sys/epoll.h>

#include "hash.h"
#include "timeout.h"
#include "turboserve-array.h"
#include "turboserve-config.h"
#include "turboserve-coro.h"
#include "turboserve-status.h"
#include "turboserve-strbuf.h"
#include "turboserve-trie.h"

#if defined(__cplusplus)
#define ZERO_IF_IS_ARRAY(array) 0
#else
/* This macro expands to 0 if its parameter is an array, and causes a
 * compilation error otherwise.  This is used by the N_ELEMENTS() macro to catch
 * invalid usages of this macro (e.g. when using arrays decayed to pointers) */
#define ZERO_IF_IS_ARRAY(array)                                                \
    (!sizeof(char[1 - 2 * __builtin_types_compatible_p(                        \
                              __typeof__(array), __typeof__(&(array)[0]))]))
#endif

#define N_ELEMENTS(array)                                                      \
    (ZERO_IF_IS_ARRAY(array) | sizeof(array) / sizeof(array[0]))


#ifdef __APPLE__
#define turboserve_SECTION_NAME(name_) "__DATA," #name_
#else
#define turboserve_SECTION_NAME(name_) #name_
#endif

#define turboserve_MODULE_REF(name_) turboserve_module_info_##name_.module
#define turboserve_MODULE_FORWARD_DECL(name_)                                        \
    extern const struct turboserve_module_info turboserve_module_info_##name_;
#define turboserve_REGISTER_MODULE(name_, module_)                                   \
    const struct turboserve_module_info                                              \
        __attribute__((used, section(turboserve_SECTION_NAME(turboserve_module))))         \
            turboserve_module_info_##name_ = {.name = #name_, .module = module_}

#define turboserve_HANDLER_REF(name_) turboserve_handler_##name_

#define turboserve_HANDLER_ROUTE(name_, route_)                                      \
    static enum turboserve_http_status turboserve_handler_##name_(                         \
        struct turboserve_request *, struct turboserve_response *, void *);                \
    static const struct turboserve_handler_info                                      \
        __attribute__((used, section(turboserve_SECTION_NAME(turboserve_handler))))        \
        __attribute__((aligned(8))) /* FIXME: why is this alignment needed? */ \
        turboserve_handler_info_##name_ = {                                          \
            .name = #name_,                                                    \
            .route = route_,                                                   \
            .handler = turboserve_handler_##name_,                                   \
    };                                                                         \
    __attribute__((used)) static enum turboserve_http_status turboserve_handler_##name_(   \
        struct turboserve_request *request __attribute__((unused)),                  \
        struct turboserve_response *response __attribute__((unused)),                \
        void *data __attribute__((unused)))
#define turboserve_HANDLER(name_) turboserve_HANDLER_ROUTE(name_, NULL)

#define ALWAYS_INLINE inline __attribute__((always_inline))

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#define STR4_INT(a, b, c, d) ((uint32_t)((a) | (b) << 8 | (c) << 16 | (d) << 24))
#define STR2_INT(a, b) ((uint16_t)((a) | (b) << 8))
#define STR8_INT(a, b, c, d, e, f, g, h)                                       \
    ((uint64_t)STR4_INT(a, b, c, d) | (uint64_t)STR4_INT(e, f, g, h) << 32)
#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
#define STR4_INT(d, c, b, a) ((uint32_t)((a) | (b) << 8 | (c) << 16 | (d) << 24))
#define STR2_INT(b, a) ((uint16_t)((a) | (b) << 8))
#define STR8_INT(a, b, c, d, e, f, g, h)                                       \
    ((uint64_t)STR4_INT(a, b, c, d) << 32 | (uint64_t)STR4_INT(e, f, g, h))
#elif __BYTE_ORDER__ == __ORDER_PDP_ENDIAN__
#error A PDP? Seriously?
#endif

static ALWAYS_INLINE uint16_t string_as_uint16(const char *s)
{
    uint16_t u;

    memcpy(&u, s, sizeof(u));

    return u;
}

static ALWAYS_INLINE uint32_t string_as_uint32(const char *s)
{
    uint32_t u;

    memcpy(&u, s, sizeof(u));

    return u;
}

static ALWAYS_INLINE uint64_t string_as_uint64(const char *s)
{
    uint64_t u;

    memcpy(&u, s, sizeof(u));

    return u;
}

#define LOWER2(s) ((s) | (uint16_t)0x2020)
#define LOWER4(s) ((s) | (uint32_t)0x20202020)
#define LOWER8(s) ((s) | (uint64_t)0x2020202020202020)

#define STR2_INT_L(a, b) LOWER2(STR2_INT(a, b))
#define STR4_INT_L(a, b, c, d) LOWER4(STR4_INT(a, b, c, d))
#define STR8_INT_L(a, b, c, d, e, f, g, h) LOWER8(STR8_INT(a, b, c, d, e, f, g, h))

#define STRING_SWITCH_SMALL(s) switch (string_as_uint16(s))
#define STRING_SWITCH_SMALL_L(s) switch (LOWER2(string_as_uint16(s)))
#define STRING_SWITCH(s) switch (string_as_uint32(s))
#define STRING_SWITCH_L(s) switch (LOWER4(string_as_uint32(s)))
#define STRING_SWITCH_LARGE(s) switch (string_as_uint64(s))
#define STRING_SWITCH_LARGE_L(s) switch (LOWER8(string_as_uint64(s)))

#define LIKELY_IS(x, y) __builtin_expect((x), (y))
#define LIKELY(x) LIKELY_IS(!!(x), 1)
#define UNLIKELY(x) LIKELY_IS((x), 0)

#define ATOMIC_READ(V) (*(volatile typeof(V) *)&(V))
#define ATOMIC_OP(P, O, V) (__sync_##O##_and_fetch((P), (V)))
#define ATOMIC_AAF(P, V) ATOMIC_OP((P), add, (V))
#define ATOMIC_SAF(P, V) ATOMIC_OP((P), sub, (V))
#define ATOMIC_INC(V) ATOMIC_AAF(&(V), 1)
#define ATOMIC_DEC(V) ATOMIC_SAF(&(V), 1)

#if defined(__cplusplus)
#define turboserve_ARRAY_PARAM(length) [length]
#else
#define turboserve_ARRAY_PARAM(length) [static length]
#endif

#include "turboserve-http-status.h"

#define GENERATE_ENUM_ITEM(id, code, short, long) HTTP_ ## id = code,
enum turboserve_http_status {
    HTTP_CLASS__INFORMATIONAL = 100,
    HTTP_CLASS__SUCCESS = 200,
    HTTP_CLASS__REDIRECT = 300,
    HTTP_CLASS__CLIENT_ERROR = 400,
    HTTP_CLASS__SERVER_ERROR = 500,

    FOR_EACH_HTTP_STATUS(GENERATE_ENUM_ITEM)
};
#undef GENERATE_ENUM_ITEM

enum turboserve_handler_flags {
    HANDLER_EXPECTS_BODY_DATA = 1 << 0,
    HANDLER_MUST_AUTHORIZE = 1 << 1,
    HANDLER_CAN_REWRITE_URL = 1 << 2,
    HANDLER_DATA_IS_HASH_TABLE = 1 << 3,

    HANDLER_PARSE_MASK = HANDLER_EXPECTS_BODY_DATA,
};

/* 1<<0 set: response has body; see has_response_body() in turboserve-response.c */
/* 1<<3 set: request has body; see request_has_body() in turboserve-request.c */
#define FOR_EACH_REQUEST_METHOD(X)                                                \
    X(GET, get, (1 << 0), (STR4_INT('G', 'E', 'T', ' ')), 0.6)                    \
    X(POST, post, (1 << 3 | 1 << 1 | 1 << 0), (STR4_INT('P', 'O', 'S', 'T')), 0.2)\
    X(HEAD, head, (1 << 1), (STR4_INT('H', 'E', 'A', 'D')), 0.2)                  \
    X(OPTIONS, options, (1 << 2), (STR4_INT('O', 'P', 'T', 'I')), 0.1)            \
    X(DELETE, delete, (1 << 1 | 1 << 2), (STR4_INT('D', 'E', 'L', 'E')), 0.1)     \
    X(PUT, put, (1 << 3 | 1 << 2 | 1 << 0), (STR4_INT('P', 'U', 'T', ' ')), 0.1)

#define SELECT_MASK(upper, lower, mask, constant, probability) mask |
#define GENERATE_ENUM_ITEM(upper, lower, mask, constant, probability) REQUEST_METHOD_##upper = mask,

enum turboserve_request_flags {
    REQUEST_ALL_FLAGS = -1,

    REQUEST_METHOD_MASK = FOR_EACH_REQUEST_METHOD(SELECT_MASK) 0,
    FOR_EACH_REQUEST_METHOD(GENERATE_ENUM_ITEM)

    REQUEST_ACCEPT_DEFLATE = 1 << 4,
    REQUEST_ACCEPT_GZIP = 1 << 5,
    REQUEST_ACCEPT_BROTLI = 1 << 6,
    REQUEST_ACCEPT_ZSTD = 1 << 7,
    REQUEST_ACCEPT_MASK = 1 << 4 | 1 << 5 | 1 << 6 | 1 << 7,

    REQUEST_IS_HTTP_1_0 = 1 << 8,
    REQUEST_ALLOW_PROXY_REQS = 1 << 9,
    REQUEST_PROXIED = 1 << 10,
    REQUEST_ALLOW_CORS = 1 << 11,

    RESPONSE_SENT_HEADERS = 1 << 12,
    RESPONSE_CHUNKED_ENCODING = 1 << 13,
    RESPONSE_NO_CONTENT_LENGTH = 1 << 14,
    RESPONSE_NO_EXPIRES = 1 << 15,
    RESPONSE_URL_REWRITTEN = 1 << 16,

    RESPONSE_STREAM = 1 << 17,

    REQUEST_PARSED_QUERY_STRING = 1 << 18,
    REQUEST_PARSED_IF_MODIFIED_SINCE = 1 << 19,
    REQUEST_PARSED_RANGE = 1 << 20,
    REQUEST_PARSED_FORM_DATA = 1 << 21,
    REQUEST_PARSED_COOKIES = 1 << 22,
    REQUEST_PARSED_ACCEPT_ENCODING = 1 << 23,

    RESPONSE_INCLUDE_REQUEST_ID = 1 << 24,

    REQUEST_HAS_QUERY_STRING = 1 << 25,

    REQUEST_WANTS_HSTS_HEADER = 1 << 26,
};

#undef SELECT_MASK
#undef GENERATE_ENUM_ITEM

#define CONN_EPOLL_EVENT_SHIFT 16
#define CONN_EPOLL_EVENT_MASK ((1 << CONN_EPOLL_EVENT_SHIFT) - 1)

enum turboserve_connection_flags {
    CONN_MASK = -1,

    /* Upper 16-bit of CONN_EVENTS_* store the epoll event interest
     * mask for those events.  */
    CONN_EVENTS_READ = ((EPOLLIN | EPOLLRDHUP) << CONN_EPOLL_EVENT_SHIFT) | 1 << 0,
    CONN_EVENTS_WRITE = ((EPOLLOUT | EPOLLRDHUP) << CONN_EPOLL_EVENT_SHIFT) | 1 << 1,
    CONN_EVENTS_READ_WRITE = CONN_EVENTS_READ | CONN_EVENTS_WRITE,
    CONN_EVENTS_MASK = 1 << 0 | 1 << 1,

    CONN_IS_KEEP_ALIVE = 1 << 2,

    /* WebSockets-related flags. */
    CONN_IS_UPGRADE = 1 << 3,
    CONN_IS_WEBSOCKET = 1 << 4,

    /* These are used for a few different things:
     * - Avoid re-deferring callbacks to remove request from the timeout wheel
     *   after it has slept previously and is requesting to sleep again. (The
     *   timeout defer is disarmed right after resuming, and is only there
     * because connections may be closed when they're suspended.)
     * - Distinguish file descriptor in event loop between the connection and
     *   an awaited file descriptor.  (This is set in the connection that's
     *   awaiting since the pointer to the connection is used as user_data in both
     *   cases. This is required to be able to resume the connection coroutine
     *   after the await is completed, and to bubble up errors in awaited file
     *   descriptors to request handlers rather than abruptly closing the
     *   connection.) */
    CONN_SUSPENDED_MASK = 1 << 5,
    CONN_SUSPENDED = (EPOLLRDHUP << CONN_EPOLL_EVENT_SHIFT) | CONN_SUSPENDED_MASK,
    CONN_HAS_REMOVE_SLEEP_DEFER = 1 << 6,

    /* Used when HTTP pipelining has been detected.  This enables usage of the
     * MSG_MORE flags when sending responses to batch as many short responses
     * as possible in a single TCP fragment. */
    CONN_CORK = 1 << 7,

    /* Set only on file descriptors being watched by async/await to determine
     * which epoll operation to use when suspending/resuming (ADD/MOD). Reset
     * whenever associated client connection is closed. */
    CONN_ASYNC_AWAIT = 1 << 8,

    /* Used to both implement turboserve_request_awaitv_all() correctly, and to
     * ensure that spurious resumes from fds that weren't in the multiple
     * await call won't return to the request handler.  */
    CONN_ASYNC_AWAITV = 1 << 9,

    CONN_SENT_CONNECTION_HEADER = 1 << 10,

    /* Is this a TLS connection? */
    CONN_TLS = 1 << 11,

    /* Both are used to know if an epoll event pertains to a listener rather
     * than a client.  */
    CONN_LISTENER = 1 << 12,

    /* Only valid when CONN_ASYNC_AWAIT is set. Set on file descriptors that
     * got (EPOLLHUP|EPOLLRDHUP) events from epoll so that request handlers
     * can deal with this fact.  */
    CONN_HUNG_UP = 1 << 13,

    CONN_FLAG_LAST = CONN_HUNG_UP,
};

static_assert(CONN_FLAG_LAST < ((1 << 15) - 1),
              "Enough space for epoll events in conn flags");

enum turboserve_connection_coro_yield {
    /* Returns to the event loop and terminates the coroutine, freeing
     * all resources associated with it, including calling deferred
     * callback, and the coroutine itself. */
    CONN_CORO_ABORT,

    /* Return to the event loop without changing the epoll event mask
     * or any other flag in this coroutine. */
    CONN_CORO_YIELD,

    /* Returns to the event loop, and optionally change the epoll event
     * mask (if it's not already the expected one.) */
    CONN_CORO_WANT_READ,
    CONN_CORO_WANT_WRITE,
    CONN_CORO_WANT_READ_WRITE,

    /* If a connection coroutine yields with CONN_CORO_SUSPEND, then
     * it'll be resumed using CONN_CORO_RESUME from the event loop.
     * CONN_CORO_RESUME should never be used from within connections
     * themselves, and should be considered a private API. */
    CONN_CORO_SUSPEND,
    CONN_CORO_RESUME,

    CONN_CORO_MAX,
};

struct turboserve_key_value {
    char *key;
    char *value;
};

struct turboserve_request;

struct turboserve_response {
    struct turboserve_strbuf *buffer;
    const char *mime_type;

    union {
        struct {
            const struct turboserve_key_value *headers;
        };

        struct {
            enum turboserve_http_status (*callback)(struct turboserve_request *request,
                                              void *data);
            void *data;
        } stream;
    };
};

struct turboserve_value {
    char *value;
    size_t len;
};

struct turboserve_connection {
    /* This structure is exactly 32-bytes on x86-64. If it is changed,
     * make sure the scheduler (turboserve-thread.c) is updated as well. */
    enum turboserve_connection_flags flags;

    unsigned int time_to_expire;

    struct coro *coro;
    struct turboserve_thread *thread;

    /* This union is here to support async/await when a handler is waiting
     * on multiple file descriptors.  By storing a pointer to the parent
     * connection here, we're able to register the awaited file descriptor
     * in epoll using a pointer to the awaited file descriptor struct,
     * allowing us to yield to the handler this information and signal which
     * file descriptor caused the handler to be awoken.  (We can yield just
     * the file descriptor plus another integer with values to signal things
     * like timeouts and whatnot.  Future problems!)
     *
     * Also, when CONN_ASYNC_AWAIT is set, `coro` points to parent->coro,
     * so that conn->coro is consistently usable.  Gotta be careful though,
     * because struct coros are not refcounted and this could explode with
     * a double free. */
    union {
        /* For HTTP client connections handling inside the timeout queue */
        struct {
            int prev;
            int next;
        };

        /* For awaited file descriptor, only valid if flags&CONN_ASYNC_AWAIT */
        struct turboserve_connection *parent;
    };
};

struct turboserve_proxy {
    union {
        struct sockaddr_in ipv4;
        struct sockaddr_in6 ipv6;
    } from, to;
};

DEFINE_ARRAY_TYPE(turboserve_key_value_array, struct turboserve_key_value)

struct turboserve_request_parser_helper;

struct turboserve_request {
    enum turboserve_request_flags flags;
    int fd;
    struct turboserve_connection *conn;
    const struct turboserve_value *const global_response_headers;

    struct turboserve_request_parser_helper *helper;

    struct turboserve_value url;
    struct turboserve_value original_url;
    struct turboserve_response response;

    struct turboserve_proxy *proxy;
    struct timeout timeout;
};

struct turboserve_module {
    enum turboserve_http_status (*handle_request)(struct turboserve_request *request,
                                            struct turboserve_response *response,
                                            void *instance);

    void *(*create)(const char *prefix, void *args);
    void *(*create_from_hash)(const char *prefix, const struct hash *hash);
    void (*destroy)(void *instance);

    bool (*parse_conf)(void *instance, struct config *config);

    enum turboserve_handler_flags flags;
};

struct turboserve_module_info {
    const char *name;
    const struct turboserve_module *module;
};

struct turboserve_url_map_route_info {
    const char *route;
    enum turboserve_http_status (*handler)(struct turboserve_request *request,
                                     struct turboserve_response *response,
                                     void *data);
};

struct turboserve_handler_info {
    const char *name;
    enum turboserve_http_status (*handler)(struct turboserve_request *request,
                                     struct turboserve_response *response,
                                     void *data);
    const char *route;
};

struct turboserve_url_map {
    enum turboserve_http_status (*handler)(struct turboserve_request *request,
                                     struct turboserve_response *response,
                                     void *data);
    void *data;

    const char *prefix;
    size_t prefix_len;
    enum turboserve_handler_flags flags;

    const struct turboserve_module *module;
    void *args;

    struct {
        char *realm;
        char *password_file;
    } authorization;
};

struct turboserve_thread {
    struct turboserve *turboserve;
    struct {
        char date[30];
        char expires[30];
    } date;
    int epoll_fd;
    struct timeouts *wheel;
    int listen_fd;
    int tls_listen_fd;
    unsigned int cpu;
    pthread_t self;
};

struct turboserve_straitjacket {
    const char *user_name;
    const char *chroot_path;
    bool drop_capabilities;
};

struct turboserve_config {
    /* Field will be overridden during initialization. */
    enum turboserve_request_flags request_flags;
    struct turboserve_key_value *global_headers;

    char *listener;
    char *tls_listener;
    char *error_template;
    char *config_file_path;

    struct {
        char *cert;
        char *key;
        bool send_hsts_header;
    } ssl;

    size_t max_post_data_size;
    size_t max_put_data_size;
    size_t request_buffer_size;

    unsigned int keep_alive_timeout;
    unsigned int expires;
    unsigned int n_threads;
    unsigned int max_file_descriptors;

    unsigned int quiet : 1;
    unsigned int proxy_protocol : 1;
    unsigned int allow_cors : 1;
    unsigned int allow_post_temp_file : 1;
    unsigned int allow_put_temp_file : 1;
};

struct turboserve {
    struct turboserve_trie url_map_trie;
    struct turboserve_connection *conns;
    struct turboserve_value headers;

#if defined(turboserve_HAVE_MBEDTLS)
    struct turboserve_tls_context *tls;
#endif

    struct {
        struct turboserve_thread *threads;

        unsigned int max_fd;
        unsigned int count;
        pthread_barrier_t barrier;
    } thread;

    struct turboserve_config config;

    unsigned int online_cpus;
    unsigned int available_cpus;
};

void turboserve_set_url_map(struct turboserve *l, const struct turboserve_url_map *map);
void turboserve_detect_url_map(struct turboserve *l);
void turboserve_main_loop(struct turboserve *l);

size_t turboserve_prepare_response_header(struct turboserve_request *request,
                                    enum turboserve_http_status status,
                                    char header_buffer[],
                                    size_t header_buffer_size)
    __attribute__((warn_unused_result));

const char *turboserve_request_get_post_param(struct turboserve_request *request,
                                        const char *key)
    __attribute__((warn_unused_result, pure));
const char *turboserve_request_get_query_param(struct turboserve_request *request,
                                         const char *key)
    __attribute__((warn_unused_result, pure));
const char *turboserve_request_get_cookie(struct turboserve_request *request,
                                    const char *key)
    __attribute__((warn_unused_result, pure));
const char *turboserve_request_get_header(struct turboserve_request *request,
                                    const char *header)
    __attribute__((warn_unused_result));

void turboserve_request_sleep(struct turboserve_request *request, uint64_t ms);

bool turboserve_response_set_chunked(struct turboserve_request *request,
                               enum turboserve_http_status status);
bool turboserve_response_set_chunked_full(struct turboserve_request *request,
                                    enum turboserve_http_status status,
                                    const struct turboserve_key_value *additional_headers);
void turboserve_response_send_chunk(struct turboserve_request *request);
void turboserve_response_send_chunk_full(struct turboserve_request *request,
                                   struct turboserve_strbuf *strbuf);

bool turboserve_response_set_event_stream(struct turboserve_request *request,
                                    enum turboserve_http_status status);
void turboserve_response_send_event(struct turboserve_request *request, const char *event);

const char *turboserve_determine_mime_type_for_file_name(const char *file_name)
    __attribute__((pure)) __attribute__((warn_unused_result));

void turboserve_init(struct turboserve *l);
void turboserve_init_with_config(struct turboserve *l, const struct turboserve_config *config);
void turboserve_shutdown(struct turboserve *l);

static inline int turboserve_main(void)
{
    struct turboserve l;

    turboserve_init(&l);

    turboserve_detect_url_map(&l);
    turboserve_main_loop(&l);

    turboserve_shutdown(&l);

    return 0;
}

const struct turboserve_config *turboserve_get_default_config(void);

const char *turboserve_request_get_host(struct turboserve_request *request);

const char *
turboserve_request_get_remote_address(const struct turboserve_request *request,
                                char buffer turboserve_ARRAY_PARAM(INET6_ADDRSTRLEN))
    __attribute__((warn_unused_result));

const char *turboserve_request_get_remote_address_and_port(
    const struct turboserve_request *request,
    char buffer turboserve_ARRAY_PARAM(INET6_ADDRSTRLEN), uint16_t *port)
    __attribute__((warn_unused_result));

static inline enum turboserve_request_flags
turboserve_request_get_method(const struct turboserve_request *request)
{
    return (enum turboserve_request_flags)(request->flags & REQUEST_METHOD_MASK);
}
const char *turboserve_request_get_method_str(const struct turboserve_request *request);

int turboserve_request_get_range(struct turboserve_request *request,
                           off_t *from,
                           off_t *to);
int turboserve_request_get_if_modified_since(struct turboserve_request *request,
                                       time_t *value);
const struct turboserve_value *
turboserve_request_get_request_body(struct turboserve_request *request);
const struct turboserve_value *
turboserve_request_get_content_type(struct turboserve_request *request);
const struct turboserve_key_value_array *
turboserve_request_get_cookies(struct turboserve_request *request);
const struct turboserve_key_value_array *
turboserve_request_get_query_params(struct turboserve_request *request);
const struct turboserve_key_value_array *
turboserve_request_get_post_params(struct turboserve_request *request);
enum turboserve_request_flags
turboserve_request_get_accept_encoding(struct turboserve_request *request);

enum turboserve_http_status
turboserve_request_websocket_upgrade(struct turboserve_request *request);
void turboserve_response_websocket_write_text(struct turboserve_request *request);
void turboserve_response_websocket_write_binary(struct turboserve_request *request);
int turboserve_response_websocket_read(struct turboserve_request *request);
int turboserve_response_websocket_read_hint(struct turboserve_request *request, size_t size_hint);

int turboserve_request_await_read(struct turboserve_request *r, int fd);
int turboserve_request_await_write(struct turboserve_request *r, int fd);
int turboserve_request_await_read_write(struct turboserve_request *r, int fd);
int turboserve_request_awaitv_any(struct turboserve_request *r, ...);
int turboserve_request_awaitv_all(struct turboserve_request *r, ...);

void turboserve_straitjacket_enforce(const struct turboserve_straitjacket *sj);

#if defined(__cplusplus)
}
#endif
