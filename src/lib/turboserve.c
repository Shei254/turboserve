/*
 * turboserve - web server
 * Copyright (c) 2012, 2013 L. A. F. Pereira <l@tia.mat.br>
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
#include <assert.h>
#include <ctype.h>
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <libproc.h>
#include <limits.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

#include "turboserve-private.h"

#include "turboserve-config.h"
#include "turboserve-http-authorize.h"

#if defined(turboserve_HAVE_LUA)
#include "turboserve-lua.h"
#endif

/* Ideally, this would check if all items in enum turboserve_request_flags,
 * when bitwise-or'd together, would not have have any bit set that
 * is also set in REQUEST_METHOD_MASK. */
static_assert(REQUEST_ACCEPT_DEFLATE > REQUEST_METHOD_MASK,
              "enough bits to store request methods");

/* See detect_fastest_monotonic_clock() */
clockid_t monotonic_clock_id = CLOCK_MONOTONIC;

static const struct turboserve_config default_config = {
    .listener = "localhost:8080",
    .keep_alive_timeout = 15,
    .quiet = false,
    .proxy_protocol = false,
    .allow_cors = false,
    .expires = 1 * ONE_WEEK,
    .n_threads = 0,
    .request_buffer_size = DEFAULT_BUFFER_SIZE,
    .max_post_data_size = 10 * DEFAULT_BUFFER_SIZE,
    .allow_post_temp_file = false,
    .max_put_data_size = 10 * DEFAULT_BUFFER_SIZE,
    .allow_put_temp_file = false,
    .max_file_descriptors = 524288,
};

turboserve_HANDLER_ROUTE(brew_coffee, NULL /* do not autodetect this route */)
{
    /* Placeholder handler so that __start_turboserve_handler and __stop_turboserve_handler
     * symbols will get defined.
     */
    return HTTP_I_AM_A_TEAPOT;
}

__attribute__((no_sanitize_address))
static void *find_handler(const char *name)
{
    const struct turboserve_handler_info *handler;

    turboserve_SECTION_FOREACH(turboserve_handler, handler) {
        if (streq(handler->name, name))
            return handler->handler;
    }

    return NULL;
}

__attribute__((no_sanitize_address))
static const struct turboserve_module *find_module(const char *name)
{
    const struct turboserve_module_info *module;

    turboserve_SECTION_FOREACH(turboserve_module, module) {
        if (streq(module->name, name))
            return module->module;
    }

    return NULL;
}

static void destroy_urlmap(void *data)
{
    struct turboserve_url_map *url_map = data;

    if (url_map->module) {
        const struct turboserve_module *module = url_map->module;

        if (module->destroy)
            module->destroy(url_map->data);
    } else if (url_map->data && url_map->flags & HANDLER_DATA_IS_HASH_TABLE) {
        hash_unref(url_map->data);
    }

    free(url_map->authorization.realm);
    free(url_map->authorization.password_file);
    free((char *)url_map->prefix);
    free(url_map);
}

static struct turboserve_url_map *add_url_map(struct turboserve_trie *t, const char *prefix,
                                        const struct turboserve_url_map *map)
{
    struct turboserve_url_map *copy = malloc(sizeof(*copy));

    if (!copy)
        turboserve_status_critical_perror("Could not copy URL map");

    memcpy(copy, map, sizeof(*copy));

    copy->prefix = strdup(prefix ? prefix : copy->prefix);
    if (!copy->prefix)
        turboserve_status_critical_perror("Could not copy URL prefix");

    copy->prefix_len = strlen(copy->prefix);
    turboserve_trie_add(t, copy->prefix, copy);

    return copy;
}

static bool can_override_header(const char *name)
{
    /* NOTE: Update turboserve_prepare_response_header_full() in turboserve-response.c
     *       if new headers are added here. */

    if (strcaseequal_neutral(name, "Date"))
        return false;
    if (strcaseequal_neutral(name, "Expires"))
        return false;
    if (strcaseequal_neutral(name, "WWW-Authenticate"))
        return false;
    if (strcaseequal_neutral(name, "Connection"))
        return false;
    if (strcaseequal_neutral(name, "Content-Type"))
        return false;
    if (strcaseequal_neutral(name, "Transfer-Encoding"))
        return false;
    if (strcaseequal_neutral_len(name, "Access-Control-Allow-",
                     sizeof("Access-Control-Allow-") - 1))
        return false;

    return true;
}

static void build_response_headers(struct turboserve *l,
                                   const struct turboserve_key_value *kv)
{
    struct turboserve_strbuf strbuf;
    bool set_server = false;

    assert(l);

    turboserve_strbuf_init(&strbuf);

    for (; kv && kv->key; kv++) {
        if (!can_override_header(kv->key)) {
            turboserve_status_warning("Cannot override header '%s'", kv->key);
        } else {
            if (strcaseequal_neutral(kv->key, "Server"))
                set_server = true;

            turboserve_strbuf_append_printf(&strbuf, "\r\n%s: %s", kv->key,
                                      kv->value);
        }
    }

    if (!set_server)
        turboserve_strbuf_append_strz(&strbuf, "\r\nServer: turboserve");

    turboserve_strbuf_append_strz(&strbuf, "\r\n\r\n");

    l->headers = turboserve_strbuf_to_value(&strbuf);
}

static void parse_global_headers(struct config *c,
                                 struct turboserve *turboserve)
{
    struct turboserve_key_value_array hdrs;
    const struct config_line *l;
    struct turboserve_key_value *kv;

    turboserve_key_value_array_init(&hdrs);

    while ((l = config_read_line(c))) {
        switch (l->type) {
        case CONFIG_LINE_TYPE_SECTION:
            config_error(
                c, "No sections are supported under the 'headers' section");
            goto cleanup;

        case CONFIG_LINE_TYPE_LINE:
            kv = turboserve_key_value_array_append(&hdrs);
            if (!kv) {
                turboserve_status_critical_perror(
                    "Could not allocate memory for custom response header");
            }

            kv->key = strdup(l->key);
            if (!kv->key) {
                turboserve_status_critical_perror(
                    "Could not allocate memory for custom response header");
            }

            kv->value = strdup(l->value);
            if (!kv->value) {
                turboserve_status_critical_perror(
                    "Could not allocate memory for custom response header");
            }
            break;

        case CONFIG_LINE_TYPE_SECTION_END:
            kv = turboserve_key_value_array_append(&hdrs);
            if (!kv) {
                turboserve_status_critical_perror(
                    "Could not allocate memory for custom response header");
            }

            kv->key = NULL;
            kv->value = NULL;

            build_response_headers(turboserve, turboserve_key_value_array_get_array(&hdrs));
            goto cleanup;
        }
    }

    config_error(c, "EOF while looking for end of 'headers' section");

cleanup:
    turboserve_ARRAY_FOREACH (&hdrs, kv) {
        free(kv->key);
        free(kv->value);
    }
    turboserve_key_value_array_reset(&hdrs);
}

static void parse_listener_prefix_authorization(struct config *c,
                                                const struct config_line *l,
                                                struct turboserve_url_map *url_map)
{
    if (!streq(l->value, "basic")) {
        config_error(c, "Only basic authorization supported");
        return;
    }

    memset(&url_map->authorization, 0, sizeof(url_map->authorization));

    while ((l = config_read_line(c))) {
        switch (l->type) {
        case CONFIG_LINE_TYPE_LINE:
            if (streq(l->key, "realm")) {
                free(url_map->authorization.realm);
                url_map->authorization.realm = strdup(l->value);
            } else if (streq(l->key, "password_file")) {
                free(url_map->authorization.password_file);
                url_map->authorization.password_file = realpath(l->value, NULL);
                if (!url_map->authorization.password_file)
                    config_error(c, "Could not determine full path for password file: %s", l->value);
            }
            break;

        case CONFIG_LINE_TYPE_SECTION:
            config_error(c, "Unexpected section: %s", l->key);
            goto error;

        case CONFIG_LINE_TYPE_SECTION_END:
            if (!url_map->authorization.realm)
                url_map->authorization.realm = strdup("turboserve");
            if (!url_map->authorization.password_file)
                url_map->authorization.password_file = strdup("htpasswd");

            url_map->flags |= HANDLER_MUST_AUTHORIZE;
            return;
        }
    }

    config_error(c, "Could not find end of authorization section");

error:
    free(url_map->authorization.realm);
    free(url_map->authorization.password_file);
}

__attribute__((no_sanitize_address))
static const char *get_module_name(const struct turboserve_module *module)
{
    const struct turboserve_module_info *iter;

    turboserve_SECTION_FOREACH(turboserve_module, iter) {
        if (iter->module == module)
            return iter->name;
    }

    return "<unknown>";
}

static void parse_listener_prefix(struct config *c,
                                  const struct config_line *l,
                                  struct turboserve *turboserve,
                                  const struct turboserve_module *module,
                                  void *handler)
{
    struct turboserve_url_map url_map = {};
    struct hash *hash = hash_str_new(free, free);
    char *prefix = strdupa(l->value);
    struct config *isolated;

    if (!hash)
        turboserve_status_critical("Could not allocate hash table");

    isolated = config_isolate_section(c, l);
    if (!isolated) {
        config_error(c, "Could not isolate configuration file");
        goto out;
    }

    while ((l = config_read_line(c))) {
        switch (l->type) {
        case CONFIG_LINE_TYPE_LINE: {
            char *key_copy = strdup(l->key);
            char *value_copy = strdup(l->value);

            if (!key_copy)
                turboserve_status_critical("Could not copy key from config file");
            if (!value_copy)
                turboserve_status_critical("Could not copy value from config file");

            hash_add(hash, key_copy, value_copy);
            break;
        }

        case CONFIG_LINE_TYPE_SECTION:
            if (streq(l->key, "authorization")) {
                parse_listener_prefix_authorization(c, l, &url_map);
            } else if (!config_skip_section(c, l)) {
                config_error(c, "Could not skip section");
                goto out;
            }
            break;

        case CONFIG_LINE_TYPE_SECTION_END:
            goto add_map;
        }
    }

    config_error(c, "Expecting section end while parsing prefix");
    goto out;

add_map:
    assert((handler && !module) || (!handler && module));

    if (handler) {
        url_map.handler = handler;
        url_map.flags |= HANDLER_PARSE_MASK | HANDLER_DATA_IS_HASH_TABLE;
        url_map.data = hash;
        url_map.module = NULL;

        hash = NULL;
    } else if (module->create_from_hash && module->handle_request) {
        turboserve_status_debug("Initializing module %s from config",
                          get_module_name(module));

        url_map.data = module->create_from_hash(prefix, hash);
        if (!url_map.data) {
            config_error(c, "Could not create module instance");
            goto out;
        }

        if (module->parse_conf && !module->parse_conf(url_map.data, isolated)) {
            const char *msg = config_last_error(isolated);

            config_error(c, "Error from module: %s", msg ? msg : "Unknown");
            goto out;
        }

        url_map.handler = module->handle_request;
        url_map.flags |= module->flags;
        url_map.module = module;
    } else if (UNLIKELY(!module->create_from_hash)) {
        config_error(c, "Module isn't prepared to load settings from a file; "
                        "create_from_hash() method isn't present");
        goto out;
    } else if (UNLIKELY(!module->handle_request)) {
        config_error(c, "Module does not have handle_request() method");
        goto out;
    }

    add_url_map(&turboserve->url_map_trie, prefix, &url_map);

out:
    hash_unref(hash);
    config_close(isolated);
}

static void register_url_map(struct turboserve *l, const struct turboserve_url_map *map)
{
    struct turboserve_url_map *copy = add_url_map(&l->url_map_trie, NULL, map);

    if (copy->module && copy->module->create) {
        turboserve_status_debug("Initializing module %s from struct",
                          get_module_name(copy->module));

        copy->data = copy->module->create(map->prefix, copy->args);
        if (!copy->data) {
            turboserve_status_critical("Could not initialize module %s",
                                 get_module_name(copy->module));
        }

        copy->flags = copy->module->flags;
        copy->handler = copy->module->handle_request;
    } else {
        copy->flags = HANDLER_PARSE_MASK;
    }
}

void turboserve_set_url_map(struct turboserve *l, const struct turboserve_url_map *map)
{
    turboserve_trie_destroy(&l->url_map_trie);
    if (UNLIKELY(!turboserve_trie_init(&l->url_map_trie, destroy_urlmap)))
        turboserve_status_critical_perror("Could not initialize trie");

    for (; map->prefix; map++)
        register_url_map(l, map);
}

__attribute__((no_sanitize_address))
void turboserve_detect_url_map(struct turboserve *l)
{
    const struct turboserve_handler_info *iter;

    turboserve_trie_destroy(&l->url_map_trie);
    if (UNLIKELY(!turboserve_trie_init(&l->url_map_trie, destroy_urlmap)))
        turboserve_status_critical_perror("Could not initialize trie");

    turboserve_SECTION_FOREACH(turboserve_handler, iter) {
        if (!iter->route)
            continue;

        turboserve_status_debug("Using handler `%s' for route `%s'",
                          iter->name, iter->route);

        const struct turboserve_url_map map = {.prefix = iter->route,
                                         .handler = iter->handler,
                                         .flags = HANDLER_PARSE_MASK};
        register_url_map(l, &map);
    }
}

const char *turboserve_get_config_path(char *path_buf, size_t path_buf_len)
{
    char buffer[PATH_MAX];

    if (proc_pidpath(getpid(), buffer, sizeof(buffer)) < 0)
        goto out;

    char *path = strrchr(buffer, '/');
    if (!path)
        goto out;
    int ret = snprintf(path_buf, path_buf_len, "%s.conf", path + 1);
    if (ret < 0 || ret >= (int)path_buf_len)
        goto out;

    return path_buf;

out:
    return "turboserve.conf";
}

static void parse_tls_listener(struct config *conf, const struct config_line *line, struct turboserve *turboserve)
{
#if !defined(turboserve_HAVE_MBEDTLS)
    config_error(conf, "turboserve has been built without mbedTLS support");
    return;
#endif

    turboserve->config.tls_listener = strdup(line->value);
    if (!turboserve->config.tls_listener) {
        config_error(conf, "Could not allocate memory for tls_listener");
        return;
    }

    turboserve->config.ssl.cert = NULL;
    turboserve->config.ssl.key = NULL;

    while ((line = config_read_line(conf))) {
        switch (line->type) {
        case CONFIG_LINE_TYPE_SECTION_END:
            if (!turboserve->config.ssl.cert)
                config_error(conf, "Missing path to certificate");
            if (!turboserve->config.ssl.key)
                config_error(conf, "Missing path to private key");
            return;
        case CONFIG_LINE_TYPE_SECTION:
            config_error(conf, "Unexpected section: %s", line->key);
            return;
        case CONFIG_LINE_TYPE_LINE:
            if (streq(line->key, "cert")) {
                free(turboserve->config.ssl.cert);
                turboserve->config.ssl.cert = strdup(line->value);
                if (!turboserve->config.ssl.cert)
                    return turboserve_status_critical("Could not copy string");
            } else if (streq(line->key, "key")) {
                free(turboserve->config.ssl.key);
                turboserve->config.ssl.key = strdup(line->value);
                if (!turboserve->config.ssl.key)
                    return turboserve_status_critical("Could not copy string");
            } else if (streq(line->key, "hsts")) {
                turboserve->config.ssl.send_hsts_header = parse_bool(line->value, false);
            } else {
                config_error(conf, "Unexpected key: %s", line->key);
            }
        }
    }

    config_error(conf, "Expecting section end while parsing SSL configuration");
}

static void
parse_listener(struct config *c, const struct config_line *l, struct turboserve *turboserve)
{
    turboserve->config.listener = strdup(l->value);
    if (!turboserve->config.listener)
        config_error(c, "Could not allocate memory for listener");

    while ((l = config_read_line(c))) {
        switch (l->type) {
        case CONFIG_LINE_TYPE_LINE:
            config_error(c, "Unexpected key %s", l->key);
            return;
        case CONFIG_LINE_TYPE_SECTION:
            config_error(c, "Unexpected section %s", l->key);
            return;
        case CONFIG_LINE_TYPE_SECTION_END:
            return;
        }
    }

    config_error(c, "Unexpected EOF while parsing listener");
}

static void
parse_site(struct config *c, const struct config_line *l, struct turboserve *turboserve)
{
    while ((l = config_read_line(c))) {
        switch (l->type) {
        case CONFIG_LINE_TYPE_LINE:
            config_error(c, "Expecting prefix section");
            return;
        case CONFIG_LINE_TYPE_SECTION:
            /* FIXME: per-site authorization? */

            if (l->key[0] == '&') {
                void *handler = find_handler(l->key + 1);
                if (handler) {
                    parse_listener_prefix(c, l, turboserve, NULL, handler);
                    continue;
                }

                config_error(c, "Could not find handler name: %s", l->key + 1);
                return;
            }

            const struct turboserve_module *module = find_module(l->key);
            if (module) {
                parse_listener_prefix(c, l, turboserve, module, NULL);
                continue;
            }

            config_error(c, "Invalid section or module not found: %s", l->key);
            return;
        case CONFIG_LINE_TYPE_SECTION_END:
            return;
        }
    }

    config_error(c, "Expecting section end while parsing listener");
}

static bool setup_from_config(struct turboserve *turboserve, const char *path)
{
    const struct config_line *line;
    struct config *conf;
    bool has_site = false;
    bool has_listener = false;
    bool has_tls_listener = false;
    char path_buf[PATH_MAX];

    if (!path)
        path = turboserve_get_config_path(path_buf, sizeof(path_buf));
    turboserve_status_info("Loading configuration file: %s", path);

    conf = config_open(path);
    if (!conf)
        return false;

    if (!turboserve_trie_init(&turboserve->url_map_trie, destroy_urlmap))
        return false;

    while ((line = config_read_line(conf))) {
        switch (line->type) {
        case CONFIG_LINE_TYPE_LINE:
            if (streq(line->key, "keep_alive_timeout")) {
                turboserve->config.keep_alive_timeout = (unsigned int)parse_long(
                    line->value, default_config.keep_alive_timeout);
            } else if (streq(line->key, "quiet")) {
                turboserve->config.quiet =
                    parse_bool(line->value, default_config.quiet);
            } else if (streq(line->key, "proxy_protocol")) {
                turboserve->config.proxy_protocol =
                    parse_bool(line->value, default_config.proxy_protocol);
            } else if (streq(line->key, "allow_cors")) {
                turboserve->config.allow_cors =
                    parse_bool(line->value, default_config.allow_cors);
            } else if (streq(line->key, "expires")) {
                turboserve->config.expires =
                    parse_time_period(line->value, default_config.expires);
            } else if (streq(line->key, "error_template")) {
                free(turboserve->config.error_template);
                turboserve->config.error_template = strdup(line->value);
            } else if (streq(line->key, "threads")) {
                long n_threads =
                    parse_long(line->value, default_config.n_threads);
                if (n_threads < 0)
                    config_error(conf, "Invalid number of threads: %ld",
                                 n_threads);
                turboserve->config.n_threads = (unsigned int)n_threads;
            } else if (streq(line->key, "request_buffer_size")) {
                long request_buffer_size = parse_long(
                    line->value, (long)default_config.request_buffer_size);

                if (request_buffer_size > 16 * (1 << 20)) {
                    config_error(conf,
                                 "Request buffer can't be over 16MiB");
                } else if (request_buffer_size < DEFAULT_BUFFER_SIZE) {
                    turboserve_status_warning("Using request buffer size of %d bytes instead of the "
                                        "requested %ld bytes",
                                        DEFAULT_BUFFER_SIZE,
                                        request_buffer_size);

                    request_buffer_size = DEFAULT_BUFFER_SIZE;
                }

                turboserve->config.request_buffer_size = (size_t)request_buffer_size;
            } else if (streq(line->key, "max_file_descriptors")) {
                long max_file_descriptors = parse_long(
                    line->value, (long)default_config.max_file_descriptors);

                if (max_file_descriptors < 0) {
                    config_error(conf, "Maximum number of file descriptors can't be negative");
                } else if (max_file_descriptors > 2000000l) {
                    config_error(conf, "2M file descriptors should be sufficient!");
                } else if (max_file_descriptors == 0) {
                    max_file_descriptors = default_config.max_file_descriptors;
                }

                turboserve->config.max_file_descriptors = (unsigned int)max_file_descriptors;
            } else if (streq(line->key, "max_post_data_size")) {
                long max_post_data_size = parse_long(
                    line->value, (long)default_config.max_post_data_size);

                if (max_post_data_size < 0) {
                    config_error(conf, "Negative maximum post data size");
                } else if (max_post_data_size > 128 * (1 << 20)) {
                    config_error(conf,
                                 "Maximum post data can't be over 128MiB");
                }

                turboserve->config.max_post_data_size = (size_t)max_post_data_size;
            } else if (streq(line->key, "max_put_data_size")) {
                long max_put_data_size = parse_long(
                    line->value, (long)default_config.max_put_data_size);

                if (max_put_data_size < 0) {
                    config_error(conf, "Negative maximum put data size");
                } else if (max_put_data_size > 128 * (1 << 20)) {
                    config_error(conf,
                                 "Maximum put data can't be over 128MiB");
                }
                turboserve->config.max_put_data_size = (size_t)max_put_data_size;
            } else if (streq(line->key, "allow_temp_files")) {
                bool has_post, has_put;

                if (strstr(line->value, "all")) {
                    has_post = has_put = true;
                } else {
                    has_post = !!strstr(line->value, "post");
                    has_put = !!strstr(line->value, "put");
                }

                turboserve->config.allow_post_temp_file = has_post;
                turboserve->config.allow_put_temp_file = has_put;
            } else {
                config_error(conf, "Unknown config key: %s", line->key);
            }
            break;
        case CONFIG_LINE_TYPE_SECTION:
            if (streq(line->key, "site")) {
                if (!has_site) {
                    parse_site(conf, line, turboserve);
                    has_site = true;
                } else {
                    config_error(conf, "Only one site may be configured");
                }
            } else if (streq(line->key, "straitjacket") || streq(line->key, "straightjacket")) {
                turboserve_straitjacket_enforce_from_config(conf);
            } else if (streq(line->key, "headers")) {
                parse_global_headers(conf, turboserve);
            } else if (streq(line->key, "listener")) {
                if (has_listener) {
                    config_error(conf, "Listener already set up");
                } else {
                    parse_listener(conf, line, turboserve);
                    has_listener = true;
                }
            } else if (streq(line->key, "tls_listener")) {
                if (has_tls_listener) {
                    config_error(conf, "TLS Listener already set up");
                } else {
                    parse_tls_listener(conf, line, turboserve);
                    has_tls_listener = true;
                }
            } else {
                config_error(conf, "Unknown section type: %s", line->key);
            }
            break;
        case CONFIG_LINE_TYPE_SECTION_END:
            config_error(conf, "Unexpected section end");
        }
    }

    if (config_last_error(conf)) {
        turboserve_status_critical("Error on config file \"%s\", line %d: %s", path,
                             config_cur_line(conf), config_last_error(conf));
        turboserve_trie_destroy(&turboserve->url_map_trie);
    }

    config_close(conf);

    return true;
}

static void try_setup_from_config(struct turboserve *l,
                                  const struct turboserve_config *config)
{
    if (!setup_from_config(l, config->config_file_path)) {
        if (config->config_file_path) {
            turboserve_status_critical("Could not read config file: %s",
                                 config->config_file_path);
        }
    }

    turboserve_status_init(l); /* `quiet` key might have changed value. */

    l->config.request_flags =
        (l->config.proxy_protocol ? REQUEST_ALLOW_PROXY_REQS : 0) |
        (l->config.allow_cors ? REQUEST_ALLOW_CORS : 0) |
        (l->config.ssl.send_hsts_header ? REQUEST_WANTS_HSTS_HEADER : 0);
}

static rlim_t setup_open_file_count_limits(struct turboserve *l)
{
    struct rlimit r;

    if (getrlimit(RLIMIT_NOFILE, &r) < 0) {
        turboserve_status_perror("Could not obtain maximum number of file "
                           "descriptors. Assuming %d",
                           OPEN_MAX);
        return OPEN_MAX;
    }

    if (r.rlim_max != r.rlim_cur) {
        const rlim_t current = r.rlim_cur;

        if (r.rlim_max == RLIM_INFINITY && r.rlim_cur < OPEN_MAX) {
            r.rlim_cur = OPEN_MAX;
        } else if (r.rlim_cur < r.rlim_max) {
            r.rlim_cur = r.rlim_max;
        } else {
            /* Shouldn't happen, so just return the current value. */
            goto out;
        }

        r.rlim_cur = turboserve_MIN(l->config.max_file_descriptors,
                              r.rlim_cur);

        if (setrlimit(RLIMIT_NOFILE, &r) < 0) {
            turboserve_status_perror("Could not raise maximum number of file "
                               "descriptors to %" PRIu64 ". Leaving at "
                               "%" PRIu64, r.rlim_max, current);
            r.rlim_cur = current;
        }
    }

out:
    if (r.rlim_cur < 10 * l->thread.count) {
        turboserve_status_critical("Number of file descriptors (%ld) is smaller than 10x "
                             "the number of threads (%d)\n",
                             r.rlim_cur,
                             10 * l->thread.count);
    }

    return r.rlim_cur;
}

static void allocate_connections(struct turboserve *l, size_t max_open_files)
{
    const size_t sz = max_open_files * sizeof(struct turboserve_connection);

    l->conns = turboserve_aligned_alloc(sz, 64);
    if (UNLIKELY(!l->conns))
        turboserve_status_critical_perror("turboserve_alloc_aligned");

    memset(l->conns, 0, sz);
}

static void get_number_of_cpus(struct turboserve *l)
{
    long n_online_cpus = sysconf(_SC_NPROCESSORS_ONLN);
    long n_available_cpus = sysconf(_SC_NPROCESSORS_CONF);

    if (n_online_cpus < 0) {
        turboserve_status_warning(
            "Could not get number of online CPUs, assuming 1 CPU");
        n_online_cpus = 1;
    }

    if (n_available_cpus < 0) {
        turboserve_status_warning(
            "Could not get number of available CPUs, assuming %ld CPUs",
            n_online_cpus);
        n_available_cpus = n_online_cpus;
    }

    l->online_cpus = (unsigned int)n_online_cpus;
    l->available_cpus = (unsigned int)n_available_cpus;
}

void turboserve_init(struct turboserve *l) { turboserve_init_with_config(l, &default_config); }

const struct turboserve_config *turboserve_get_default_config(void)
{
    return &default_config;
}

static char *dup_or_null(const char *s)
{
    return s ? strdup(s) : NULL;
}

DEFINE_ARRAY_TYPE(constructor_array, struct turboserve_constructor_callback_info)

static int constructor_sort(const void *a, const void *b)
{
    const struct turboserve_constructor_callback_info *ca = a;
    const struct turboserve_constructor_callback_info *cb = b;
    return (ca->prio < cb->prio) - (ca->prio > cb->prio);
}

__attribute__((no_sanitize_address)) static void
call_constructors(struct turboserve *l)
{
    struct constructor_array constructors;
    const struct turboserve_constructor_callback_info *iter;

    constructor_array_init(&constructors);
    turboserve_SECTION_FOREACH(turboserve_constructor, iter)
    {
        struct turboserve_constructor_callback_info *info =
            constructor_array_append(&constructors);
        if (!info)
            turboserve_status_critical("Could not append to constructor array");
        *info = *iter;
    }
    constructor_array_sort(&constructors, constructor_sort);

    turboserve_ARRAY_FOREACH (&constructors, iter) {
        iter->func(l);
    }

    constructor_array_reset(&constructors);
}

void turboserve_init_with_config(struct turboserve *l, const struct turboserve_config *config)
{
    /* Load defaults */
    memset(l, 0, sizeof(*l));
    memcpy(&l->config, config, sizeof(*config));
    l->config.listener = dup_or_null(l->config.listener);
    l->config.config_file_path = dup_or_null(l->config.config_file_path);
    l->config.ssl.key = dup_or_null(l->config.ssl.key);
    l->config.ssl.cert = dup_or_null(l->config.ssl.cert);

    /* Initialize status first, as it is used by other things during
     * their initialization. */
    turboserve_status_init(l);

    call_constructors(l);

    /* These will only print debugging messages. Debug messages are always
     * printed if we're on a debug build, so the quiet setting will be
     * respected. */
    turboserve_job_thread_init();
    turboserve_tables_init();

    /* Get the number of CPUs here because straightjacket might be active
     * and this will block access to /proc and /sys, which will cause
     * get_number_of_cpus() to get incorrect fallback values. */
    get_number_of_cpus(l);

    try_setup_from_config(l, config);

    if (!l->headers.len)
        build_response_headers(l, config->global_headers);

    turboserve_response_init(l);

    /* Continue initialization as normal. */
    turboserve_status_debug("Initializing turboserve web server");

    if (!l->config.n_threads) {
        l->thread.count = l->online_cpus;
        if (l->thread.count == 1)
            l->thread.count = 2;
    } else if (l->config.n_threads > 3 * l->online_cpus) {
        l->thread.count = l->online_cpus * 3;

        turboserve_status_warning("%d threads requested, but only %d online CPUs "
                            "(out of %d configured CPUs); capping to %d threads",
                            l->config.n_threads, l->online_cpus, l->available_cpus,
                            3 * l->online_cpus);
    } else if (l->config.n_threads > 255) {
        l->thread.count = 256;

        turboserve_status_warning("%d threads requested, but max 256 supported",
            l->config.n_threads);
    } else {
        l->thread.count = l->config.n_threads;
    }

    rlim_t max_open_files = setup_open_file_count_limits(l);
    allocate_connections(l, (size_t)max_open_files);

    l->thread.max_fd = (unsigned)max_open_files / (unsigned)l->thread.count;
    turboserve_status_info("Using %d threads, maximum %d sockets per thread",
                     l->thread.count, l->thread.max_fd);

    signal(SIGPIPE, SIG_IGN);

    turboserve_readahead_init();
    turboserve_thread_init(l);
    turboserve_http_authorize_init();
}

void turboserve_shutdown(struct turboserve *l)
{
    turboserve_status_info("Shutting down");

    free(l->config.listener);
    free(l->config.error_template);
    free(l->config.config_file_path);

    turboserve_always_bzero(l->config.ssl.cert, strlen(l->config.ssl.cert));
    free(l->config.ssl.cert);
    turboserve_always_bzero(l->config.ssl.key, strlen(l->config.ssl.key));
    free(l->config.ssl.key);

    turboserve_job_thread_shutdown();
    turboserve_thread_shutdown(l);

    turboserve_status_debug("Shutting down URL handlers");
    turboserve_trie_destroy(&l->url_map_trie);

    free(l->headers.value);
    free(l->conns);

    turboserve_response_shutdown(l);
    turboserve_tables_shutdown();
    turboserve_status_shutdown(l);
    turboserve_http_authorize_shutdown();
    turboserve_readahead_shutdown();
}

void turboserve_main_loop(struct turboserve *l)
{
    turboserve_status_info("Ready to serve");

    turboserve_job_thread_main_loop();
}

#ifdef CLOCK_MONOTONIC_COARSE
turboserve_CONSTRUCTOR(detect_fastest_monotonic_clock, 0)
{
    struct timespec ts;

    if (!clock_gettime(CLOCK_MONOTONIC_COARSE, &ts))
        monotonic_clock_id = CLOCK_MONOTONIC_COARSE;
}
#endif

void turboserve_set_thread_name(const char *name)
{
    char thread_name[16];
    char process_name[PATH_MAX];
    char *tmp;
    int ret;

    if (proc_pidpath(getpid(), process_name, sizeof(process_name)) < 0)
        return;

    tmp = strrchr(process_name, '/');
    if (!tmp)
        return;

    ret = snprintf(thread_name, sizeof(thread_name), "%s %s", tmp + 1, name);
    if (ret < 0)
        return;

    pthread_set_name_np(pthread_self(), thread_name);
}
