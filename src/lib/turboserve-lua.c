/*
 * turboserve - web server
 * Copyright (c) 2014 L. A. F. Pereira <l@tia.mat.br>
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
#include <ctype.h>
#include <lauxlib.h>
#include <lualib.h>
#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "turboserve-private.h"

#include "turboserve-lua.h"

#if defined(turboserve_HAVE_LUA_JIT)
#define luaL_reg luaL_Reg
#endif

static const char *request_metatable_name = "turboserve.Request";

ALWAYS_INLINE struct turboserve_request *turboserve_lua_get_request_from_userdata(lua_State *L)
{
    struct turboserve_request **r = luaL_checkudata(L, 1, request_metatable_name);

    return *r;
}

turboserve_LUA_METHOD(http_version)
{
    if (request->flags & REQUEST_IS_HTTP_1_0)
        lua_pushstring(L, "HTTP/1.0");
    else
        lua_pushstring(L, "HTTP/1.1");
    return 1;
}

turboserve_LUA_METHOD(http_method)
{
    lua_pushstring(L, turboserve_request_get_method_str(request));
    return 1;
}

turboserve_LUA_METHOD(http_headers)
{
    const struct turboserve_request_parser_helper *helper = request->helper;

    lua_newtable(L);

    for (size_t i = 0; i < helper->n_header_start; i++) {
        const char *header = helper->header_start[i];
        const char *next_header = helper->header_start[i + 1];
        const char *colon = memchr(header, ':', (size_t)(next_header - header));

        if (!colon)
            continue;

        const ptrdiff_t header_len = colon - header;
        const ptrdiff_t value_len = next_header - colon - 4;

        if (header_len < 0 || value_len < 0)
            continue;

        lua_pushlstring(L, header, (size_t)header_len);
        lua_pushlstring(L, colon + 2, (size_t)value_len);
        lua_rawset(L, -3);
    }

    return 1;
}

turboserve_LUA_METHOD(say)
{
    size_t response_str_len;
    const char *response_str = lua_tolstring(L, -1, &response_str_len);

    turboserve_strbuf_set_static(request->response.buffer, response_str,
                           response_str_len);
    turboserve_response_send_chunk(request);

    return 0;
}

turboserve_LUA_METHOD(send_event)
{
    size_t event_str_len;
    const char *event_str = lua_tolstring(L, -1, &event_str_len);
    const char *event_name = lua_tostring(L, -2);

    turboserve_strbuf_set_static(request->response.buffer, event_str, event_str_len);
    turboserve_response_send_event(request, event_name);

    return 0;
}

turboserve_LUA_METHOD(set_response)
{
    size_t response_str_len;
    const char *response_str = lua_tolstring(L, -1, &response_str_len);

    turboserve_strbuf_set(request->response.buffer, response_str, response_str_len);

    return 0;
}

static int request_param_getter(lua_State *L,
                                struct turboserve_request *request,
                                const char *(*getter)(struct turboserve_request *req,
                                                      const char *key))
{
    const char *key_str = lua_tostring(L, -1);
    const char *value = getter(request, key_str);

    if (!value)
        lua_pushnil(L);
    else
        lua_pushstring(L, value);

    return 1;
}

turboserve_LUA_METHOD(remote_address)
{
    char ip_buffer[INET6_ADDRSTRLEN];
    lua_pushstring(L, turboserve_request_get_remote_address(request, ip_buffer));
    return 1;
}

turboserve_LUA_METHOD(header)
{
    return request_param_getter(L, request, turboserve_request_get_header);
}

turboserve_LUA_METHOD(is_https)
{
    lua_pushboolean(L, !!(request->conn->flags & CONN_TLS));
    return 1;
}

turboserve_LUA_METHOD(path)
{
    lua_pushlstring(L, request->url.value, request->url.len);
    return 1;
}

turboserve_LUA_METHOD(host)
{
    const char *host = turboserve_request_get_host(request);

    if (host)
        lua_pushstring(L, host);
    else
        lua_pushnil(L);

    return 1;
}

turboserve_LUA_METHOD(query_string)
{
    if (request->helper->query_string.len) {
        lua_pushlstring(L, request->helper->query_string.value, request->helper->query_string.len);
    } else {
        lua_pushlstring(L, "", 0);
    }
    return 1;
}

turboserve_LUA_METHOD(query_param)
{
    return request_param_getter(L, request, turboserve_request_get_query_param);
}

turboserve_LUA_METHOD(post_param)
{
    return request_param_getter(L, request, turboserve_request_get_post_param);
}

turboserve_LUA_METHOD(cookie)
{
    return request_param_getter(L, request, turboserve_request_get_cookie);
}

turboserve_LUA_METHOD(body)
{
    if (request->helper->body_data.len) {
        lua_pushlstring(L, request->helper->body_data.value, request->helper->body_data.len);
    } else {
        lua_pushlstring(L, "", 0);
    }
    return 1;
}

turboserve_LUA_METHOD(ws_upgrade)
{
    enum turboserve_http_status status = turboserve_request_websocket_upgrade(request);

    lua_pushinteger(L, status);

    return 1;
}

turboserve_LUA_METHOD(ws_write_text)
{
    size_t data_len;
    const char *data_str = lua_tolstring(L, -1, &data_len);

    turboserve_strbuf_set_static(request->response.buffer, data_str, data_len);
    turboserve_response_websocket_write_text(request);

    return 0;
}

turboserve_LUA_METHOD(ws_write_binary)
{
    size_t data_len;
    const char *data_str = lua_tolstring(L, -1, &data_len);

    turboserve_strbuf_set_static(request->response.buffer, data_str, data_len);
    turboserve_response_websocket_write_binary(request);

    return 0;
}

turboserve_LUA_METHOD(ws_write)
{
    size_t data_len;
    const char *data_str = lua_tolstring(L, -1, &data_len);

    turboserve_strbuf_set_static(request->response.buffer, data_str, data_len);

    for (size_t i = 0; i < data_len; i++) {
        if ((signed char)data_str[i] < 0) {
            turboserve_response_websocket_write_binary(request);
            return 0;
        }
    }

    turboserve_response_websocket_write_text(request);
    return 0;
}

turboserve_LUA_METHOD(ws_read)
{
    int r;

    /* FIXME: maybe return a table {status=r, content=buf}? */

    r = turboserve_response_websocket_read(request);
    switch (r) {
    case 0:
        lua_pushlstring(L, turboserve_strbuf_get_buffer(request->response.buffer),
                        turboserve_strbuf_get_length(request->response.buffer));
        break;
    case ENOTCONN:
    case EAGAIN:
        lua_pushinteger(L, r);
        break;
    default:
        lua_pushinteger(L, ENOMSG);
        break;
    }

    return 1;
}

static bool append_key_value(struct turboserve_request *request,
                             lua_State *L,
                             struct coro *coro,
                             struct turboserve_key_value_array *arr,
                             char *key,
                             int value_index)
{
    size_t len;
    const char *lua_value = lua_tolstring(L, value_index, &len);
    char *value = coro_memdup(coro, lua_value, len + 1);

    if (strcaseequal_neutral(key, "Content-Type")) {
        request->response.mime_type = value;
    } else {
        struct turboserve_key_value *kv;

        kv = turboserve_key_value_array_append(arr);
        if (!kv)
            return false;

        kv->key = key;
        kv->value = value;
    }

    return value != NULL;
}

turboserve_LUA_METHOD(set_headers)
{
    const int table_index = 2;
    const int key_index = -2;
    const int value_index = -1;
    struct turboserve_key_value_array *headers;
    struct coro *coro = request->conn->coro;
    struct turboserve_key_value *kv;

    if (request->flags & RESPONSE_SENT_HEADERS)
        goto out;

    if (!lua_istable(L, table_index))
        goto out;

    headers = coro_turboserve_key_value_array_new(request->conn->coro);
    if (!headers)
        goto out;

    for (lua_pushnil(L); lua_next(L, table_index) != 0; lua_pop(L, 1)) {
        char *key;

        if (lua_type(L, key_index) != LUA_TSTRING)
            continue;

        key = coro_strdup(request->conn->coro, lua_tostring(L, key_index));
        if (!key)
            goto out;

        switch (lua_type(L, value_index)) {
        case LUA_TSTRING:
            if (!append_key_value(request, L, coro, headers, key, value_index))
                goto out;
            break;
        case LUA_TTABLE:
            for (lua_pushnil(L); lua_next(L, value_index - 1) != 0; lua_pop(L, 1)) {
                if (!lua_isstring(L, value_index))
                    continue;
                if (!append_key_value(request, L, coro, headers, key,
                                      value_index))
                    goto out;
            }
            break;
        }
    }

    kv = turboserve_key_value_array_append(headers);
    if (!kv)
        goto out;
    kv->key = kv->value = NULL;

    request->response.headers = turboserve_key_value_array_get_array(headers);
    lua_pushinteger(L, (lua_Integer)headers->base.elements);
    return 1;

out:
    lua_pushnil(L);
    return 1;
}

turboserve_LUA_METHOD(sleep)
{
    lua_Integer ms = lua_tointeger(L, -1);

    turboserve_request_sleep(request, (uint64_t)ms);

    return 0;
}

turboserve_LUA_METHOD(request_id)
{
    lua_pushfstring(L, "%016lx", turboserve_request_get_id(request));
    return 1;
}

turboserve_LUA_METHOD(request_date)
{
    lua_pushstring(L, request->conn->thread->date.date);
    return 1;
}

#define FOR_EACH_LOG_FUNCTION(X) X(info) X(warning) X(error) X(critical) X(debug)

#define IMPLEMENT_FUNCTION(name)                                               \
    static int turboserve_lua_log_##name(lua_State *L)                               \
    {                                                                          \
        size_t log_str_len = 0;                                                \
        const char *log_str = lua_tolstring(L, -1, &log_str_len);              \
        if (log_str_len) {                                                     \
            turboserve_status_##name("%.*s", (int)log_str_len, log_str);             \
            (void)log_str_len;                                                 \
            (void)log_str;                                                     \
        }                                                                      \
        return 0;                                                              \
    }
FOR_EACH_LOG_FUNCTION(IMPLEMENT_FUNCTION)
#undef IMPLEMENT_FUNCTION

static int luaopen_log(lua_State *L)
{
    static const char *metatable_name = "turboserve.log";
#define LOG_FUNCTION(name) {#name, turboserve_lua_log_##name},
    static const struct luaL_Reg functions[] = {
        FOR_EACH_LOG_FUNCTION(LOG_FUNCTION)
        {}
    };
#undef LOG_FUNCTION

    luaL_newmetatable(L, metatable_name);
    luaL_register(L, metatable_name, functions);

    return 0;
}

DEFINE_ARRAY_TYPE(turboserve_lua_method_array, luaL_reg)
static struct turboserve_lua_method_array lua_methods;

turboserve_CONSTRUCTOR(register_lua_methods, 0)
{
    const struct turboserve_lua_method_info *info;
    luaL_reg *r;

    turboserve_SECTION_FOREACH(turboserve_lua_method, info) {
        r = turboserve_lua_method_array_append(&lua_methods);
        if (!r) {
            turboserve_status_critical("Could not register Lua method `%s`",
                                 info->name);
        }

        r->name = info->name;
        r->func = info->func;
    }

    r = turboserve_lua_method_array_append(&lua_methods);
    if (!r)
        turboserve_status_critical("Could not add Lua method sentinel");

    r->name = NULL;
    r->func = NULL;
}

const char *turboserve_lua_state_last_error(lua_State *L)
{
    return lua_tostring(L, -1);
}

lua_State *turboserve_lua_create_state(const char *script_file, const char *script)
{
    lua_State *L;

    L = luaL_newstate();
    if (UNLIKELY(!L))
        return NULL;

    luaL_openlibs(L);
    luaopen_log(L);

    luaL_newmetatable(L, request_metatable_name);
    luaL_register(L, NULL, turboserve_lua_method_array_get_array(&lua_methods));
    lua_setfield(L, -1, "__index");

    if (script_file) {
        if (UNLIKELY(luaL_dofile(L, script_file) != 0)) {
            turboserve_status_error("Error opening Lua script %s: %s", script_file,
                              lua_tostring(L, -1));
            goto close_lua_state;
        }
    } else if (script) {
        if (UNLIKELY(luaL_dostring(L, script) != 0)) {
            turboserve_status_error("Error evaluating Lua script %s",
                              lua_tostring(L, -1));
            goto close_lua_state;
        }
    } else {
        turboserve_status_error("Either file or inline script has to be provided");
        goto close_lua_state;
    }

    return L;

close_lua_state:
    lua_close(L);
    return NULL;
}

void turboserve_lua_state_push_request(lua_State *L, struct turboserve_request *request)
{
    struct turboserve_request **userdata =
        lua_newuserdata(L, sizeof(struct turboserve_request *));

    *userdata = request;
    luaL_getmetatable(L, request_metatable_name);
    lua_setmetatable(L, -2);
}
