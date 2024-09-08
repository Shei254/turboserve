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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 */

#pragma once

#include <lua.h>

struct turboserve_request;

struct turboserve_lua_method_info {
    const char *name;
    int (*func)();
};

#define turboserve_LUA_METHOD(name_)                                                 \
    static int turboserve_lua_method_##name_##_wrapper(lua_State *L);                \
    static int turboserve_lua_method_##name_(lua_State *L,                           \
                                       struct turboserve_request *request);          \
    static const struct turboserve_lua_method_info                                   \
        __attribute__((used, section(turboserve_SECTION_NAME(turboserve_lua_method))))     \
        turboserve_lua_method_info_##name_ = {                                       \
            .name = #name_, .func = turboserve_lua_method_##name_##_wrapper};        \
    static int turboserve_lua_method_##name_##_wrapper(lua_State *L)                 \
    {                                                                          \
        struct turboserve_request *request = turboserve_lua_get_request_from_userdata(L);  \
        return turboserve_lua_method_##name_(L, request);                            \
    }                                                                          \
    static ALWAYS_INLINE int turboserve_lua_method_##name_(                          \
        lua_State *L, struct turboserve_request *request)


const char *turboserve_lua_state_last_error(lua_State *L);
lua_State *turboserve_lua_create_state(const char *script_file, const char *script);

void turboserve_lua_state_push_request(lua_State *L, struct turboserve_request *request);

struct turboserve_request *turboserve_lua_get_request_from_userdata(lua_State *L);
