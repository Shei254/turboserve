/*
 * turboserve - web server
 * Copyright (c) 2016 L. A. F. Pereira <l@tia.mat.br>
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

/* API available in Glibc/Linux, but possibly not elsewhere */
#cmakedefine turboserve_HAVE_ACCEPT4
#cmakedefine turboserve_HAVE_ALLOCA_H
#cmakedefine turboserve_HAVE_CLOCK_GETTIME
#cmakedefine turboserve_HAVE_GET_CURRENT_DIR_NAME
#cmakedefine turboserve_HAVE_GETAUXVAL
#cmakedefine turboserve_HAVE_MEMPCPY
#cmakedefine turboserve_HAVE_MEMRCHR
#cmakedefine turboserve_HAVE_MKOSTEMP
#cmakedefine turboserve_HAVE_PIPE2
#cmakedefine turboserve_HAVE_PTHREADBARRIER
#cmakedefine turboserve_HAVE_READAHEAD
#cmakedefine turboserve_HAVE_REALLOCARRAY
#cmakedefine turboserve_HAVE_EPOLL
#cmakedefine turboserve_HAVE_KQUEUE
#cmakedefine turboserve_HAVE_KQUEUE1
#cmakedefine turboserve_HAVE_DLADDR
#cmakedefine turboserve_HAVE_POSIX_FADVISE
#cmakedefine turboserve_HAVE_LINUX_CAPABILITY
#cmakedefine turboserve_HAVE_PTHREAD_SET_NAME_NP
#cmakedefine turboserve_HAVE_GETENTROPY
#cmakedefine turboserve_HAVE_FWRITE_UNLOCKED
#cmakedefine turboserve_HAVE_GETTID
#cmakedefine turboserve_HAVE_SECURE_GETENV
#cmakedefine turboserve_HAVE_STATFS
#cmakedefine turboserve_HAVE_SO_ATTACH_REUSEPORT_CBPF
#cmakedefine turboserve_HAVE_SO_INCOMING_CPU
#cmakedefine turboserve_HAVE_SYSLOG
#cmakedefine turboserve_HAVE_STPCPY
#cmakedefine turboserve_HAVE_EVENTFD
#cmakedefine turboserve_HAVE_MINCORE

/* Compiler builtins for specific CPU instruction support */
#cmakedefine turboserve_HAVE_BUILTIN_CLZLL
#cmakedefine turboserve_HAVE_BUILTIN_CPU_INIT
#cmakedefine turboserve_HAVE_BUILTIN_IA32_CRC32
#cmakedefine turboserve_HAVE_BUILTIN_MUL_OVERFLOW
#cmakedefine turboserve_HAVE_BUILTIN_ADD_OVERFLOW
#cmakedefine turboserve_HAVE_BUILTIN_FPCLASSIFY
#cmakedefine turboserve_HAVE_BUILTIN_EXPECT_PROBABILITY

/* C11 _Static_assert() */
#cmakedefine turboserve_HAVE_STATIC_ASSERT

/* Libraries */
#cmakedefine turboserve_HAVE_LUA
#cmakedefine turboserve_HAVE_LUA_JIT
#cmakedefine turboserve_HAVE_BROTLI
#cmakedefine turboserve_HAVE_ZSTD
#cmakedefine turboserve_HAVE_LIBUCONTEXT
#cmakedefine turboserve_HAVE_MBEDTLS

/* Valgrind support for coroutines */
#cmakedefine turboserve_HAVE_VALGRIND

/* Sanitizer */
#cmakedefine turboserve_HAVE_UNDEFINED_SANITIZER
#cmakedefine turboserve_HAVE_ADDRESS_SANITIZER
#cmakedefine turboserve_HAVE_THREAD_SANITIZER
