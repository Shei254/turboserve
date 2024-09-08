/*
 * turboserve - web server
 * Copyright (c) 2013 L. A. F. Pereira <l@tia.mat.br>
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

#include <errno.h>
#include <sys/socket.h>
#include <sys/uio.h>
#include <unistd.h>

#include "turboserve.h"

ssize_t turboserve_writev_fd(struct turboserve_request *request,
                       int fd,
                       struct iovec *iov,
                       int iovcnt);
ssize_t turboserve_send_fd(struct turboserve_request *request,
                     int fd,
                     const void *buf,
                     size_t count,
                     int flags);
int turboserve_sendfile_fd(struct turboserve_request *request,
                     int out_fd,
                     int in_fd,
                     off_t offset,
                     size_t count,
                     const char *header,
                     size_t header_len);
ssize_t turboserve_recv_fd(
    struct turboserve_request *request, int fd, void *buf, size_t count, int flags);
ssize_t turboserve_readv_fd(struct turboserve_request *request,
                      int fd,
                      struct iovec *iov,
                      int iov_count);

static inline ssize_t
turboserve_writev(struct turboserve_request *request, struct iovec *iov, int iovcnt)
{
    ssize_t r = turboserve_writev_fd(request, request->fd, iov, iovcnt);
    if (UNLIKELY(r < 0)) {
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }
    return r;
}

static inline ssize_t turboserve_send(struct turboserve_request *request,
                                const void *buf,
                                size_t count,
                                int flags)
{
    ssize_t r = turboserve_send_fd(request, request->fd, buf, count, flags);
    if (UNLIKELY(r < 0)) {
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }
    return r;
}

static inline int turboserve_sendfile(struct turboserve_request *request,
                                int in_fd,
                                off_t offset,
                                size_t count,
                                const char *header,
                                size_t header_len)
{
    int r = turboserve_sendfile_fd(request, request->fd, in_fd, offset, count, header,
                             header_len);
    if (UNLIKELY(r < 0)) {
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }
    return r;
}

static inline ssize_t
turboserve_recv(struct turboserve_request *request, void *buf, size_t count, int flags)
{
    ssize_t r = turboserve_recv_fd(request, request->fd, buf, count, flags);
    if (UNLIKELY(r < 0 && !(flags & MSG_NOSIGNAL))) {
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }
    return r;
}

static inline ssize_t
turboserve_readv(struct turboserve_request *request, struct iovec *iov, int iov_count)
{
    ssize_t r = turboserve_readv_fd(request, request->fd, iov, iov_count);
    if (UNLIKELY(r < 0)) {
        coro_yield(request->conn->coro, CONN_CORO_ABORT);
        __builtin_unreachable();
    }
    return r;
}
