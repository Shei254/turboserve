/*
 * turboserve - web server
 * Copyright (c) 2019 L. A. F. Pereira <l@tia.mat.br>
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

#include <unistd.h>

#include "turboserve-private.h"
#include "turboserve-tq.h"

static inline int timeout_queue_node_to_idx(struct timeout_queue *tq,
                                            struct turboserve_connection *conn)
{
    return (conn == &tq->head) ? -1 : (int)(intptr_t)(conn - tq->conns);
}

static inline struct turboserve_connection *
timeout_queue_idx_to_node(struct timeout_queue *tq, int idx)
{
    return (idx < 0) ? &tq->head : &tq->conns[idx];
}

inline void timeout_queue_insert(struct timeout_queue *tq,
                                 struct turboserve_connection *new_node)
{
    assert(!(new_node->flags & (CONN_HUNG_UP | CONN_ASYNC_AWAIT)));

    new_node->next = -1;
    new_node->prev = tq->head.prev;
    struct turboserve_connection *prev = timeout_queue_idx_to_node(tq, tq->head.prev);
    tq->head.prev = prev->next = timeout_queue_node_to_idx(tq, new_node);
}

static inline void timeout_queue_remove(struct timeout_queue *tq,
                                        struct turboserve_connection *node)
{
    struct turboserve_connection *prev = timeout_queue_idx_to_node(tq, node->prev);
    struct turboserve_connection *next = timeout_queue_idx_to_node(tq, node->next);

    next->prev = node->prev;
    prev->next = node->next;
}

inline bool timeout_queue_empty(struct timeout_queue *tq)
{
    return tq->head.next < 0;
}

inline void timeout_queue_move_to_last(struct timeout_queue *tq,
                                       struct turboserve_connection *conn)
{
    /* CONN_IS_KEEP_ALIVE isn't checked here because non-keep-alive connections
     * are closed in the request processing coroutine after they have been
     * served.  In practice, if this is called, it's a keep-alive connection. */
    conn->time_to_expire = tq->current_time + tq->move_to_last_bump;

    timeout_queue_remove(tq, conn);
    timeout_queue_insert(tq, conn);
}

void timeout_queue_init(struct timeout_queue *tq, const struct turboserve *turboserve)
{
    *tq = (struct timeout_queue){
        .turboserve = turboserve,
        .conns = turboserve->conns,
        .current_time = 0,
        .move_to_last_bump = turboserve->config.keep_alive_timeout,
        .head.next = -1,
        .head.prev = -1,
        .timeout = (struct timeout){},
    };
}

void timeout_queue_expire(struct timeout_queue *tq,
                          struct turboserve_connection *conn)
{
    assert(!(conn->flags & (CONN_HUNG_UP | CONN_ASYNC_AWAIT)));

    timeout_queue_remove(tq, conn);

    if (LIKELY(conn->coro)) {
        coro_free(conn->coro);
        conn->coro = NULL;
    }

    close(turboserve_connection_get_fd(tq->turboserve, conn));
}

void timeout_queue_expire_waiting(struct timeout_queue *tq)
{
    tq->current_time++;

    while (!timeout_queue_empty(tq)) {
        struct turboserve_connection *conn =
            timeout_queue_idx_to_node(tq, tq->head.next);

        if (conn->time_to_expire > tq->current_time)
            return;

        if (conn->flags & CONN_IS_WEBSOCKET) {
            if (LIKELY(turboserve_send_websocket_ping_for_tq(conn))) {
                timeout_queue_move_to_last(tq, conn);
                continue;
            }
        }

        timeout_queue_expire(tq, conn);
    }

    /* Timeout queue exhausted: reset epoch */
    tq->current_time = 0;
}

void timeout_queue_expire_all(struct timeout_queue *tq)
{
    while (!timeout_queue_empty(tq)) {
        struct turboserve_connection *conn =
            timeout_queue_idx_to_node(tq, tq->head.next);
        timeout_queue_expire(tq, conn);
    }
}
