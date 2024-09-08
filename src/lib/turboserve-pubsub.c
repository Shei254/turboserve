/*
 * turboserve - web server
 * Copyright (c) 2020 L. A. F. Pereira <l@tia.mat.br>
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
#include <fcntl.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#if defined(turboserve_HAVE_EVENTFD)
#include <sys/eventfd.h>
#endif

#include "list.h"
#include "ringbuffer.h"
#include "turboserve-private.h"

struct turboserve_pubsub_topic {
    struct list_head subscribers;
    pthread_rwlock_t lock;
};

struct turboserve_pubsub_msg {
    struct turboserve_value value;
    unsigned int refcount;
};

DEFINE_RING_BUFFER_TYPE(turboserve_pubsub_msg_ref_ring, struct turboserve_pubsub_msg *, 16)

struct turboserve_pubsub_msg_ref {
    struct list_node ref;
    struct turboserve_pubsub_msg_ref_ring ring;
};

struct turboserve_pubsub_subscriber {
    struct list_node subscriber;

    pthread_mutex_t lock;
    struct list_head msg_refs;

    int event_fd[2];
};

static void turboserve_pubsub_queue_init(struct turboserve_pubsub_subscriber *sub)
{
    list_head_init(&sub->msg_refs);
}

static bool turboserve_pubsub_queue_put(struct turboserve_pubsub_subscriber *sub,
                                  const struct turboserve_pubsub_msg *msg)
{
    struct turboserve_pubsub_msg_ref *ref;

    ref = list_tail(&sub->msg_refs, struct turboserve_pubsub_msg_ref, ref);
    if (ref) {
        /* Try putting the message in the last ringbuffer in this queue: if it's
         * full, will need to allocate a new ring buffer, even if others might
         * have space in them:  the FIFO order must be preserved, and short of
         * compacting the queue at this point -- which will eventually happen
         * as it is consumed -- this is the only option. */
        if (turboserve_pubsub_msg_ref_ring_try_put(&ref->ring, &msg))
            return true;
    }

    ref = malloc(sizeof(*ref));
    if (!ref)
        return false;

    turboserve_pubsub_msg_ref_ring_init(&ref->ring);
    turboserve_pubsub_msg_ref_ring_put(&ref->ring, &msg);
    list_add_tail(&sub->msg_refs, &ref->ref);

    return true;
}

static struct turboserve_pubsub_msg *
turboserve_pubsub_queue_get(struct turboserve_pubsub_subscriber *sub)
{
    struct turboserve_pubsub_msg_ref *ref, *next;

    list_for_each_safe (&sub->msg_refs, ref, next, ref) {
        struct turboserve_pubsub_msg *msg;

        if (turboserve_pubsub_msg_ref_ring_empty(&ref->ring)) {
            list_del(&ref->ref);
            free(ref);
            continue;
        }

        msg = turboserve_pubsub_msg_ref_ring_get(&ref->ring);

        if (ref->ref.next != ref->ref.prev) {
            /* If this segment isn't the last one, try pulling in just one
             * element from the next segment, as there's space in the
             * current segment now.
             *
             * This might lead to an empty ring buffer segment in the middle
             * of the linked list.  This is by design, to introduce some
             * hysteresis and avoid the pathological case where malloc churn
             * will happen when subscribers consume at the same rate as
             * publishers are able to publish.
             *
             * The condition above will take care of these empty segments
             * once they're dealt with, eventually compacting the queue
             * completely (and ultimately reducing it to an empty list
             * without any ring buffers).
             */
            struct turboserve_pubsub_msg_ref *next_ring;

            next_ring = container_of(ref->ref.next, struct turboserve_pubsub_msg_ref, ref);
            if (!turboserve_pubsub_msg_ref_ring_empty(&next_ring->ring)) {
                const struct turboserve_pubsub_msg *next_msg;

                next_msg = turboserve_pubsub_msg_ref_ring_get(&next_ring->ring);
                turboserve_pubsub_msg_ref_ring_put(&ref->ring, &next_msg);
            }
        }

        return msg;
    }

    return NULL;
}

static void turboserve_pubsub_unsubscribe_internal(struct turboserve_pubsub_topic *topic,
                                             struct turboserve_pubsub_subscriber *sub,
                                             bool take_topic_lock);

struct turboserve_pubsub_topic *turboserve_pubsub_new_topic(void)
{
    struct turboserve_pubsub_topic *topic = calloc(1, sizeof(*topic));

    if (!topic)
        return NULL;

    list_head_init(&topic->subscribers);
    pthread_rwlock_init(&topic->lock, NULL);

    return topic;
}

void turboserve_pubsub_free_topic(struct turboserve_pubsub_topic *topic)
{
    struct turboserve_pubsub_subscriber *iter, *next;

    pthread_rwlock_wrlock(&topic->lock);
    list_for_each_safe (&topic->subscribers, iter, next, subscriber)
        turboserve_pubsub_unsubscribe_internal(topic, iter, false);
    pthread_rwlock_unlock(&topic->lock);

    pthread_rwlock_destroy(&topic->lock);

    free(topic);
}

void turboserve_pubsub_msg_done(struct turboserve_pubsub_msg *msg)
{
    if (!ATOMIC_DEC(msg->refcount)) {
        free(msg->value.value);
        free(msg);
    }
}

static bool turboserve_pubsub_publish_value(struct turboserve_pubsub_topic *topic,
                                      const struct turboserve_value value)
{
    struct turboserve_pubsub_msg *msg = malloc(sizeof(*msg));
    struct turboserve_pubsub_subscriber *sub;

    if (!msg)
        return false;

    /* Initialize refcount to 1, so we can drop one ref after publishing to
     * all subscribers.  If it drops to 0, it means we didn't publish the
     * message and we can free it. */
    msg->refcount = 1;
    msg->value = value;

    pthread_rwlock_rdlock(&topic->lock);
    list_for_each (&topic->subscribers, sub, subscriber) {
        ATOMIC_INC(msg->refcount);

        /* FIXME: use trylock and a local queue to try again? */
        pthread_mutex_lock(&sub->lock);
        if (!turboserve_pubsub_queue_put(sub, msg)) {
            turboserve_status_warning("Couldn't enqueue message, dropping");
            ATOMIC_DEC(msg->refcount);
        }
        pthread_mutex_unlock(&sub->lock);

        if (sub->event_fd[1] < 0) {
            continue;
        }
        while (true) {
            ssize_t written =
                write(sub->event_fd[1], &(uint64_t){1}, sizeof(uint64_t));

            if (LIKELY(written == (ssize_t)sizeof(uint64_t)))
                break;

            if (UNLIKELY(written < 0)) {
                if (errno == EINTR || errno == EAGAIN)
                    continue;
                turboserve_status_perror("write to eventfd failed, ignoring");
                break;
            }
        }
    }
    pthread_rwlock_unlock(&topic->lock);

    turboserve_pubsub_msg_done(msg);

    return true;
}

static void *my_memdup(const void *src, size_t len)
{
    void *dup = malloc(len);

    return dup ? memcpy(dup, src, len) : NULL;
}

bool turboserve_pubsub_publish(struct turboserve_pubsub_topic *topic,
                         const void *contents,
                         size_t len)
{
    const struct turboserve_value value = { .value = my_memdup(contents, len), .len = len };

    if (!value.value)
        return false;

    return turboserve_pubsub_publish_value(topic, value);
}

bool turboserve_pubsub_publishf(struct turboserve_pubsub_topic *topic,
                          const char *format,
                          ...)
{
    char *msg;
    int len;
    va_list ap;

    va_start(ap, format);
    len = vasprintf(&msg, format, ap);
    va_end(ap);

    if (len < 0)
        return false;

    const struct turboserve_value value = { .value = msg, .len = (size_t)len };
    return turboserve_pubsub_publish_value(topic, value);
}

struct turboserve_pubsub_subscriber *
turboserve_pubsub_subscribe(struct turboserve_pubsub_topic *topic)
{
    struct turboserve_pubsub_subscriber *sub = calloc(1, sizeof(*sub));

    if (!sub)
        return NULL;

    sub->event_fd[0] = -1;
    sub->event_fd[1] = -1;

    pthread_mutex_init(&sub->lock, NULL);
    turboserve_pubsub_queue_init(sub);

    pthread_rwlock_wrlock(&topic->lock);
    list_add(&topic->subscribers, &sub->subscriber);
    pthread_rwlock_unlock(&topic->lock);

    return sub;
}

struct turboserve_pubsub_msg *turboserve_pubsub_consume(struct turboserve_pubsub_subscriber *sub)
{
    struct turboserve_pubsub_msg *msg;

    pthread_mutex_lock(&sub->lock);
    msg = turboserve_pubsub_queue_get(sub);
    pthread_mutex_unlock(&sub->lock);

    if (msg && sub->event_fd[0] >= 0) {
        uint64_t discard;
        turboserve_NO_DISCARD(read(sub->event_fd[0], &discard, sizeof(uint64_t)));
    }

    return msg;
}

static void turboserve_pubsub_unsubscribe_internal(struct turboserve_pubsub_topic *topic,
                                             struct turboserve_pubsub_subscriber *sub,
                                             bool take_topic_lock)
{
    struct turboserve_pubsub_msg *iter;

    if (take_topic_lock)
        pthread_rwlock_wrlock(&topic->lock);
    list_del(&sub->subscriber);
    if (take_topic_lock)
        pthread_rwlock_unlock(&topic->lock);

    pthread_mutex_lock(&sub->lock);
    while ((iter = turboserve_pubsub_queue_get(sub)))
        turboserve_pubsub_msg_done(iter);
    pthread_mutex_unlock(&sub->lock);

    pthread_mutex_destroy(&sub->lock);

    if (sub->event_fd[0] != sub->event_fd[1]) {
        close(sub->event_fd[0]);
        close(sub->event_fd[1]);
    } else if (LIKELY(sub->event_fd[0] >= 0)) {
        close(sub->event_fd[0]);
    }

    free(sub);
}

void turboserve_pubsub_unsubscribe(struct turboserve_pubsub_topic *topic,
                             struct turboserve_pubsub_subscriber *sub)
{
    return (void)turboserve_pubsub_unsubscribe_internal(topic, sub, true);
}

const struct turboserve_value *turboserve_pubsub_msg_value(const struct turboserve_pubsub_msg *msg)
{
    return &msg->value;
}

int turboserve_pubsub_get_notification_fd(struct turboserve_pubsub_subscriber *sub)
{
    if (sub->event_fd[0] < 0) {
#if defined(turboserve_HAVE_EVENTFD)
        int efd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK | EFD_SEMAPHORE);
        if (efd < 0) {
            return -1;
        }

        sub->event_fd[0] = sub->event_fd[1] = efd;
#else
        if (pipe2(sub->event_fd, O_CLOEXEC | O_NONBLOCK) < 0) {
            return -1;
        }
#endif
    }

    return sub->event_fd[0];
}
