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

#pragma once

#include "turboserve.h"

struct turboserve_pubsub_topic;
struct turboserve_pubsub_msg;
struct turboserve_pubsub_subscriber;

struct turboserve_pubsub_topic *turboserve_pubsub_new_topic(void);
void turboserve_pubsub_free_topic(struct turboserve_pubsub_topic *topic);

bool turboserve_pubsub_publish(struct turboserve_pubsub_topic *topic,
                         const void *contents,
                         size_t len);
bool turboserve_pubsub_publishf(struct turboserve_pubsub_topic *topic,
                          const char *format,
                          ...) __attribute__((format(printf, 2, 3)));

struct turboserve_pubsub_subscriber *
turboserve_pubsub_subscribe(struct turboserve_pubsub_topic *topic);
void turboserve_pubsub_unsubscribe(struct turboserve_pubsub_topic *topic,
                             struct turboserve_pubsub_subscriber *sub);

struct turboserve_pubsub_msg *turboserve_pubsub_consume(struct turboserve_pubsub_subscriber *sub);
const struct turboserve_value *turboserve_pubsub_msg_value(const struct turboserve_pubsub_msg *msg);
void turboserve_pubsub_msg_done(struct turboserve_pubsub_msg *msg);

int turboserve_pubsub_get_notification_fd(struct turboserve_pubsub_subscriber *sub);
