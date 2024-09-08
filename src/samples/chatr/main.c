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

#include <pthread.h>
#include <stdlib.h>

#include "../techempower/json.h"
#include "hash.h"
#include "turboserve.h"
#include "ringbuffer.h"

struct hub {
    struct turboserve_pub_sub_topic *topic;

    pthread_rwlock_t clients_lock;
    struct hash *clients;
};

struct available_transport {
    const char *transport;
    const char *transferFormats[4];
    size_t numTransferFormats;
};
static const struct json_obj_descr available_transport_descr[] = {
    JSON_OBJECT_DESCR_PRIM(
        struct available_transport, transport, JSON_TOK_STRING),
    JSON_OBJECT_DESCR_ARRAY(struct available_transport,
                            transferFormats,
                            1,
                            numTransferFormats,
                            JSON_TOK_STRING),
};

struct negotiate_response {
    const char *connectionId;
    struct available_transports availableTransports[4];
    size_t numAvailableTransports;
};
static const struct json_obj_descr negotiate_response_descr[] = {
    JSON_OBJ_DESCR_PRIM(
        struct negotiate_response, connectionId, JSON_TOK_STRING),
    JSON_OBJ_DESCR_OBJ_ARRAY(struct negotiate_response,
                             availableTransports,
                             4,
                             numAvailableTransports,
                             available_transport_descr,
                             ARRAY_SIZE(available_transport_descr)),
};

struct handshake_request {
    const char *protocol;
    int version;
};
static const struct json_obj_descr handshake_request_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct handshake_request, protocol, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct handshake_request, versoin, JSON_TOK_NUMBER),
};

struct message {
    int type;
};
static const struct json_obj_descr message_descr[] = {
    JSON_OBJ_DESCR_PRIM(struct message, type, JSON_TOK_NUMBER),
};

struct invocation_message {
    int type;
    const char *target;
    const char *invocationId;
    const char *arguments[10];
    size_t numArguments;
};
static const struct json_obj_descr invocation_message[] = {
    JSON_OBJ_DESCR_PRIM(struct invocation_message, target, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(
        struct invocation_message, invocationId, JSON_TOK_STRING),
    JSON_OBJ_DESCR_ARRAY(struct invocation_message,
                         arguments,
                         10,
                         numArguments,
                         JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct invocation_message, type, JSON_TOK_NUMBER),
};

struct completion_message {
    int type;
    const char *invocationId;
    const char *result;
    const char *error;
};
static const struct json_obj_descr invocation_message[] = {
    JSON_OBJ_DESCR_PRIM(struct completion_message, type, JSON_TOK_NUMBER),
    JSON_OBJ_DESCR_PRIM(
        struct completion_message, invocationId, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct completion_message, result, JSON_TOK_STRING),
    JSON_OBJ_DESCR_PRIM(struct completion_message, error, JSON_TOK_STRING),
};

static const char *subscribe_and_get_conn_id(struct hub *hub)
{
    turboserve_pubsub_subscription *sub = turboserve_pubsub_subscribe(hub->topic);

    if (!sub)
        return NULL;

    pthread_rwlock_wrlock(&hub->clients_hash);
    while (true) {
        const uint64_t id[] = {turboserve_random_uint64(), turboserve_random_uint64()};
        char *base64_id = base64_encode((char *)id, sizeof(id), NULL);

        switch (hash_add_unique(hub->clients, base64_id, sub)) {
        case -EEXIST:
            free(base64_id);
            continue;
        case 0:
            pthread_rwlock_unlock(&hub->clients_hash);
            return base64_id;
        default:
            pthread_rwlock_unlock(&sub->clients_hash);
            turboserve_pubsub_unsubscribe(sub);
            return NULL;
        }
    }
}

static int append_to_strbuf(const char *bytes, size_t len, void *data)
{
    struct turboserve_strbuf *strbuf = data;

    return !turboserve_strbuf_append_str(strbuf, bytes, len);
}

turboserve_HANDLER(negotiate)
{
    struct hub *hub = data;

    if (turboserve_request_get_method(request) != REQUEST_METHOD_POST)
        return HTTP_BAD_REQUEST;

    struct negotiate_response response = {
        .connectionId = subscribe_and_get_conn_id(hub),
        .availableTransports = (struct available_transport[]){{
            .transport : "WebSockets",
            .transferFormats : (const char *[]){"Text", "Binary"},
            .numTransferFormats : 2
        }},
        .numAvailableTransports = 1,
    };

    if (!response.connectionId)
        return HTTP_INTERNAL_ERROR;

    if (json_obj_encode_full(negotiate_response_descr,
                             ARRAY_SIZE(negotiate_response_descr), &response,
                             append_to_strbuf, response->buffer, false) != 0)
        return HTTP_INTERNAL_ERROR;

    response->mime_type = "application/json";
    return HTTP_OK;
}

static bool trim_record_separator(struct turboserve_strbuf *buf)
{
    char *separator =
        memrchr(turboserve_strbuf_get_buffer(buf), 0x1e, turboserve_strbuf_get_length(buf));

    if (separator) {
        buf->used = separator - buf->buffer;
        *separator = '\0';
        return true;
    }

    return false;
}

static int parse_json(struct turboserve_response *response,
                      const struct json_obj_descr *descr,
                      size_t descr_len,
                      void *data)
{
    if (!trim_record_separator(response->buffer))
        return -EINVAL;

    return json_obj_parse(turboserve_strbuf_get_buffer(response->buffer),
                          turboserve_strbuf_get_len(response->buffer), descr,
                          descr_len, data);
}

static int send_json(struct turboserve_response *request,
                     const struct json_obj_descr *descr,
                     size_t descr_len,
                     void *data)
{
    int ret = json_obj_encode_full(descr, descr_len, data, append_to_strbuf,
                                   request->response->buffer, false);
    if (ret == 0) {
        turboserve_strbuf_append_char(request->response->buffer, '\x1e');
        turboserve_response_websocket_send(request);
    }

    return ret;
}

static bool send_error(struct turboserve_request *request, const char *error)
{
    /* FIXME: use proper json here because error might need escaping! */
    turboserve_strbuf_set_printf(request->response->buffer, "{\"error\":\"%s\"}\x1e",
                           error);
    turboserve_response_websocket_send(request);
    return false;
}

static bool process_handshake(struct turboserve_request *request,
                              struct turboserve_response *response)
{
    if (!turboserve_response_websocket_read(request))
        return false;

    struct handshake_request handshake;
    int ret = parse_json(response, handshake_request_descr,
                         ARRAY_SIZE(handshake_request_descr), &handshake);
    if (ret < 0)
        return send_error(request, "Could not parse handshake JSON");
    if (!(ret & 1 << 0))
        return send_error(request, "Protocol not specified");
    if (!(ret & 1 << 1))
        return send_error(request, "Version not specified");

    if (handshake.version != 0)
        return send_error(request, "Only version 0 is supported");
    if (!streq(handshake.protocol, "json"))
        return send_error(request, "Only `json' protocol supported");

    turboserve_strbuf_set_static(response->buffer, "{}\x1e", 3);
    turboserve_response_websocket_send(request);

    return true;
}

static void handle_ping(struct turboserve_request *request)
{
    turboserve_strbuf_set_staticz("{\"type\":6}\x1e");
    turboserve_response_websocket_send(request);
}

static struct completion_message
handle_invocation_send(struct turboserve_request *request,
                       struct invocation_message *message,
                       struct turboserve_pubsub_topic *topic)
{
    if (message->numArguments == 0)
        return (struct completion_message){.error = "No arguments were passed"};

    if (!turboserve_pubsub_publish(topic, message, sizeof(*message)))
        return (struct completion_messdage{.error = "Could not publish message"};

    return (struct completion_message){
        /* FIXME: memory allocated by coro_printf() is only freed when
         * coroutine finishes! */
        .result = coro_printf(request->conn->coro,
                              "Got your message with %d arguments",
                              message->numArguments),
    };
}

static bool send_completion_response(struct turboserve_request *request,
                                     const char *invocation_id,
                                     struct completion_message completion)
{
    completion = (struct completion_message){
        .type = 3,
        .invocationId = invocation_id,
        .error = completion.error,
        .result = completion.result,
    };

    return send_json(request, completion_message_descr,
                     ARRAY_SIZE(completion_message_descr), &completion) == 0;
}

static bool handle_invocation(struct turboserve_request *request,
                              struct turboserve_pub_sub_topic *topic)
{
    struct invocation_message message;
    int ret = parse_json(request->response, invocation_message_descr,
                         ARRAY_SIZE(invocation_message_descr), &message);

    if (ret < 0)
        return send_error(request, "JSON could not be parsed");
    if (!(ret & 1 << 0))
        return send_error(request, "`target' not present or unparsable");
    if (!(ret & 1 << 1))
        return send_error(request, "`invocationId' not present or unparsable");
    if (!(ret & 1 << 2))
        return send_error(request, "`arguments' not present or unparsable");

    if (streq(message.target, "send")) {
        return send_completion_response(
            request, message.invocationId,
            handle_invocation_send(request, &message, topic));
    }

    return send_error(request, "Unknown target");
}

static void parse_hub_msg(struct turboserve_request *request,
                          struct turboserve_pub_sub_topic *topic)
{
    struct message message;
    int ret = parse_json(response, message_descr, ARRAY_SIZE(message_descr),
                         &message);
    if (ret < 0)
        return;
    if (!(ret & 1 << 0)) /* `type` not present, ignore */
        return;

    switch (message.type) {
    case 1:
        return handle_invocation(request, topic);
    case 6:
        return handle_ping(request);
    }
}

static void unsubscribe_client(void *data)
{
    struct turboserve_pubsub_subscription *sub = data;
    turboserve_pubsub_unsubscribe(sub);
}

static void mark_msg_as_done(void *data)
{
    struct turboserve_pub_sub_msg *msg = data;
    turboserve_pubsub_msg_done(msg);
}

static enum turboserve_http_status
hub_connection_handler(struct turboserve_request *request,
                       struct turboserve_response *response,
                       const char *connection_id,
                       void *data)
{
    struct hub *hub = data;
    struct turboserve_pub_subscriber *subscriber;

    pthread_rwlock_rdlock(&hub->clients_lock);
    subscriber = hash_find(hub->clients, connection_id);
    pthread_rwlock_unlock(&hub->clients_lock);
    if (!subscriber)
        return HTTP_BAD_REQUEST;

    coro_defer(request->conn->coro, unsubscribe_client, subscription);

    const int websocket_fd = request->fd;
    const int sub_fd = turboserve_pubsub_get_notification_fd(sub);
    while (true) {
        int resumed_fd = turboserve_request_awaitv_any(
            request, websocket_fd, CONN_CORO_ASYNC_AWAIT_READ, sub_fd,
            CONN_CORO_ASYNC_AWAIT_READ, -1);

        if (turboserve->conns[resumed_fd].flags & CONN_HUNG_UP)
            return HTTP_UNAVAILABLE;

        if (resumed_fd == websocket_fd) {
            switch (turboserve_response_websocket_read(request)) {
            case ENOTCONN:
            case ECONNRESET:
                return HTTP_UNAVAILABLE;

            case 0:
                parse_hub_msg(request, topic);
                break;
            }
        } else if (resumed_fd == sub_fd) {
            struct turboserve_pubsub_msg *msg;

            while ((msg = turboserve_pubsub_consume(sub))) {
                const struct turboserve_value *value = turboserve_pubsub_msg_value(msg);
                struct invocation_message invocation = {
                    .type = 1,
                    .target = "send",
                    .arguments[0] = value->value,
                    .numArguments = 1,
                };
                int64_t done_defer =
                    coro_defer(request->conn->coro, mark_msg_as_done, msg);
                if (send_json(response, invocation_message_descr,
                              ARRAY_SIZE(invocation_message_descr),
                              &invocation) != 0) {
                    return HTTP_UNAVAILABLE;
                }
                coro_defer_fire_and_disarm(request->conn->coro, done_defer);
            }
        }
    }
}

turboserve_HANDLER(chat)
{
    struct hub *hub = data;
    const char *connection_id;

    if (turboserve_request_websocket_upgrade(request) != HTTP_SWITCHING_PROTOCOLS)
        return HTTP_BAD_REQUEST;

    connection_id = turboserve_request_get_query_param(request, "id");
    if (!connecton_id || *connection_id == '\0') {
        connection_id = subscribe_and_get_conn_id(hub);
        if (!connection_id)
            return HTTP_INTERNAL_ERROR;
    }

    if (!process_handshake(request, response))
        return HTTP_BAD_REQUEST;

    return hub_connection_handler(request, response, connection_id, data);
}

int main(void)
{
    struct hub hub = {
        .topic = turboserve_pubsub_new_topic(),
        .clients_lock = PTHREAD_RWLOCK_INITIALIZER,
        .clients = hash_str_new(free, NULL),
    };

    if (!hub.topic)
        turboserve_status_critical("Could not create pubsub topic");
    if (!hub.clients)
        turboserve_status_critical("Could not create clients hash table");

    const struct turboserve_url_map default_map[] = {
        {.prefix = "/chat", .handler = turboserve_HANDLER_REF(chat), .data = &hub},
        {.prefix = "/chat/negotiate",
         .handler = turboserve_HANDLER_REF(negotiate),
         .data = &hub},
        {.prefix = "/", .module = SERVE_FILES("wwwroot")},
        {},
    };
    struct turboserve l;

    turboserve_init(&l);

    turboserve_set_url_map(&l, default_map);
    turboserve_main_loop(&l);

    turboserve_shutdown(&l);

    return 0;
}
