#include "rabbitmq_producer.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

RabbitMQProducer g_rabbitmq;

static bool rabbitmq_check_reply(amqp_rpc_reply_t reply)
{
    switch (reply.reply_type)
    {
    case AMQP_RESPONSE_NORMAL:
        return true;

    case AMQP_RESPONSE_NONE:
        syslog(LOG_ERR, "RabbitMQ: missing RPC reply");
        return false;

    case AMQP_RESPONSE_LIBRARY_EXCEPTION:
        syslog(LOG_ERR,
               "RabbitMQ library error: %s",
               amqp_error_string2(reply.library_error));
        return false;

    case AMQP_RESPONSE_SERVER_EXCEPTION:
        syslog(LOG_ERR,
               "RabbitMQ server exception");
        return false;
    }

    return false;
}

bool rabbitmq_init(
    const char *host,
    uint16_t port,
    const char *username,
    const char *password,
    const char *vhost)
{
    memset(&g_rabbitmq, 0, sizeof(g_rabbitmq));

    strncpy(g_rabbitmq.host, host, sizeof(g_rabbitmq.host) - 1);
    strncpy(g_rabbitmq.username, username, sizeof(g_rabbitmq.username) - 1);
    strncpy(g_rabbitmq.password, password, sizeof(g_rabbitmq.password) - 1);
    strncpy(g_rabbitmq.vhost, vhost, sizeof(g_rabbitmq.vhost) - 1);

    g_rabbitmq.port = port;

    pthread_mutex_init(&g_rabbitmq.publish_mutex, NULL);

    g_rabbitmq.connection = amqp_new_connection();

    g_rabbitmq.socket = amqp_tcp_socket_new(g_rabbitmq.connection);
    if (!g_rabbitmq.socket)
    {
        syslog(LOG_ERR, "RabbitMQ socket creation failed");
        return false;
    }

    if (amqp_socket_open(g_rabbitmq.socket,
                         host,
                         port))
    {
        syslog(LOG_ERR,
               "RabbitMQ socket open failed");
        return false;
    }

    if (!rabbitmq_check_reply(
            amqp_login(g_rabbitmq.connection,
                       vhost,
                       0,
                       131072,
                       0,
                       AMQP_SASL_METHOD_PLAIN,
                       username,
                       password)))
    {
        return false;
    }

    amqp_channel_open(g_rabbitmq.connection, 1);

    if (!rabbitmq_check_reply(
            amqp_get_rpc_reply(g_rabbitmq.connection)))
    {
        return false;
    }

    const char *queues[] = {
        "radius.session.start",
        "radius.session.update",
        "radius.session.stop",
        "radius.sync.sessions",
        "radius.sync.wl",
        "radius.sync.cgnat"};

    for (size_t i = 0;
         i < sizeof(queues) / sizeof(queues[0]);
         i++)
    {
        amqp_queue_declare(
            g_rabbitmq.connection,
            1,
            amqp_cstring_bytes(queues[i]),
            0,
            1,
            0,
            0,
            amqp_empty_table);

        if (!rabbitmq_check_reply(
                amqp_get_rpc_reply(g_rabbitmq.connection)))
        {
            return false;
        }
    }

    g_rabbitmq.connected = true;

    syslog(LOG_INFO,
           "RabbitMQ connected successfully");

    return true;
}

void rabbitmq_disconnect()
{
    pthread_mutex_lock(&g_rabbitmq.publish_mutex);

    if (g_rabbitmq.connected)
    {
        amqp_channel_close(
            g_rabbitmq.connection,
            1,
            AMQP_REPLY_SUCCESS);

        amqp_connection_close(
            g_rabbitmq.connection,
            AMQP_REPLY_SUCCESS);

        amqp_destroy_connection(g_rabbitmq.connection);

        g_rabbitmq.connected = false;
    }

    pthread_mutex_unlock(&g_rabbitmq.publish_mutex);

    pthread_mutex_destroy(&g_rabbitmq.publish_mutex);
}

bool rabbitmq_reconnect()
{
    rabbitmq_disconnect();

    return rabbitmq_init(
        g_rabbitmq.host,
        g_rabbitmq.port,
        g_rabbitmq.username,
        g_rabbitmq.password,
        g_rabbitmq.vhost);
}

bool rabbitmq_publish(
    const char *queue_name,
    const char *message)
{
    if (!queue_name || !message)
        return false;

    pthread_mutex_lock(&g_rabbitmq.publish_mutex);

    if (!g_rabbitmq.connected)
    {
        pthread_mutex_unlock(&g_rabbitmq.publish_mutex);
        return false;
    }

    amqp_bytes_t body;
    body.len = strlen(message);
    body.bytes = (void *)message;

    int ret = amqp_basic_publish(
        g_rabbitmq.connection,
        1,
        amqp_empty_bytes,
        amqp_cstring_bytes(queue_name),
        0,
        0,
        &(amqp_basic_properties_t){
            ._flags = AMQP_BASIC_CONTENT_TYPE_FLAG |
                      AMQP_BASIC_DELIVERY_MODE_FLAG,
            .content_type = amqp_cstring_bytes("application/json"),
            .delivery_mode = 2},
        body);

    pthread_mutex_unlock(&g_rabbitmq.publish_mutex);

    if (ret < 0)
    {
        syslog(LOG_ERR,
               "RabbitMQ publish failed: %s",
               amqp_error_string2(ret));

        rabbitmq_reconnect();
        return false;
    }

    return true;
}

bool rabbitmq_publish_session(
    const UserSessionInfo *session)
{
    if (!session)
        return false;

    char json[4096];

    snprintf(
        json,
        sizeof(json),
        "{"
        "\"session_id\":\"%s\","
        "\"multi_session_id\":\"%s\","
        "\"calling_station_id\":\"%s\","
        "\"status\":%u,"
        "\"event_timestamp\":%u,"
        "\"ipv4\":\"%u.%u.%u.%u\","
        "\"wl\":%u"
        "}",
        session->acAccountSessionId,
        session->acMultiSessionId,
        session->acCallingStationId,
        session->u8AccountStatusType,
        session->u32EventTimestamp,
        session->u8FramedIpv4Address[0],
        session->u8FramedIpv4Address[1],
        session->u8FramedIpv4Address[2],
        session->u8FramedIpv4Address[3],
        session->u8IsWL);

    const char *queue_name = NULL;

    switch (session->u8AccountStatusType)
    {
    case SESSION_START:
        queue_name = "radius.session.start";
        break;

    case SESSION_UPDATE:
        queue_name = "radius.session.update";
        break;

    case SESSION_STOP:
        queue_name = "radius.session.stop";
        break;

    default:
        return false;
    }

    return rabbitmq_publish(queue_name, json);
}