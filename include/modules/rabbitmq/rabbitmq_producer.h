#pragma once

#include <stdint.h>
#include <stdbool.h>
#include <pthread.h>
#include <amqp.h>
#include <amqp_tcp_socket.h>

#include "user_session.h"

typedef struct
{
    char host[128];
    uint16_t port;
    char username[128];
    char password[128];
    char vhost[128];

    amqp_connection_state_t connection;
    amqp_socket_t *socket;

    bool connected;
    pthread_mutex_t publish_mutex;

} RabbitMQProducer;

extern RabbitMQProducer g_rabbitmq;

bool rabbitmq_init(
    const char *host,
    uint16_t port,
    const char *username,
    const char *password,
    const char *vhost);

void rabbitmq_disconnect();

bool rabbitmq_publish(
    const char *queue_name,
    const char *message);

bool rabbitmq_publish_session(
    const UserSessionInfo *session);

bool rabbitmq_reconnect();