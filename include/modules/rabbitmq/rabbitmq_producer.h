#ifndef RABBITMQ_PRODUCER_H
#define RABBITMQ_PRODUCER_H

#include <amqp.h>
#include <amqp_tcp_socket.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "macros.h"

typedef struct
{
    amqp_connection_state_t conn;
    amqp_socket_t *socket;
    int channel;
} RabbitMQClient;

int rabbitmq_init(RabbitMQClient *client);
void rabbitmq_cleanup(RabbitMQClient *client);
int rabbitmq_publish_start(RabbitMQClient *client, const char *data, size_t len);
int rabbitmq_publish_update(RabbitMQClient *client, const char *data, size_t len);
int rabbitmq_publish_stop(RabbitMQClient *client, const char *data, size_t len);

#endif /* RABBITMQ_PRODUCER_H */
