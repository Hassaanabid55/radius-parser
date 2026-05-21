#include "modules/rabbitmq/rabbitmq_producer.h"

extern char opt_rabbitmq_host[128];
extern char opt_rabbitmq_vhost[64];
extern char opt_rabbitmq_user[64];
extern char opt_rabbitmq_password[64];
extern uint16_t opt_rabbitmq_port;

static int declare_topology(RabbitMQClient *client)
{
    amqp_exchange_declare(client->conn, client->channel, amqp_cstring_bytes(RABBITMQ_EXCHANGE), amqp_cstring_bytes("direct"), 0, 1, 0, 0, amqp_empty_table);
    amqp_queue_declare(client->conn, client->channel, amqp_cstring_bytes(START_QUEUE), 0, 1, 0, 0, amqp_empty_table);
    amqp_queue_declare(client->conn, client->channel, amqp_cstring_bytes(UPDATE_QUEUE), 0, 1, 0, 0, amqp_empty_table);
    amqp_queue_declare(client->conn, client->channel, amqp_cstring_bytes(STOP_QUEUE), 0, 1, 0, 0, amqp_empty_table);
    amqp_queue_bind(client->conn, client->channel, amqp_cstring_bytes(START_QUEUE), amqp_cstring_bytes(RABBITMQ_EXCHANGE), amqp_cstring_bytes(START_ROUTING_KEY), amqp_empty_table);
    amqp_queue_bind(client->conn, client->channel, amqp_cstring_bytes(UPDATE_QUEUE), amqp_cstring_bytes(RABBITMQ_EXCHANGE), amqp_cstring_bytes(UPDATE_ROUTING_KEY), amqp_empty_table);
    amqp_queue_bind(client->conn, client->channel, amqp_cstring_bytes(STOP_QUEUE), amqp_cstring_bytes(RABBITMQ_EXCHANGE), amqp_cstring_bytes(STOP_ROUTING_KEY), amqp_empty_table);
    return 1;
}

int rabbitmq_init(RabbitMQClient *client)
{
    memset(client, 0, sizeof(*client));
    client->channel = 1;
    client->conn = amqp_new_connection();
    client->socket = amqp_tcp_socket_new(client->conn);
    if (!client->socket)
    {
        fprintf(stderr, "RabbitMQ socket creation failed\n");
        return 0;
    }

    if (amqp_socket_open(client->socket, opt_rabbitmq_host, opt_rabbitmq_port))
    {
        fprintf(stderr, "RabbitMQ socket open failed\n");
        return 0;
    }

    amqp_rpc_reply_t reply;
    reply = amqp_login(client->conn, opt_rabbitmq_vhost, 0, 131072, 60, AMQP_SASL_METHOD_PLAIN, opt_rabbitmq_user, opt_rabbitmq_password);
    if (reply.reply_type != AMQP_RESPONSE_NORMAL)
    {
        fprintf(stderr, "RabbitMQ login failed\n");
        return 0;
    }

    amqp_channel_open(client->conn, client->channel);
    reply = amqp_get_rpc_reply(client->conn);
    if (reply.reply_type != AMQP_RESPONSE_NORMAL)
    {
        fprintf(stderr, "RabbitMQ channel open failed\n");
        return 0;
    }

    return declare_topology(client);
}

void rabbitmq_cleanup(RabbitMQClient *client)
{
    if (!client)
        return;

    amqp_channel_close(client->conn, client->channel, AMQP_REPLY_SUCCESS);
    amqp_connection_close(client->conn, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(client->conn);
}

static int rabbitmq_publish(RabbitMQClient *client, const char *routing_key, const char *data, size_t len)
{
    amqp_bytes_t body;
    body.len = len;
    body.bytes = (void *)data;
    int ret = amqp_basic_publish(client->conn, client->channel, amqp_cstring_bytes(RABBITMQ_EXCHANGE), amqp_cstring_bytes(routing_key), 0, 0, NULL, body);
    return (ret == 0);
}

int rabbitmq_publish_start(RabbitMQClient *client, const char *data, size_t len)
{
    return rabbitmq_publish(client, START_ROUTING_KEY, data, len);
}

int rabbitmq_publish_update(RabbitMQClient *client, const char *data, size_t len)
{
    return rabbitmq_publish(client, UPDATE_ROUTING_KEY, data, len);
}

int rabbitmq_publish_stop(RabbitMQClient *client, const char *data, size_t len)
{
    return rabbitmq_publish(client, STOP_ROUTING_KEY, data, len);
}

int rabbitmq_publish_cgnat(RabbitMQClient *client, const CgnatEntry *e)
{
    char buf[512];

    int len = snprintf(buf, sizeof(buf),
        "{"
        "\"type\":\"cgnat\","
        "\"inside_ip\":\"%s\","
        "\"nat_ip\":\"%s\","
        "\"start_port\":%u,"
        "\"end_port\":%u"
        "}",
        e->inside_ip,
        e->nat_ip,
        e->start_port,
        e->end_port
    );

    return rabbitmq_publish(client, CGNAT_QUEUE, buf, len);
}

int rabbitmq_publish_whitelist(RabbitMQClient *client, const WhitelistInfo *w)
{
    char buf[256];

    int len = snprintf(buf, sizeof(buf),
        "{"
        "\"type\":\"whitelist\","
        "\"msisdn\":\"%s\","
        "\"status\":%d"
        "}",
        w->msisdn,
        w->status
    );

    return rabbitmq_publish(client, WHITELIST_QUEUE, buf, len);
}

int rabbitmq_publish_session(RabbitMQClient *client, const UserSessionInfo *s)
{
    char buf[2048];

    int len = session_to_json(s, buf, sizeof(buf));

    return rabbitmq_publish(client, SESSION_QUEUE, buf, len);
}

void restore_state_from_queue(amqp_connection_state_t conn, const char *queue);

void restore_cgnat(CgnatNode **map, const CgnatEntry *e)
{
    CgnatNode *node = malloc(sizeof(CgnatNode));
    memset(node, 0, sizeof(*node));

    strcpy(node->inside_ip, e->inside_ip);
    node->entry = *e;

    HASH_ADD_STR(*map, inside_ip, node);
}

void restore_whitelist(WlNode **map, const WhitelistInfo *w)
{
    WlNode *node = malloc(sizeof(WlNode));
    memset(node, 0, sizeof(*node));

    strcpy(node->msisdn, w->msisdn);
    node->info = *w;

    HASH_ADD_STR(*map, msisdn, node);
}

void restore_session(SessionNode **map, const UserSessionInfo *s)
{
    SessionNode *node = malloc(sizeof(SessionNode));
    memset(node, 0, sizeof(*node));

    strcpy(node->acAccountSessionId, s->acAccountSessionId);
    node->entry = *s;

    HASH_ADD_STR(*map, acAccountSessionId, node);
}