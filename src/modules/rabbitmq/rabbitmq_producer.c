#include "modules/rabbitmq/rabbitmq_producer.h"

// extern char opt_rabbitmq_host[128];
// extern char opt_rabbitmq_vhost[64];
// extern char opt_rabbitmq_user[64];
// extern char opt_rabbitmq_password[64];
// extern uint16_t opt_rabbitmq_port;

// static int declare_topology(RabbitMQClient *client)
// {
//     amqp_exchange_declare(client->conn, client->channel, amqp_cstring_bytes(RABBITMQ_EXCHANGE), amqp_cstring_bytes("direct"), 0, 1, 0, 0, amqp_empty_table);
//     amqp_queue_declare(client->conn, client->channel, amqp_cstring_bytes(START_QUEUE), 0, 1, 0, 0, amqp_empty_table);
//     amqp_queue_declare(client->conn, client->channel, amqp_cstring_bytes(UPDATE_QUEUE), 0, 1, 0, 0, amqp_empty_table);
//     amqp_queue_declare(client->conn, client->channel, amqp_cstring_bytes(STOP_QUEUE), 0, 1, 0, 0, amqp_empty_table);
//     amqp_queue_bind(client->conn, client->channel, amqp_cstring_bytes(START_QUEUE), amqp_cstring_bytes(RABBITMQ_EXCHANGE), amqp_cstring_bytes(START_ROUTING_KEY), amqp_empty_table);
//     amqp_queue_bind(client->conn, client->channel, amqp_cstring_bytes(UPDATE_QUEUE), amqp_cstring_bytes(RABBITMQ_EXCHANGE), amqp_cstring_bytes(UPDATE_ROUTING_KEY), amqp_empty_table);
//     amqp_queue_bind(client->conn, client->channel, amqp_cstring_bytes(STOP_QUEUE), amqp_cstring_bytes(RABBITMQ_EXCHANGE), amqp_cstring_bytes(STOP_ROUTING_KEY), amqp_empty_table);
//     return 1;
// }

// int rabbitmq_init(RabbitMQClient *client)
// {
//     memset(client, 0, sizeof(*client));
//     client->channel = 1;
//     client->conn = amqp_new_connection();
//     client->socket = amqp_tcp_socket_new(client->conn);
//     if (!client->socket)
//     {
//         fprintf(stderr, "RabbitMQ socket creation failed\n");
//         return 0;
//     }

//     if (amqp_socket_open(client->socket, opt_rabbitmq_host, opt_rabbitmq_port))
//     {
//         fprintf(stderr, "RabbitMQ socket open failed\n");
//         return 0;
//     }

//     amqp_rpc_reply_t reply;
//     reply = amqp_login(client->conn, opt_rabbitmq_vhost, 0, 131072, 60, AMQP_SASL_METHOD_PLAIN, opt_rabbitmq_user, opt_rabbitmq_password);
//     if (reply.reply_type != AMQP_RESPONSE_NORMAL)
//     {
//         fprintf(stderr, "RabbitMQ login failed\n");
//         return 0;
//     }

//     amqp_channel_open(client->conn, client->channel);
//     reply = amqp_get_rpc_reply(client->conn);
//     if (reply.reply_type != AMQP_RESPONSE_NORMAL)
//     {
//         fprintf(stderr, "RabbitMQ channel open failed\n");
//         return 0;
//     }

//     return declare_topology(client);
// }

// void rabbitmq_cleanup(RabbitMQClient *client)
// {
//     if (!client)
//         return;

//     amqp_channel_close(client->conn, client->channel, AMQP_REPLY_SUCCESS);
//     amqp_connection_close(client->conn, AMQP_REPLY_SUCCESS);
//     amqp_destroy_connection(client->conn);
// }

// static int rabbitmq_publish(RabbitMQClient *client, const char *routing_key, const char *data, size_t len)
// {
//     amqp_bytes_t body;
//     body.len = len;
//     body.bytes = (void *)data;
//     int ret = amqp_basic_publish(client->conn, client->channel, amqp_cstring_bytes(RABBITMQ_EXCHANGE), amqp_cstring_bytes(routing_key), 0, 0, NULL, body);
//     return (ret == 0);
// }

// int rabbitmq_publish_start(RabbitMQClient *client, const char *data, size_t len)
// {
//     return rabbitmq_publish(client, START_ROUTING_KEY, data, len);
// }

// int rabbitmq_publish_update(RabbitMQClient *client, const char *data, size_t len)
// {
//     return rabbitmq_publish(client, UPDATE_ROUTING_KEY, data, len);
// }

// int rabbitmq_publish_stop(RabbitMQClient *client, const char *data, size_t len)
// {
//     return rabbitmq_publish(client, STOP_ROUTING_KEY, data, len);
// }

// int rabbitmq_publish_cgnat(RabbitMQClient *client, const CgnatEntry *e)
// {
//     char buf[512];

//     int len = snprintf(buf, sizeof(buf),
//         "{"
//         "\"type\":\"cgnat\","
//         "\"inside_ip\":\"%s\","
//         "\"nat_ip\":\"%s\","
//         "\"start_port\":%u,"
//         "\"end_port\":%u"
//         "}",
//         e->inside_ip,
//         e->nat_ip,
//         e->start_port,
//         e->end_port
//     );

//     return rabbitmq_publish(client, CGNAT_QUEUE, buf, len);
// }

// int rabbitmq_publish_whitelist(RabbitMQClient *client, const WhitelistInfo *w)
// {
//     char buf[256];

//     int len = snprintf(buf, sizeof(buf),
//         "{"
//         "\"type\":\"whitelist\","
//         "\"msisdn\":\"%s\","
//         "\"status\":%d"
//         "}",
//         w->msisdn,
//         w->status
//     );

//     return rabbitmq_publish(client, WHITELIST_QUEUE, buf, len);
// }

// int rabbitmq_publish_session(RabbitMQClient *client, const UserSessionInfo *s)
// {
//     char buf[2048];

//     int len = session_to_json(s, buf, sizeof(buf));

//     return rabbitmq_publish(client, SESSION_QUEUE, buf, len);
// }

// void restore_state_from_queue(amqp_connection_state_t conn, const char *queue);

// void restore_cgnat(CgnatNode **map, const CgnatEntry *e)
// {
//     CgnatNode *node = malloc(sizeof(CgnatNode));
//     memset(node, 0, sizeof(*node));

//     strcpy(node->inside_ip, e->inside_ip);
//     node->entry = *e;

//     HASH_ADD_STR(*map, inside_ip, node);
// }

// void restore_whitelist(WlNode **map, const WhitelistInfo *w)
// {
//     WlNode *node = malloc(sizeof(WlNode));
//     memset(node, 0, sizeof(*node));

//     strcpy(node->msisdn, w->msisdn);
//     node->info = *w;

//     HASH_ADD_STR(*map, msisdn, node);
// }

// void restore_session(SessionNode **map, const UserSessionInfo *s)
// {
//     SessionNode *node = malloc(sizeof(SessionNode));
//     memset(node, 0, sizeof(*node));

//     strcpy(node->acAccountSessionId, s->acAccountSessionId);
//     node->entry = *s;

//     HASH_ADD_STR(*map, acAccountSessionId, node);
// }

RabbitMQClient g_rabbitmq;
pthread_mutex_t g_rabbitmq_mutex = PTHREAD_MUTEX_INITIALIZER;

/* =========================================================
 * INIT
 * ========================================================= */
int rabbitmq_init(const RabbitMQConfig *cfg)
{
    memset(&g_rabbitmq, 0, sizeof(g_rabbitmq));
    g_rabbitmq.cfg = *cfg;

    g_rabbitmq.conn = amqp_new_connection();
    g_rabbitmq.socket = amqp_tcp_socket_new(g_rabbitmq.conn);

    if (!g_rabbitmq.socket)
        return 0;

    if (amqp_socket_open(g_rabbitmq.socket, cfg->host, cfg->port))
        return 0;

    amqp_rpc_reply_t r = amqp_login(g_rabbitmq.conn, cfg->vhost, 0, 131072, 60, AMQP_SASL_METHOD_PLAIN, cfg->user, cfg->password);

    if (r.reply_type != AMQP_RESPONSE_NORMAL)
        return 0;

    g_rabbitmq.channel = 1;
    amqp_channel_open(g_rabbitmq.conn, g_rabbitmq.channel);

    if (amqp_get_rpc_reply(g_rabbitmq.conn).reply_type != AMQP_RESPONSE_NORMAL)
        return 0;

    /* Exchange */
    amqp_exchange_declare(&g_rabbitmq, g_rabbitmq.channel, amqp_cstring_bytes(g_rabbitmq.cfg.exchange), amqp_cstring_bytes("direct"), 0, 1, 0, 0, amqp_empty_table);

    amqp_queue_declare(g_rabbitmq.conn, g_rabbitmq.channel, amqp_cstring_bytes("sync.session"), 0, 1, 0, 0, amqp_empty_table);
    amqp_queue_declare(g_rabbitmq.conn, g_rabbitmq.channel, amqp_cstring_bytes("sync.cgnat"), 0, 1, 0, 0, amqp_empty_table);
    amqp_queue_declare(g_rabbitmq.conn, g_rabbitmq.channel, amqp_cstring_bytes("sync.whitelist"), 0, 1, 0, 0, amqp_empty_table);

    return 1;
}

/* =========================================================
 * RAW PUBLISH
 * ========================================================= */
int rabbitmq_publish_raw(RabbitMQClient *c, const char *exchange, const char *routing_key, const void *data, size_t len)
{
    amqp_bytes_t body;
    body.len = len;
    body.bytes = (void *)data;

    return amqp_basic_publish(c->conn, c->channel, amqp_cstring_bytes(exchange), amqp_cstring_bytes(routing_key), 0, 0, NULL, body) == 0;
}

/* =========================================================
 * SESSION EVENT STREAM
 * ========================================================= */
int rabbitmq_publish_session_start(RabbitMQClient *c, const UserSessionInfo *s)
{
    return rabbitmq_publish_raw(c, g_rabbitmq.cfg.exchange, RK_SESSION_START, s, sizeof(*s));
}

int rabbitmq_publish_session_stop(RabbitMQClient *c, const UserSessionInfo *s)
{
    return rabbitmq_publish_raw(c, g_rabbitmq.cfg.exchange, RK_SESSION_STOP, s, sizeof(*s));
}

/* =========================================================
 * STATS STREAM
 * ========================================================= */
int rabbitmq_publish_session_stats(RabbitMQClient *c, const UserSessionInfo *s)
{
    return rabbitmq_publish_raw(c, g_rabbitmq.cfg.exchange, RK_SESSION_STATS, s, sizeof(*s));
}

/* =========================================================
 * INTERNAL HANDLER (SESSION RESTORE)
 * ========================================================= */
static void restore_session(SessionNode **map, const UserSessionInfo *s)
{
    pthread_mutex_lock(&g_session_mutex);

    SessionNode *node = NULL;
    HASH_FIND_STR(*map, s->acAccountSessionId, node);

    if (node)
    {
        if (s->u32EventTimestamp > node->entry.u32EventTimestamp)
            node->entry = *s;
    }
    else
    {
        node = malloc(sizeof(SessionNode));
        memset(node, 0, sizeof(*node));
        strcpy(node->acAccountSessionId, s->acAccountSessionId);
        node->entry = *s;
        HASH_ADD_STR(*map, acAccountSessionId, node);
    }

    pthread_mutex_unlock(&g_session_mutex);
}

/* =========================================================
 * CONSUME BOOTSTRAP STREAM
 * ========================================================= */

static void handle_boot_message(
    const char *queue,
    const void *data,
    size_t len,
    void *ctx)
{
    RabbitMQBootstrapCtx *boot = ctx;

    SessionNode **session_map = boot->session_map;
    CgnatNode **cgnat_map = boot->cgnat_map;
    WlNode **wl_map = boot->wl_map;
    RabbitMQBootstrapState *state = boot->state;

    (void)len;

    /* SESSION STREAM */
    if (strcmp(queue, "sync.session") == 0)
    {
        const UserSessionInfo *s = (const UserSessionInfo *)data;

        restore_session(session_map, s);
        state->sessions_loaded = 1;
        state->has_session_state = 1;
        return;
    }

    /* CGNAT STREAM */
    if (strcmp(queue, "sync.cgnat") == 0)
    {
        const CgnatEntry *e = (const CgnatEntry *)data;

        CgnatNode *n = malloc(sizeof(CgnatNode));
        memset(n, 0, sizeof(*n));
        strcpy(n->inside_ip, e->inside_ip);
        n->entry = *e;

        HASH_ADD_STR(*cgnat_map, inside_ip, n);
        state->cgnat_loaded = 1;
        return;
    }

    /* WHITELIST STREAM */
    if (strcmp(queue, "sync.whitelist") == 0)
    {
        const WhitelistInfo *w = (const WhitelistInfo *)data;

        WlNode *n = malloc(sizeof(WlNode));
        memset(n, 0, sizeof(*n));
        strcpy(n->msisdn, w->msisdn);
        n->info = *w;

        HASH_ADD_STR(*wl_map, msisdn, n);
        state->whitelist_loaded = 1;
        return;
    }
}

/* =========================================================
 * CLUSTER SYNC STREAM
 * ========================================================= */
int rabbitmq_publish_cgnat_sync(RabbitMQClient *c, const CgnatEntry *e)
{
    return rabbitmq_publish_raw(c, g_rabbitmq.cfg.exchange, RK_SYNC_CGNAT, e, sizeof(*e));
}

int rabbitmq_publish_whitelist_sync(RabbitMQClient *c, const WhitelistInfo *w)
{
    return rabbitmq_publish_raw(c, g_rabbitmq.cfg.exchange, RK_SYNC_WHITELIST, w, sizeof(*w));
}

int rabbitmq_publish_session_sync(RabbitMQClient *c, const UserSessionInfo *s)
{
    return rabbitmq_publish_raw(c, g_rabbitmq.cfg.exchange, RK_SYNC_SESSION, s, sizeof(*s));
}

/* =========================================================
 * CLEANUP
 * ========================================================= */
void rabbitmq_cleanup(RabbitMQClient *c)
{
    if (!c)
        return;

    amqp_channel_close(c->conn, c->channel, AMQP_REPLY_SUCCESS);
    amqp_connection_close(c->conn, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(c->conn);
}

int rabbitmq_consume_sync_queue(RabbitMQClient *c, const char *queue, RabbitMQSyncHandler handler, void *ctx)
{
    amqp_basic_consume(c->conn, c->channel, amqp_cstring_bytes(queue), amqp_empty_bytes, 0, 1, 0, amqp_empty_table);
    amqp_rpc_reply_t r = amqp_get_rpc_reply(c->conn);
    if (r.reply_type != AMQP_RESPONSE_NORMAL)
        return -1;

    while (1)
    {
        amqp_envelope_t envelope;
        amqp_maybe_release_buffers(c->conn);

        struct timeval timeout = {0, 200000}; // 200ms
        amqp_rpc_reply_t res = amqp_consume_message(c->conn, &envelope, &timeout, 0);

        if (res.reply_type != AMQP_RESPONSE_NORMAL)
            break;

        handler(queue, envelope.message.body.bytes, envelope.message.body.len, ctx);
        amqp_destroy_envelope(&envelope);
    }

    return 0;
}

int rabbitmq_bootstrap_state(RabbitMQClient *client, SessionNode **session_map, CgnatNode **cgnat_map, WlNode **wl_map, RabbitMQBootstrapState *state)
{
    memset(state, 0, sizeof(*state));

    RabbitMQBootstrapCtx ctx = {
        .session_map = session_map,
        .cgnat_map = cgnat_map,
        .wl_map = wl_map,
        .state = state};

    rabbitmq_consume_sync_queue(client, "sync.session", handle_boot_message, &ctx);
    rabbitmq_consume_sync_queue(client, "sync.cgnat", handle_boot_message, &ctx);
    rabbitmq_consume_sync_queue(client, "sync.whitelist", handle_boot_message, &ctx);

    state->has_session_state = (state->sessions_loaded > 0);

    return 0;
}