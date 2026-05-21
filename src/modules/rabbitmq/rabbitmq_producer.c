#include "modules/rabbitmq/rabbitmq_producer.h"

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
    amqp_exchange_declare(g_rabbitmq.conn, g_rabbitmq.channel, amqp_cstring_bytes(g_rabbitmq.cfg.exchange), amqp_cstring_bytes("direct"), 0, 1, 0, 0, amqp_empty_table);

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