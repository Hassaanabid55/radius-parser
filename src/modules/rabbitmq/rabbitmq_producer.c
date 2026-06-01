#include "modules/rabbitmq/rabbitmq_producer.h"

RabbitMQClient g_rabbitmq;
pthread_mutex_t g_rabbitmq_mutex = PTHREAD_MUTEX_INITIALIZER;

extern SessionNode *g_session_map;
extern pthread_mutex_t g_session_mutex;

/* =========================================================
 * SAFE PUBLISH
 * ========================================================= */
static int rabbitmq_publish_locked(RabbitMQClient *c, const char *exchange, const char *routing_key, const void *data, size_t len)
{
    amqp_bytes_t body = {
        .len = len,
        .bytes = (void *)data};

    pthread_mutex_lock(&g_rabbitmq_mutex);
    int rc = amqp_basic_publish(c->conn, c->channel, amqp_cstring_bytes(exchange), amqp_cstring_bytes(routing_key), 0, 0, NULL, body);
    pthread_mutex_unlock(&g_rabbitmq_mutex);

    return rc == 0;
}

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

    amqp_exchange_declare(g_rabbitmq.conn, g_rabbitmq.channel, amqp_cstring_bytes(cfg->exchange), amqp_cstring_bytes("direct"), 0, 1, 0, 0, amqp_empty_table);
    return 1;
}

/* =========================================================
 * RAW PUBLISH
 * ========================================================= */
int rabbitmq_publish_raw(RabbitMQClient *c, const char *exchange, const char *routing_key, const void *data, size_t len)
{
    return rabbitmq_publish_locked(c, exchange, routing_key, data, len);
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
 * SYNC STREAM (STATE MODEL)
 * ========================================================= */
int rabbitmq_publish_session_sync(RabbitMQClient *c, const UserSessionInfo *s)
{
    return rabbitmq_publish_raw(c, g_rabbitmq.cfg.exchange, RK_SYNC_SESSION, s, sizeof(*s));
}

int rabbitmq_publish_session_delete(RabbitMQClient *c, const char *session_id)
{
    return rabbitmq_publish_raw(c, g_rabbitmq.cfg.exchange, RK_SYNC_SESSION_DELETE, session_id, strlen(session_id) + 1);
}

/* =========================================================
 * STATS STREAM
 * ========================================================= */
int rabbitmq_publish_session_stats(RabbitMQClient *c, const UserSessionInfo *s)
{
    return rabbitmq_publish_raw(c, g_rabbitmq.cfg.exchange, RK_SESSION_STATS, s, sizeof(*s));
}

/* =========================================================
 * SESSION RESTORE
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
        node = calloc(1, sizeof(SessionNode));
        strcpy(node->acAccountSessionId, s->acAccountSessionId);
        node->entry = *s;
        HASH_ADD_STR(*map, acAccountSessionId, node);
    }

    pthread_mutex_unlock(&g_session_mutex);
}

/* =========================================================
 * HANDLER
 * ========================================================= */
static void handle_boot_message(const char *queue, const void *data, size_t len, void *ctx)
{
    RabbitMQBootstrapCtx *boot = ctx;

    if (strcmp(queue, RK_SYNC_SESSION) == 0)
    {
        if (len != sizeof(UserSessionInfo))
            return;

        restore_session(boot->session_map, data);
        boot->state->sessions_loaded = 1;
        return;
    }

    if (strcmp(queue, RK_SYNC_SESSION_DELETE) == 0)
    {
        const char *id = data;

        pthread_mutex_lock(&g_session_mutex);

        SessionNode *node = NULL;
        HASH_FIND_STR(*boot->session_map, id, node);

        if (node)
        {
            HASH_DEL(*boot->session_map, node);
            free(node);
        }

        pthread_mutex_unlock(&g_session_mutex);
    }
}

/* =========================================================
 * CONSUMER (FIXED DECLARED + DEFINED)
 * ========================================================= */
int rabbitmq_consume_sync_queue(RabbitMQClient *c, const char *queue, RabbitMQSyncHandler handler, void *ctx)
{
    pthread_mutex_lock(&g_rabbitmq_mutex);

    amqp_basic_consume(c->conn, c->channel, amqp_cstring_bytes(queue), amqp_empty_bytes, 0, 1, 0, amqp_empty_table);
    if (amqp_get_rpc_reply(c->conn).reply_type != AMQP_RESPONSE_NORMAL)
    {
        pthread_mutex_unlock(&g_rabbitmq_mutex);
        return -1;
    }

    pthread_mutex_unlock(&g_rabbitmq_mutex);

    while (g_running)
    {
        amqp_envelope_t env;
        struct timeval tv = {0, 200000};

        pthread_mutex_lock(&g_rabbitmq_mutex);
        amqp_rpc_reply_t res = amqp_consume_message(c->conn, &env, &tv, 0);
        pthread_mutex_unlock(&g_rabbitmq_mutex);

        if (res.reply_type != AMQP_RESPONSE_NONE)
            break;

        if (res.reply_type != AMQP_RESPONSE_NORMAL)
            continue;

        handler(queue, env.message.body.bytes, env.message.body.len, ctx);
        amqp_destroy_envelope(&env);
    }

    return 0;
}

/* =========================================================
 * BOOTSTRAP (DRY READ ONLY)
 * ========================================================= */
int rabbitmq_bootstrap_state(RabbitMQClient *client, SessionNode **session_map, RabbitMQBootstrapState *state)
{
    memset(state, 0, sizeof(*state));
    RabbitMQBootstrapCtx ctx = {
        .session_map = session_map,
        .state = state};

    rabbitmq_consume_sync_queue(client, RK_SYNC_SESSION, handle_boot_message, &ctx);
    rabbitmq_consume_sync_queue(client, RK_SYNC_SESSION_DELETE, handle_boot_message, &ctx);

    state->sessions_loaded = 1;
    return 0;
}

/* =========================================================
 * STATS
 * ========================================================= */

void *rabbitmq_stats_worker(void *arg)
{
    (void)arg;

    amqp_basic_consume(g_rabbitmq.conn, g_rabbitmq.channel, amqp_cstring_bytes(RK_SESSION_STATS), amqp_empty_bytes, 0, 1, 0, amqp_empty_table);
    if (amqp_get_rpc_reply(g_rabbitmq.conn).reply_type != AMQP_RESPONSE_NORMAL)
        return NULL;

    while (g_running)
    {
        amqp_envelope_t env;
        struct timeval tv = {0, 200000};

        pthread_mutex_lock(&g_rabbitmq_mutex);
        amqp_rpc_reply_t res = amqp_consume_message(g_rabbitmq.conn, &env, &tv, 0);
        pthread_mutex_unlock(&g_rabbitmq_mutex);

        if (res.reply_type != AMQP_RESPONSE_NORMAL)
            continue;

        if (env.message.body.len == sizeof(UserSessionInfo))
        {
            const UserSessionInfo *s = (const UserSessionInfo *)env.message.body.bytes;

            pthread_mutex_lock(&g_session_mutex);

            SessionNode *node = NULL;
            HASH_FIND_STR(g_session_map, s->acAccountSessionId, node);

            if (node)
                node->entry.packet_count = s->packet_count;

            pthread_mutex_unlock(&g_session_mutex);
        }

        amqp_destroy_envelope(&env);
    }

    return NULL;
}

/* =========================================================
 * CLEANUP
 * ========================================================= */
void rabbitmq_cleanup(RabbitMQClient *c)
{
    if (!c)
        return;

    pthread_mutex_lock(&g_rabbitmq_mutex);

    amqp_channel_close(c->conn, c->channel, AMQP_REPLY_SUCCESS);
    amqp_connection_close(c->conn, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(c->conn);

    pthread_mutex_unlock(&g_rabbitmq_mutex);
}