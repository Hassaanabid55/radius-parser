#include "modules/rabbitmq/rabbitmq_producer.h"

/* ================= GLOBALS ================= */
RabbitMQClient g_rabbitmq;
RabbitPublishQueue g_publish_queue;
// pthread_mutex_t g_rabbitmq_sync_mutex = PTHREAD_MUTEX_INITIALIZER;
// pthread_mutex_t g_rabbitmq_pub_mutex = PTHREAD_MUTEX_INITIALIZER;
// pthread_mutex_t g_rabbitmq_stat_mutex = PTHREAD_MUTEX_INITIALIZER;

/* external session map */
extern SessionNode *g_session_map;
extern pthread_mutex_t g_session_mutex;
extern volatile int g_running;

/* =========================================================
   INTERNAL HELPERS
   ========================================================= */

/* -------- thread‑safe publish -------- */
int rabbitmq_publish(RabbitMQClient *c, const char *routing_key, const void *data, size_t len)
{
    if (!c || !c->conn)
        return 0;

    amqp_bytes_t body = {
        .len = len,
        .bytes = (void *)data};

    /* IMPORTANT: fully zero-initialize */
    amqp_basic_properties_t props;
    memset(&props, 0, sizeof(props));
    props._flags = AMQP_BASIC_DELIVERY_MODE_FLAG;
    props.delivery_mode = 2;

    int rc = amqp_basic_publish(c->conn, c->pub_channel, amqp_cstring_bytes(c->cfg.exchange), amqp_cstring_bytes(routing_key), 0, 0, &props, body);

    return (rc == 0);
}

/* =========================================================
   INIT – no queue/exchange declarations
   ========================================================= */
int rabbitmq_init(const RabbitMQConfig *cfg)
{
    memset(&g_rabbitmq, 0, sizeof(g_rabbitmq));
    g_rabbitmq.cfg = *cfg;

    rabbitmq_publish_queue_init();

    g_rabbitmq.conn = amqp_new_connection();
    amqp_socket_t *socket = amqp_tcp_socket_new(g_rabbitmq.conn);
    if (!socket)
        return 0;

    if (amqp_socket_open(socket, cfg->host, cfg->port))
        return 0;

    amqp_rpc_reply_t r = amqp_login(g_rabbitmq.conn, cfg->vhost, 0, 131072, 60, AMQP_SASL_METHOD_PLAIN, cfg->user, cfg->password);
    if (r.reply_type != AMQP_RESPONSE_NORMAL)
        return 0;

    g_rabbitmq.pub_channel = 1;
    amqp_channel_open(g_rabbitmq.conn, 1);
    if (amqp_get_rpc_reply(g_rabbitmq.conn).reply_type != AMQP_RESPONSE_NORMAL)
        return 0;

    g_rabbitmq.stats_channel = 2;
    amqp_channel_open(g_rabbitmq.conn, 2);
    if (amqp_get_rpc_reply(g_rabbitmq.conn).reply_type != AMQP_RESPONSE_NORMAL)
        return 0;

    g_rabbitmq.sync_channel = 3;
    amqp_channel_open(g_rabbitmq.conn, 3);
    if (amqp_get_rpc_reply(g_rabbitmq.conn).reply_type != AMQP_RESPONSE_NORMAL)
        return 0;

    return 1;
}

void rabbitmq_publish_queue_init(void)
{
    memset(&g_publish_queue, 0, sizeof(g_publish_queue));

    pthread_mutex_init(&g_publish_queue.mutex, NULL);
    pthread_cond_init(&g_publish_queue.cond, NULL);
}

/* =========================================================
   CLEANUP
   ========================================================= */
void rabbitmq_cleanup(RabbitMQClient *c)
{
    if (!c || !c->conn)
        return;

    amqp_channel_close(c->conn, c->pub_channel, AMQP_REPLY_SUCCESS);

    amqp_channel_close(c->conn, c->stats_channel, AMQP_REPLY_SUCCESS);

    amqp_channel_close(c->conn, c->sync_channel, AMQP_REPLY_SUCCESS);

    amqp_connection_close(c->conn, AMQP_REPLY_SUCCESS);
    amqp_destroy_connection(c->conn);
}

/* =========================================================
   HIGH‑LEVEL PUBLISH
   ========================================================= */
int rabbitmq_enqueue(
    const char *routing_key,
    const void *data,
    size_t len)
{
    RabbitPublishEvent *evt =
        calloc(1, sizeof(*evt));

    if (!evt)
        return 0;

    strcpy(evt->routing_key, routing_key);

    evt->len = len;

    if (strcmp(routing_key, RK_SYNC_SESSION_DELETE) == 0)
    {
        strncpy(
            evt->session_id,
            (const char *)data,
            sizeof(evt->session_id) - 1);
    }
    else
    {
        memcpy(
            &evt->session,
            data,
            sizeof(UserSessionInfo));
    }

    pthread_mutex_lock(&g_publish_queue.mutex);

    if (!g_publish_queue.tail)
    {
        g_publish_queue.head =
            g_publish_queue.tail = evt;
    }
    else
    {
        g_publish_queue.tail->next = evt;
        g_publish_queue.tail = evt;
    }

    pthread_cond_signal(&g_publish_queue.cond);

    pthread_mutex_unlock(&g_publish_queue.mutex);

    return 1;
}

int rabbitmq_publish_session_start(RabbitMQClient *c, const UserSessionInfo *s)
{
    return rabbitmq_enqueue(RK_SESSION_START, s, sizeof(*s));
}
int rabbitmq_publish_session_stop(RabbitMQClient *c, const UserSessionInfo *s)
{
    return rabbitmq_enqueue(RK_SESSION_STOP, s, sizeof(*s));
}
int rabbitmq_publish_session_sync(RabbitMQClient *c, const UserSessionInfo *s)
{
    return rabbitmq_enqueue(RK_SYNC_SESSION, s, sizeof(*s));
}
int rabbitmq_publish_session_delete(RabbitMQClient *c, const char *session_id)
{
    return rabbitmq_enqueue(RK_SYNC_SESSION_DELETE, session_id, strlen(session_id) + 1);
}

/* =========================================================
   BOOTSTRAP – drain existing messages with basic_get
   ========================================================= */
/* Function to restore / delete */
static void bootstrap_handler(const char *queue, const void *data, size_t len, void *ctx_ptr)
{
    struct
    {
        SessionNode **map;
    } *c = ctx_ptr;

    if (strcmp(queue, RK_SYNC_SESSION) == 0)
    {
        if (len != sizeof(UserSessionInfo))
            return;
        const UserSessionInfo *s = data;

        pthread_mutex_lock(&g_session_mutex);
        SessionNode *node = NULL;
        HASH_FIND_STR(*c->map, s->acAccountSessionId, node);

        if (!node)
        {
            node = calloc(1, sizeof(SessionNode));
            strcpy(node->acAccountSessionId, s->acAccountSessionId);
            node->entry = *s;
            HASH_ADD_STR(*c->map, acAccountSessionId, node);
            g_session_count++;
            g_session_total_restores++;
        }
        else
        {
            /* Only overwrite if newer */
            if (s->u32EventTimestamp > node->entry.u32EventTimestamp)
                node->entry = *s;
        }
        pthread_mutex_unlock(&g_session_mutex);
    }
    else if (strcmp(queue, RK_SYNC_SESSION_DELETE) == 0)
    {
        const char *id = data;

        pthread_mutex_lock(&g_session_mutex);
        SessionNode *node = NULL;
        HASH_FIND_STR(*c->map, id, node);
        if (node)
        {
            HASH_DEL(*c->map, node);
            if (g_session_count > 0)
                g_session_count--;
            g_session_total_deletes++;
            free(node);
        }
        pthread_mutex_unlock(&g_session_mutex);
    }
}

static int drain_sync_queue(
    RabbitMQClient *c,
    const char *queue,
    RabbitMQSyncHandler handler,
    void *ctx)
{
    amqp_basic_consume(c->conn, c->sync_channel, amqp_cstring_bytes(queue), amqp_empty_bytes, 1, 0, 0, amqp_empty_table);
    amqp_rpc_reply_t reply = amqp_get_rpc_reply(c->conn);

    if (reply.reply_type != AMQP_RESPONSE_NORMAL)
        return -1;

    while (1)
    {
        amqp_envelope_t env;
        struct timeval timeout = {2, 0};

        amqp_rpc_reply_t res = amqp_consume_message(c->conn, &env, &timeout, 0);

        if (res.reply_type == AMQP_RESPONSE_NONE)
        {
            syslog(LOG_INFO, "Finished draining queue 1: %s", queue);
            break;
        }
        if (res.reply_type != AMQP_RESPONSE_NORMAL)
        {
            syslog(LOG_INFO, "Finished draining queue 2: %s with response: %d and library error: %d", queue, res.reply_type, res.library_error);
            break;
        }

        handler(queue, env.message.body.bytes, env.message.body.len, ctx);

        amqp_destroy_envelope(&env);
    }

    amqp_basic_cancel(c->conn, c->sync_channel, amqp_empty_bytes);

    return 0;
}

int rabbitmq_bootstrap_state(RabbitMQClient *client, SessionNode **session_map)
{
    /* The handler that will be called for each message */
    struct
    {
        SessionNode **map;
    } ctx = {.map = session_map};

    /* Drain both sync queues in order */
    if (drain_sync_queue(client, RK_SYNC_SESSION, bootstrap_handler, &ctx) != 0)
        return -1;
    if (drain_sync_queue(client, RK_SYNC_SESSION_DELETE, bootstrap_handler, &ctx) != 0)
        return -1;

    syslog(LOG_INFO, "RabbitMQ: bootstrap completed");
    return 0;
}

void *rabbitmq_publish_worker(void *arg)
{
    while (g_running)
    {
        pthread_mutex_lock(&g_publish_queue.mutex);

        while (!g_publish_queue.head && g_running)
        {
            pthread_cond_wait(
                &g_publish_queue.cond,
                &g_publish_queue.mutex);
        }

        if (!g_running)
        {
            pthread_mutex_unlock(
                &g_publish_queue.mutex);
            break;
        }

        RabbitPublishEvent *evt =
            g_publish_queue.head;

        g_publish_queue.head =
            evt->next;

        if (!g_publish_queue.head)
            g_publish_queue.tail = NULL;

        pthread_mutex_unlock(
            &g_publish_queue.mutex);

        rabbitmq_publish(
            &g_rabbitmq,
            evt->routing_key,
            strcmp(evt->routing_key, RK_SYNC_SESSION_DELETE) == 0
                ? (void *)evt->session_id
                : (void *)&evt->session,
            evt->len);

        free(evt);
    }

    return NULL;
}

/* =========================================================
   STATS CONSUMER (permanent thread)
   ========================================================= */
void *rabbitmq_stats_worker(void *arg)
{
    (void)arg;
    RabbitMQClient *c = &g_rabbitmq;

RECONNECT:

    amqp_basic_consume(c->conn, c->stats_channel, amqp_cstring_bytes(RK_SESSION_STATS), amqp_empty_bytes, 0, 1, 0, amqp_empty_table);
    amqp_rpc_reply_t reply = amqp_get_rpc_reply(c->conn);

    if (reply.reply_type != AMQP_RESPONSE_NORMAL)
    {
        syslog(LOG_ERR, "stats worker: basic_consume failed");
        return NULL;
    }

    while (g_running)
    {
        amqp_envelope_t env;
        struct timeval tv = {2, 0};

        /* BLOCKING CALL → real standby */
        amqp_rpc_reply_t res = amqp_consume_message(c->conn, &env, &tv, 0);

        if (!g_running)
            break;

        if (res.reply_type != AMQP_RESPONSE_NORMAL)
        {
            syslog(LOG_ERR, "stats worker: consume error → reconnecting");
            sleep(1);
            goto RECONNECT;
        }

        if (env.message.body.len == sizeof(UserSessionInfo))
        {
            const UserSessionInfo *s =
                (const UserSessionInfo *)env.message.body.bytes;

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