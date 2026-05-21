#pragma once

#include <amqp.h>
#include <amqp_tcp_socket.h>
#include <stdint.h>
#include <sys/time.h>
#include <stdbool.h>

#include "modules/mysql/db.h"

/* =========================================================
 * CONFIG
 * ========================================================= */
typedef struct
{
    char host[128];
    char vhost[64];
    char user[64];
    char password[64];
    char exchange[64];
    uint16_t port;

} RabbitMQConfig;

/* =========================================================
 * CLIENT
 * ========================================================= */
typedef struct
{
    amqp_connection_state_t conn;
    amqp_socket_t *socket;
    int channel;
    RabbitMQConfig cfg;

} RabbitMQClient;

typedef struct
{
    int sessions_loaded;
    int cgnat_loaded;
    int whitelist_loaded;
    int has_session_state;

} RabbitMQBootstrapState;

typedef void (*RabbitMQSyncHandler)(
    const char *routing_key,
    const void *body,
    size_t len,
    void *ctx);

typedef struct RabbitMQBootstrapCtx
{
    SessionNode **session_map;
    CgnatNode **cgnat_map;
    WlNode **wl_map;
    RabbitMQBootstrapState *state;
} RabbitMQBootstrapCtx;

extern RabbitMQClient g_rabbitmq;
extern pthread_mutex_t g_rabbitmq_mutex;

int rabbitmq_bootstrap_state(RabbitMQClient *client, SessionNode **session_map, CgnatNode **cgnat_map, WlNode **wl_map, RabbitMQBootstrapState *state);

/* =========================================================
 * INIT / CLEANUP
 * ========================================================= */
int rabbitmq_init(const RabbitMQConfig *cfg);
void rabbitmq_cleanup(RabbitMQClient *client);

/* =========================================================
 * 1. SESSION EVENT STREAM (START / UPDATE / STOP)
 * ========================================================= */
int rabbitmq_publish_session_start(RabbitMQClient *c, const UserSessionInfo *s);
int rabbitmq_publish_session_update(RabbitMQClient *c, const UserSessionInfo *s);
int rabbitmq_publish_session_stop(RabbitMQClient *c, const UserSessionInfo *s);

/* =========================================================
 * 2. ANALYTICS STREAM (external consumer)
 * ========================================================= */
int rabbitmq_publish_session_stats(RabbitMQClient *c, const UserSessionInfo *s);

/* =========================================================
 * 3. CLUSTER STATE SYNC
 * ========================================================= */
int rabbitmq_publish_cgnat_sync(RabbitMQClient *c, const CgnatEntry *e);
int rabbitmq_publish_whitelist_sync(RabbitMQClient *c, const WhitelistInfo *w);
int rabbitmq_publish_session_sync(RabbitMQClient *c, const UserSessionInfo *s);

/* =========================================================
 * INTERNAL HELPERS
 * ========================================================= */
int rabbitmq_publish_raw(RabbitMQClient *c, const char *exchange, const char *routing_key, const void *data, size_t len);