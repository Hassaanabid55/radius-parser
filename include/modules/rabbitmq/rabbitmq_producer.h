#include "modules/mysql/db.h"

/* globals */
extern RabbitMQClient g_rabbitmq;
extern pthread_mutex_t g_rabbitmq_mutex;
extern volatile sig_atomic_t g_running;

/* ================= INIT ================= */
int rabbitmq_init(const RabbitMQConfig *cfg);
void rabbitmq_cleanup(RabbitMQClient *client);

/* ================= PUBLISH (EVENT STREAM) ================= */
int rabbitmq_publish_session_start(RabbitMQClient *c, const UserSessionInfo *s);
int rabbitmq_publish_session_stop(RabbitMQClient *c, const UserSessionInfo *s);

/* ================= STATS STREAM ================= */
int rabbitmq_publish_session_stats(RabbitMQClient *c, const UserSessionInfo *s);

/* ================= CLUSTER SYNC (STATE MODEL) ================= */
int rabbitmq_publish_session_sync(RabbitMQClient *c, const UserSessionInfo *s);
int rabbitmq_publish_session_delete(RabbitMQClient *c, const char *session_id);

/* ================= BOOTSTRAP ================= */
int rabbitmq_bootstrap_state(RabbitMQClient *client, SessionNode **session_map, RabbitMQBootstrapState *state);

/* ================= CONSUMERS ================= */
void *rabbitmq_stats_worker(void *arg);

/* ================= INTERNAL ================= */
int rabbitmq_publish_raw(RabbitMQClient *c, const char *exchange, const char *routing_key, const void *data, size_t len);
int rabbitmq_consume_sync_queue(RabbitMQClient *c, const char *queue, RabbitMQSyncHandler handler, void *ctx);