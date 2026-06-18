#include "modules/mysql/db.h"

/* globals */
extern RabbitMQClient g_rabbitmq;
extern RabbitPublishQueue g_publish_queue;
// extern pthread_mutex_t g_rabbitmq_sync_mutex;
// extern pthread_mutex_t g_rabbitmq_pub_mutex;
// extern pthread_mutex_t g_rabbitmq_stat_mutex;

/* -------- lifecycle -------- */
int rabbitmq_init(const RabbitMQConfig *cfg);
void rabbitmq_cleanup(RabbitMQClient *client);

/* -------- publish -------- */
int rabbitmq_publish_session_start(RabbitMQClient *c, const UserSessionInfo *s);
int rabbitmq_publish_session_stop(RabbitMQClient *c, const UserSessionInfo *s);
int rabbitmq_publish_session_sync(RabbitMQClient *c, const UserSessionInfo *s);
int rabbitmq_publish_session_delete(RabbitMQClient *c, const char *session_id);

/* -------- bootstrap / one‑time replay -------- */
int rabbitmq_bootstrap_state(RabbitMQClient *client, SessionNode **session_map);

/* -------- permanent consumer threads (to be launched by main) -------- */
void *rabbitmq_publish_worker(void *arg);
void *rabbitmq_stats_worker(void *arg);