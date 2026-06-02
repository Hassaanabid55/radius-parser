#include "modules/mysql/db.h"

/* globals */
extern RabbitMQClient g_rabbitmq;
extern pthread_mutex_t g_rabbitmq_mutex;
extern volatile sig_atomic_t g_running;

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
void *rabbitmq_stats_worker(void *arg);