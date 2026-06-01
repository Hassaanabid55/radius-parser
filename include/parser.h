#include "modules/rabbitmq/rabbitmq_producer.h"

extern SessionNode *g_session_map;
extern bool opt_extract_all;
extern volatile sig_atomic_t g_running;
extern uint32_t opt_update_timeout;

static inline int logInvalidAvp(uint8_t type, uint8_t len, uint16_t offset)
{
    syslog(LOG_ERR, "Invalid AVP - Type=%u Len=%u Offset=%u", type, len, offset);
    return -1;
}

static inline void ipv4_to_str(const uint8_t ip[4], char out[16])
{
    snprintf(out, 16, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

static inline SessionNode *session_find_locked(const char *id)
{
    SessionNode *node = NULL;
    HASH_FIND_STR(g_session_map, id, node);
    return node;
}

static inline SessionNode *session_find(const char *id)
{
    if (!id)
        return NULL;

    pthread_mutex_lock(&g_session_mutex);
    SessionNode *node = session_find_locked(id);
    pthread_mutex_unlock(&g_session_mutex);
    return node;
}

static inline int session_insert(const UserSessionInfo *s)
{
    if (!s) return -1;

    SessionNode *node = malloc(sizeof(SessionNode));
    if (!node) return -1;

    memset(node, 0, sizeof(*node));
    memcpy(node->acAccountSessionId,           s->acAccountSessionId,           sizeof(node->acAccountSessionId) - 1);
    node->entry = *s;
    int is_new = 0;
    pthread_mutex_lock(&g_session_mutex);
    SessionNode *existing = NULL;
    HASH_FIND_STR(g_session_map, node->acAccountSessionId, existing);

    if (existing)
    {
        existing->entry = *s;
        free(node);
    }
    else
    {
        HASH_ADD_STR(g_session_map, acAccountSessionId, node);
        is_new = 1;
    }

    pthread_mutex_unlock(&g_session_mutex);
    /* OUTSIDE LOCK → safe */
    if (is_new)
        rabbitmq_publish_session_sync(&g_rabbitmq, s);

    return is_new ? 0 : 1;
}

static inline void session_delete(SessionNode *node)
{
    if (!node) return;

    char id_copy[SESSION_ID_MAX_LEN];
    strncpy(id_copy, node->acAccountSessionId, sizeof(id_copy));

    pthread_mutex_lock(&g_session_mutex);
    HASH_DEL(g_session_map, node);
    pthread_mutex_unlock(&g_session_mutex);
    free(node);
    /* OUTSIDE LOCK */
    rabbitmq_publish_session_delete(&g_rabbitmq, id_copy);
}

void session_print_stats();
void *session_timeout_thread(void *arg);
const char *getIpLayer(const char *pPacket, size_t len);
const char *getUdpLayer(const char *pIpLayer, size_t len);
uint16_t getUdpDstPort(const char *pStartOfUdpLayer);
const char *getRadiusAcctLayer(const char *pPacket, size_t len);
void setCurrentLocalTime(struct tm *sTime);
int sessionStart(UserSessionInfo *pSession);
int sessionEnd(UserSessionInfo *pSession);
int parseRadiusPkt(const char *pPacket, size_t len, RadiusPacket *radiusPkt);
int readRadiusAttributes(const RadiusPacket *radiusPkt, UserSessionInfo *pSession);