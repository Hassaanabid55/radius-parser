#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <sys/syslog.h>
#include <time.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "user_session.h"
#include "uthash.h"
#include "modules/cgnat/whitelist_handler.h"
#include "modules/cgnat/cgnat_handler.h"

typedef struct
{
    const uint8_t *pData;
    const uint8_t *pPayload;
    uint16_t length;
    uint16_t payloadLen;
    uint8_t code;
    uint8_t identifier;
} RadiusPacket;

typedef struct SessionNode
{
    char acAccountSessionId[SESSION_ID_MAX_LEN];
    UserSessionInfo entry;
    UT_hash_handle hh;
} SessionNode;

extern SessionNode *g_session_map;
extern pthread_mutex_t g_session_mutex;
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
    if (!s)
        return -1;

    SessionNode *node = malloc(sizeof(SessionNode));
    if (!node)
        return -1;

    memset(node, 0, sizeof(*node));
    memcpy(node->acAccountSessionId, s->acAccountSessionId, sizeof(node->acAccountSessionId) - 1);
    node->entry = *s;
    pthread_mutex_lock(&g_session_mutex);
    SessionNode *existing = NULL;
    HASH_FIND_STR(g_session_map, node->acAccountSessionId, existing);
    if (existing)
    {
        existing->entry = *s;
        pthread_mutex_unlock(&g_session_mutex);
        free(node);
        return 1;
    }
    HASH_ADD_STR(g_session_map, acAccountSessionId, node);
    pthread_mutex_unlock(&g_session_mutex);
    return 0;
}

static inline void session_delete(SessionNode *node)
{
    if (!node)
        return;

    pthread_mutex_lock(&g_session_mutex);
    HASH_DEL(g_session_map, node);
    pthread_mutex_unlock(&g_session_mutex);
    free(node);
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