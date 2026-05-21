#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/syslog.h>
#include <pthread.h>
#include <time.h>
#include <stdarg.h>
#include <arpa/inet.h>

#include "uthash.h"

#include "modules/cgnat/whitelist_handler.h"

extern bool opt_extract_all;

typedef struct
{
    uint8_t type;
    uint8_t len;
    uint8_t value[MAX_AVP_VALUE];
} extra_avps;

typedef struct
{
    /* ================= FAST MODE FIELDS ================= */
    uint64_t u64ValidAttributes;
    uint32_t u32EventTimestamp;
    uint8_t u8AccountStatusType;
    char acAccountSessionId[SESSION_ID_MAX_LEN];
    char acMultiSessionId[SESSION_ID_MAX_LEN];
    uint8_t u8FramedIpv4Address[IPV4_OCTETS];
    uint8_t u8FramedIpv6Prefix[IPV6_PREFIX_MAX_LEN];
    char acCallingStationId[32];
    uint8_t u8IsWL;
    uint8_t u8FramedIpv4PubAddress[IPV4_OCTETS];
    uint16_t portStart;
    uint16_t portEnd;
    uint32_t packet_count;
    struct tm sSessionStartTime;
    struct tm sSessionEndTime;
    uint32_t destroy_time;
    /* ================= OPTIONAL AVPS ================= */
    uint16_t extra_avp_count;
    extra_avps extra_avps[MAX_EXTRA_AVPS];
} UserSessionInfo;

typedef struct SessionNode
{
    char acAccountSessionId[SESSION_ID_MAX_LEN];
    UserSessionInfo entry;
    UT_hash_handle hh;
} SessionNode;

/* =========================================================
 * SESSION TYPE STRING
 * ========================================================= */
static inline const char *session_type_str(uint8_t type)
{
    switch (type)
    {
    case SESSION_START:
        return "START";

    case SESSION_STOP:
        return "STOP";

    case SESSION_UPDATE:
        return "UPDATE";

    default:
        return "UNKNOWN";
    }
}

extern SessionNode *g_session_map;
extern pthread_mutex_t g_session_mutex;

void printUserSession(const UserSessionInfo *pSession);