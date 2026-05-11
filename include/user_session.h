#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <sys/syslog.h>
#include <time.h>
#include <arpa/inet.h>

#include "radius_attribute_list.h"

extern bool opt_extract_all;

typedef struct
{
    uint8_t type;
    uint8_t len;
    uint8_t value[MAX_AVP_VALUE];
} extra_avps;

typedef struct
{
    // ================= FAST MODE FIELDS =================
    int nSessionIndicator;
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
    struct tm sSessionStartTime;
    struct tm sSessionEndTime;
    // ================= FULL MODE STORAGE =================
    uint16_t extra_avp_count;
    extra_avps extra_avps[MAX_EXTRA_AVPS];
} UserSessionInfo;

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

static inline void print_string_field(const char *label, const char *value, int valid)
{
    syslog(LOG_INFO, "│ %-24s : %s", label, valid ? value : "[not present]");
}

static inline void print_uint_field(const char *label, uint32_t value, int valid)
{
    if (__builtin_expect(valid, 1))
    {
        syslog(LOG_INFO, "│ %-24s : %u", label, value);
    }
    else
    {
        syslog(LOG_INFO, "│ %-24s : [not present]", label);
    }
}

static inline void print_ipv4_field(const char *label, const uint8_t *ip, int valid)
{
    if (__builtin_expect(valid, 1))
    {
        syslog(LOG_INFO, "│ %-24s : %u.%u.%u.%u", label, ip[0], ip[1], ip[2], ip[3]);
    }
    else
    {
        syslog(LOG_INFO, "│ %-24s : [not present]", label);
    }
}

static inline void print_ipv6_prefix_field(const char *label, const uint8_t *prefix, int valid)
{
    if (__builtin_expect(!valid, 0))
    {
        syslog(LOG_INFO, "│ %-24s : [not present]", label);
        return;
    }

    char ip6[INET6_ADDRSTRLEN];

    inet_ntop(AF_INET6, prefix + 2, ip6, sizeof(ip6));
    syslog(LOG_INFO, "│ %-24s : %s/%u", label, ip6, prefix[1]);
}

static inline void print_timestamp(uint32_t epoch, int valid)
{
    if (__builtin_expect(!valid, 0))
    {
        syslog(LOG_INFO, "│ %-24s : [not present]", "Event Timestamp");
        return;
    }
    struct tm tm_info;
    time_t t = (time_t)epoch;
    localtime_r(&t, &tm_info);
    char buf[32];
    strftime(buf, sizeof(buf), "%Y-%m-%d %H:%M:%S", &tm_info);
    syslog(LOG_INFO, "│ %-24s : %u", "Event Timestamp", epoch);
    syslog(LOG_INFO, "│ %-24s : %s", "Event Time", buf);
}

static inline void print_port_range(const UserSessionInfo *s)
{
    if (__builtin_expect((s->portStart != 0 || s->portEnd != 0), 1))
    {
        syslog(LOG_INFO, "│ %-24s : %u - %u", "NAT Port Range", s->portStart, s->portEnd);
    }
    else
    {
        syslog(LOG_INFO, "│ %-24s : [not mapped]", "NAT Port Range");
    }
}

static inline void print_extra_avps(const UserSessionInfo *s)
{
    if (__builtin_expect(!opt_extract_all, 1))
        return;

    if (__builtin_expect(s->extra_avp_count == 0, 1))
        return;

    LOG_LINE();
    syslog(LOG_INFO, "│ EXTRA AVPs (%u)", s->extra_avp_count);
    LOG_LINE();
    for (uint16_t i = 0; i < s->extra_avp_count; i++)
    {
        const extra_avps *avp = &s->extra_avps[i];
        const char *name = getRadiusAttributeName(avp->type);
        syslog(LOG_INFO, "│ [%03u] %-30s Type=%-3u Len=%-3u", i + 1, name, avp->type, avp->len);

        /*
         * Print AVP value hex
         */
        char hexbuf[512];
        int pos = 0;
        const uint16_t payloadLen = avp->len - 2;
        for (uint16_t j = 0; j < payloadLen && j < MAX_AVP_VALUE; j++)
        {
            pos += snprintf(hexbuf + pos, sizeof(hexbuf) - pos, "%02x ", avp->value[j]);
            if (pos >= (int)(sizeof(hexbuf) - 4))
                break;
        }
        syslog(LOG_INFO, "│ %-24s : %s", "Value", hexbuf);
    }
}

void printUserSession(const UserSessionInfo *pSession);