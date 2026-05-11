#pragma once

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <sys/syslog.h>
#include <time.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "user_session.h"
#include "modules/cgnat/whitelist_handler.h"
#include "modules/cgnat/cgnat_handler.h"

extern bool opt_extract_all;

typedef struct
{
    const uint8_t *pData;
    const uint8_t *pPayload;
    uint16_t length;
    uint16_t payloadLen;
    uint8_t code;
    uint8_t identifier;
} RadiusPacket;

static inline int logInvalidAvp(uint8_t type, uint8_t len, uint16_t offset)
{
    syslog(LOG_ERR, "Invalid AVP - Type=%u Len=%u Offset=%u", type, len, offset);
    return -1;
}

static inline void ipv4_to_str(const uint8_t ip[4], char out[16])
{
    /*
     * Faster than snprintf()
     * Max IPv4 string length = 15 + NULL
     */
    int len = 0;
    len += sprintf(out + len, "%u", ip[0]);
    out[len++] = '.';
    len += sprintf(out + len, "%u", ip[1]);
    out[len++] = '.';
    len += sprintf(out + len, "%u", ip[2]);
    out[len++] = '.';
    len += sprintf(out + len, "%u", ip[3]);
    out[len] = '\0';
}

const char *getIpLayer(const char *pPacket, size_t len);
const char *getUdpLayer(const char *pIpLayer, size_t len);
uint16_t getUdpDstPort(const char *pStartOfUdpLayer);
const char *getRadiusAcctLayer(const char *pPacket, size_t len);
void setCurrentLocalTime(struct tm *sTime);
int sessionStart(UserSessionInfo *pSession);
int sessionEnd(UserSessionInfo *pSession);
int parseRadiusPkt(const char *pPacket, size_t len, RadiusPacket *radiusPkt);
int readRadiusAttributes(const RadiusPacket *radiusPkt, UserSessionInfo *pSession);