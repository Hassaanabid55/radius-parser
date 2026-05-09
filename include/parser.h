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

#define IS_FAST(type, flag) (opt_extract_all || (flag))

typedef struct
{
    const uint8_t *pData;
    const uint8_t *pPayload;
    uint16_t length;
    uint16_t payloadLen;
    uint8_t code;
    uint8_t identifier;
} RadiusPacket;

const char *getIpLayer(const char *pPacket, size_t len);
const char *getUdpLayer(const char *pIpLayer, size_t len);
uint16_t getUdpDstPort(const char *pStartOfUdpLayer);
const char *getRadiusAcctLayer(const char *pPacket, size_t len);
void setCurrentLocalTime(struct tm *sTime);
int sessionStart(UserSessionInfo *pSession);
int sessionEnd(UserSessionInfo *pSession);
int parseRadiusPkt(const char *pPacket, size_t len, RadiusPacket *radiusPkt);
int logInvalidAvp(uint8_t type, uint8_t len, uint16_t offset);
int readRadiusAttributes(const RadiusPacket *radiusPkt, UserSessionInfo *pSession);