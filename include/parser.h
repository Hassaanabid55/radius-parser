#pragma once

#include <netinet/udp.h>
#include <stdint.h>
#include "radius_attribute_list.h"
#include "user_session.h"

#define RADIUS_ACCT_PORT 1813
#define RADIUS_CODE_ACCT_REQ 4
#define RADIUS_HDR_LEN 20

#define VALID_ACCT_STATUS_TYPE (1ULL << 0)
#define VALID_ACCT_SESSION_ID (1ULL << 1)
#define VALID_CALLING_STATION_ID (1ULL << 2)
#define VALID_FRAMED_IPV4 (1ULL << 3)
#define VALID_FRAMED_IPV6_PREFIX (1ULL << 4)
#define VALID_EVENT_TIMESTAMP (1ULL << 5)
// #define VALID_ (1ULL << 5)

typedef struct
{
    const uint8_t *pData;
    const uint8_t *pPayload;
    uint16_t length;
    uint16_t payloadLen;
    uint8_t code;
    uint8_t identifier;
} RadiusPacket;

int logInvalidAvp(uint8_t type, uint8_t len, uint16_t offset);
void setCurrentLocalTime(struct tm *sTime);
const char *getIpLayer(const char *pPacket, size_t len);
const char *getUdpLayer(const char *pIpLayer, size_t len);
uint16_t getUdpDstPort(const char *pStartOfUdpLayer);
const char *getRadiusAcctLayer(const char *pPacket, size_t len);
int parseRadiusPkt(const char *pPacket, size_t len, RadiusPacket *radiusPkt);
int readRadiusAttributes(const RadiusPacket *radiusPkt, UserSessionInfo *pSession);