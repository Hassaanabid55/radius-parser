#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <string.h>
#include <time.h>

#include <net/ethernet.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#include "parser.h"
#include "user_session.h"
#include "radius_attribute_list.h"

/*
 *   Extract IPv4 layer from Eth frame
 *   - pPacket: pointer to the start of the Ethernet frame
 *   - len: total packet length
 *   - Returns: pointer to the start of the IPv4 header, NULL if not IPv4
 */
const char *getIpLayer(const char *pPacket, size_t len)
{
    // validate input pointer + ensure pkt is large enough for valid Eth hdr
    if (!pPacket || len < sizeof(struct ethhdr))
        return NULL;

    // 1st byte = eth hdr
    const struct ethhdr *eth = (const struct ethhdr *)pPacket;

    // verify eth type indicates IPv4 (0x0800)
    if (ntohs(eth->h_proto) != ETH_P_IP)
        return NULL;

    return pPacket + sizeof(struct ethhdr);
}

/*
 * Extract UDP layer from an IPv4 packet.
 *  - pIpLayer : ptr to start of IPv4 header
 *  - len      : remaining pkt len starting from IPv4 hdr
 *  - Returns  : ptr to UDP header if protocol is UDP, else returns NULL
 */
const char *getUdpLayer(const char *pIpLayer, size_t len)
{
    // ensure valid ptr + valid IP hdr
    if (!pIpLayer || len < sizeof(struct iphdr))
        return NULL;

    const struct iphdr *ip = (const struct iphdr *)pIpLayer;

    // Convert IPv4 header length from 32-bit words (IHL field) to bytes
    size_t ipHdrLen = ip->ihl * 4;

    // validate hdr len
    if (ipHdrLen < sizeof(struct iphdr) || len < ipHdrLen)
        return NULL;

    if (ip->protocol != IPPROTO_UDP)
        return NULL;

    return pIpLayer + (ip->ihl * 4);
}

/*
 * Extract UDP dst port
 *  - pStartOfUdpLayer : ptr to start of UDP header
 *  - Returns          : dst port in Host byte order
 */
uint16_t getUdpDstPort(const char *pStartOfUdpLayer)
{
    if (!pStartOfUdpLayer)
        return 0;

    const struct udphdr *udp = (const struct udphdr *)pStartOfUdpLayer;

    return ntohs(udp->dest);
}

/*
 * Locate RADIUS Accounting Request
 *
 * Steps:
 * 1. Extract IPv4 hdr
 * 2. Extract UDP hdr
 * 3. Verify UDP dst port = 1813 (RADIUS Acct)
 * 4. Verify RADIUS Code = Acct-Req
 *
 *  - Returns: ptr to RADIUS layer if valid pkt
 */

const char *getRadiusAcctLayer(const char *pPacket, size_t len)
{
    if (!pPacket || len == 0)
        return NULL;

    const char *pIpLayer = getIpLayer(pPacket, len);
    if (!pIpLayer)
        return NULL;

    // calculate IP hdr offset from start of pkt
    size_t ipOffset = (size_t)(pIpLayer - pPacket);
    size_t remainingAfterIP = len - ipOffset;

    const char *pUdpLayer = getUdpLayer(pIpLayer, remainingAfterIP);
    if (!pUdpLayer)
        return NULL;

    // Calculate offset of UDP header from start of pkt
    size_t udpOffset = (size_t)(pUdpLayer - pPacket);
    size_t remainingAfterUdp = len - udpOffset;

    // Ensure packet contains full UDP header
    if (remainingAfterUdp < sizeof(struct udphdr))
        return NULL;

    if (getUdpDstPort(pUdpLayer) != RADIUS_ACCT_PORT)
        return NULL;

    const char *pRadiusLayer = pUdpLayer + sizeof(struct udphdr);

    // Calculate remaining packet length
    size_t radiusOffset = (size_t)(pRadiusLayer - pPacket);
    size_t remainingAfterRadius = len - radiusOffset;

    // ensure pkt contains full RADIUS hdr
    if (remainingAfterRadius < RADIUS_HDR_LEN)
        return NULL;

    // check RADIUS code
    uint8_t u8Code = *(const uint8_t *)pRadiusLayer;
    if (u8Code != RADIUS_CODE_ACCT_REQ)
        return NULL;

    // Validate RADIUS length field matches packet
    uint16_t radiusLen;
    memcpy(&radiusLen, pRadiusLayer + 2, sizeof(radiusLen));
    radiusLen = ntohs(radiusLen);

    if (radiusLen > remainingAfterRadius || radiusLen < RADIUS_HDR_LEN)
        return NULL;

    return pRadiusLayer;
}

void setCurrentLocalTime(struct tm *sTime)
{
    if (!sTime)
        return;

    time_t t = time(NULL);

    *sTime = *localtime(&t);
}
int sessionStart(UserSessionInfo *pSession)
{
    setCurrentLocalTime(&pSession->sSessionStartTime);
    return 0;
}
int sessionEnd(UserSessionInfo *pSession)
{
    setCurrentLocalTime(&pSession->sSessionEndTime);
    return 0;
}

int parseRadiusPkt(const char *pPacket, size_t len, RadiusPacket *radiusPkt)
{

    // validate input pointers
    if (!pPacket || !radiusPkt)
        return -1;

    // locate start of radius len field (bytes 2 - 3 in hdr)
    const char *pRadiusLayer = getRadiusAcctLayer(pPacket, len);
    if (!pRadiusLayer)
        return -1;

    // extract the radius len field
    uint16_t radiusLen;
    memcpy(&radiusLen, pRadiusLayer + 2, sizeof(radiusLen));
    radiusLen = ntohs(radiusLen);

    // validate min hdr len
    if (radiusLen < RADIUS_HDR_LEN)
        return -1;

    // populate RadiusPacket struct
    radiusPkt->pData = (const u_int8_t *)pRadiusLayer;
    radiusPkt->length = radiusLen;

    radiusPkt->code = radiusPkt->pData[0];
    radiusPkt->identifier = radiusPkt->pData[1];

    radiusPkt->pPayload = radiusPkt->pData + RADIUS_HDR_LEN;
    radiusPkt->payloadLen = radiusLen - RADIUS_HDR_LEN;

    return 0;
}

int logInvalidAvp(uint8_t type, uint8_t len, uint16_t offset)
{
    fprintf(stderr,
            "[RADIUS][ERROR] Invalid AVP - Type: %u, Length: %u, Offset: %u\n",
            type, len, offset);
    return -1;
}

/*
 * RADIUS Parser [supports Acct-Req only]
 *
 * populates a UserSessionInfo struct
 * pRadiusLayer: ptr to start of RADIUS pkt (after UDP hdr)
 * pSession: ptr to UserSessionInfo struct to populate
 *
 *  - Returns: true if all required AVPs were found
 */
int readRadiusAttributes(const RadiusPacket *radiusPkt, UserSessionInfo *pSession)
{
    if (!radiusPkt || !pSession || !radiusPkt->pPayload)
        return -1;

    uint32_t offset = 0; // current parsing position in payload

    memset(pSession, 0, sizeof(*pSession));
    pSession->nSessionIndicator = -1; // return value (SESSION_START / SESSION_STOP / SESSION_UPDATE)

    // Reset Session State before parsing new pkt
    pSession->u64ValidAttributes = 0;

    // iterate through AVPs on payload
    while (offset + 2 <= radiusPkt->payloadLen)
    {
        // each avp starts with [type (1 byte)] [length (1 byte)]
        const uint8_t *p = radiusPkt->pPayload + offset;

        uint8_t type = p[0];
        uint8_t len = p[1];

        // basic AVP sanity checks

        if (type == 0 || len < 2)
        {
            return logInvalidAvp(type, len, offset);
        }

        // Prevent reading beyond payload
        if (offset + len > radiusPkt->payloadLen)
            return logInvalidAvp(type, len, offset);

        // Extract value section (after type + len)
        const uint8_t *value = p + 2;
        uint8_t valueLen = len - 2;

        switch (type)
        {
        case ACCT_STATUS_TYPE:
        {
            // must be exact 4 bytes
            if (valueLen != 4)
                return logInvalidAvp(type, len, offset);

            uint32_t v;
            memcpy(&v, value, sizeof(v));

            // convert from network byte order
            pSession->u8AccountStatusType = (uint8_t)ntohl(v);
            fprintf(stderr, "DEBUG: AccountStatusType = %u\n", pSession->u8AccountStatusType);

            // session state handling
            switch (pSession->u8AccountStatusType)
            {
            case SESSION_START:
                sessionStart(pSession);
                pSession->nSessionIndicator = SESSION_START;
                break;
            case SESSION_STOP:
                sessionEnd(pSession);
                pSession->nSessionIndicator = SESSION_STOP;
                break;
            case SESSION_UPDATE:
                sessionEnd(pSession);
                sessionStart(pSession);
                pSession->nSessionIndicator = SESSION_UPDATE;
                break;

            default:
                break;
            }

            pSession->u64ValidAttributes |= VALID_ACCT_STATUS_TYPE;
            break;
        }

        case ACCT_SESSION_ID:
        {
            uint8_t copyLen = valueLen < sizeof(pSession->acAccountSessionId) - 1
                                  ? valueLen
                                  : sizeof(pSession->acAccountSessionId) - 1;
            memcpy(pSession->acAccountSessionId, value, copyLen);

            pSession->acAccountSessionId[copyLen] = '\0';

            pSession->u64ValidAttributes |= VALID_ACCT_SESSION_ID;
            fprintf(stderr, "DEBUG: SessionId = %s\n", pSession->acAccountSessionId);
            break;
        }

        case FRAMED_IP_ADDRESS:
        {
            if (valueLen != IPV4_OCTETS)
                // return logInvalidAvp(type, len, offset);
                return -1;

            memcpy(pSession->u8FramedIpv4Address, value, IPV4_OCTETS);

            fprintf(stderr, "DEBUG: Framed-IPv4-Address = %u.%u.%u.%u\n",
                    pSession->u8FramedIpv4Address[0], pSession->u8FramedIpv4Address[1],
                    pSession->u8FramedIpv4Address[2], pSession->u8FramedIpv4Address[3]);

            pSession->u64ValidAttributes |= VALID_FRAMED_IPV4;
            break;
        }

        case FRAMED_IPV6_PREFIX:
        {
            if (valueLen < 2 || valueLen > IPV6_PREFIX_MAX_LEN)
                return logInvalidAvp(type, len, offset);

            uint8_t prefixLen = value[1];

            if (prefixLen > 128)
                return logInvalidAvp(type, len, offset);

            // Store full prefix blob
            uint8_t copyLen = valueLen < IPV6_PREFIX_MAX_LEN
                                  ? valueLen
                                  : IPV6_PREFIX_MAX_LEN;

            memcpy(pSession->u8FramedIpv6Prefix, value, copyLen);

            fprintf(stderr, "DEBUG: IPv6 Prefix = ");
            for (int i = 0; i < copyLen; i++)
            {
                fprintf(stderr, "%02x ", pSession->u8FramedIpv6Prefix[i]);
            }
            fprintf(stderr, "\n");

            pSession->u64ValidAttributes |= VALID_FRAMED_IPV6_PREFIX;
            break;
        }

        case CALLING_STATION_ID:
        {
            if (valueLen < 3 || valueLen >= sizeof(pSession->acCallingStationId))
                return -1;
            // return loginvalidavp;

            memcpy(pSession->acCallingStationId, value, valueLen);

            fprintf(stderr, "DEBUG: Calling-Station-Id = %s\n", pSession->acCallingStationId);

            pSession->u64ValidAttributes |= VALID_CALLING_STATION_ID;
            break;
        }

        case EVENT_TIMESTAMP:
        {
            if (valueLen != 4)
                return logInvalidAvp(type, len, offset);

            uint32_t ts;
            memcpy(&ts, value, sizeof(ts));

            // Convert from network byte order
            pSession->u32EventTimestamp = ntohl(ts);

            pSession->u64ValidAttributes |= VALID_EVENT_TIMESTAMP;

            fprintf(stderr, "DEBUG: Event-Timestamp (epoch) = %u\n",
                    pSession->u32EventTimestamp);

            break;
        }
        default:
            break;
        } // END OF SWITCH
        offset += len;

    } // END OF WHILE LOOP
    // return pSession->nSessionIndicator;
    return 0;
}