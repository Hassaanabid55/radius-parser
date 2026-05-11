#include "parser.h"

/* =========================================================
 * ETHERNET -> IPV4
 * ========================================================= */
const char *getIpLayer(const char *pPacket, size_t len)
{
    if (__builtin_expect(!pPacket, 0))
        return NULL;

    if (__builtin_expect(len < sizeof(struct ethhdr), 0))
        return NULL;

    const struct ethhdr *eth =
        (const struct ethhdr *)pPacket;

    if (__builtin_expect(ntohs(eth->h_proto) != ETH_P_IP, 0))
        return NULL;

    return pPacket + sizeof(struct ethhdr);
}

/* =========================================================
 * IPV4 -> UDP
 * ========================================================= */
const char *getUdpLayer(const char *pIpLayer, size_t len)
{
    if (__builtin_expect(!pIpLayer, 0))
        return NULL;

    if (__builtin_expect(len < sizeof(struct iphdr), 0))
        return NULL;

    const struct iphdr *ip = (const struct iphdr *)pIpLayer;
    const uint32_t ipHdrLen = ((uint32_t)ip->ihl) << 2;

    if (__builtin_expect(ipHdrLen < sizeof(struct iphdr), 0))
        return NULL;

    if (__builtin_expect(ipHdrLen > len, 0))
        return NULL;

    if (__builtin_expect(ip->protocol != IPPROTO_UDP, 0))
        return NULL;

    return pIpLayer + ipHdrLen;
}

/* =========================================================
 * UDP DST PORT
 * ========================================================= */
uint16_t getUdpDstPort(const char *pStartOfUdpLayer)
{
    if (__builtin_expect(!pStartOfUdpLayer, 0))
        return 0;

    return ntohs(((const struct udphdr *)pStartOfUdpLayer)->dest);
}

/* =========================================================
 * LOCATE RADIUS ACCOUNTING LAYER
 * ========================================================= */
const char *getRadiusAcctLayer(const char *pPacket, size_t len)
{
    if (__builtin_expect(!pPacket, 0))
        return NULL;

    const char *pIpLayer = getIpLayer(pPacket, len);
    if (__builtin_expect(!pIpLayer, 0))
        return NULL;

    const size_t ipOffset = (size_t)(pIpLayer - pPacket);
    const char *pUdpLayer = getUdpLayer(pIpLayer, len - ipOffset);
    if (__builtin_expect(!pUdpLayer, 0))
        return NULL;

    if (__builtin_expect(getUdpDstPort(pUdpLayer) != 1813, 0))
        return NULL;

    const size_t udpOffset = (size_t)(pUdpLayer - pPacket);
    if (__builtin_expect(len - udpOffset < sizeof(struct udphdr), 0))
        return NULL;

    const char *pRadiusLayer = pUdpLayer + sizeof(struct udphdr);
    const size_t radiusOffset = (size_t)(pRadiusLayer - pPacket);
    const size_t remaining = len - radiusOffset;
    if (__builtin_expect(remaining < RADIUS_HDR_LEN, 0))
        return NULL;

    /*
     * Radius Code
     */
    if (__builtin_expect(((const uint8_t *)pRadiusLayer)[0] != RADIUS_CODE_ACCT_REQ, 0))
    {
        return NULL;
    }

    /*
     * Radius Length
     */
    uint16_t radiusLen;
    memcpy(&radiusLen, pRadiusLayer + 2, sizeof(radiusLen));
    radiusLen = ntohs(radiusLen);
    if (__builtin_expect(radiusLen < RADIUS_HDR_LEN, 0))
        return NULL;

    if (__builtin_expect(radiusLen > remaining, 0))
        return NULL;

    return pRadiusLayer;
}

/* =========================================================
 * LOCAL TIME
 * ========================================================= */
void setCurrentLocalTime(struct tm *sTime)
{
    if (__builtin_expect(!sTime, 0))
        return;

    time_t t = time(NULL);
    localtime_r(&t, sTime);
}

/* =========================================================
 * SESSION START
 * ========================================================= */
int sessionStart(UserSessionInfo *pSession)
{
    setCurrentLocalTime(&pSession->sSessionStartTime);
    return 0;
}

/* =========================================================
 * SESSION END
 * ========================================================= */
int sessionEnd(UserSessionInfo *pSession)
{
    setCurrentLocalTime(&pSession->sSessionEndTime);
    return 0;
}

/* =========================================================
 * PARSE RADIUS PACKET
 * ========================================================= */
int parseRadiusPkt(const char *pPacket, size_t len, RadiusPacket *radiusPkt)
{
    if (__builtin_expect(!pPacket, 0))
        return -1;

    if (__builtin_expect(!radiusPkt, 0))
        return -1;

    const char *pRadiusLayer = getRadiusAcctLayer(pPacket, len);
    if (__builtin_expect(!pRadiusLayer, 0))
        return -1;

    uint16_t radiusLen;
    memcpy(&radiusLen, pRadiusLayer + 2, sizeof(radiusLen));
    radiusLen = ntohs(radiusLen);
    if (__builtin_expect(radiusLen < RADIUS_HDR_LEN, 0))
        return -1;

    radiusPkt->pData = (const u_int8_t *)pRadiusLayer;
    radiusPkt->length = radiusLen;
    radiusPkt->code = radiusPkt->pData[0];
    radiusPkt->identifier = radiusPkt->pData[1];
    radiusPkt->pPayload = radiusPkt->pData + RADIUS_HDR_LEN;
    radiusPkt->payloadLen = radiusLen - RADIUS_HDR_LEN;
    return 0;
}

/* =========================================================
 * READ RADIUS ATTRIBUTES
 * ========================================================= */
int readRadiusAttributes(const RadiusPacket *radiusPkt, UserSessionInfo *pSession)
{
    if (__builtin_expect(!radiusPkt, 0))
        return -1;

    if (__builtin_expect(!pSession, 0))
        return -1;

    if (__builtin_expect(!radiusPkt->pPayload, 0))
        return -1;

    memset(pSession, 0, sizeof(*pSession));
    pSession->nSessionIndicator = -1;
    const uint8_t *payload = radiusPkt->pPayload;
    const uint32_t payloadLen = radiusPkt->payloadLen;
    uint32_t offset = 0;
    while (offset + 2 <= payloadLen)
    {
        const uint8_t *p = payload + offset;
        const uint8_t type = p[0];
        const uint8_t len = p[1];

        if (__builtin_expect(type == 0, 0))
            return logInvalidAvp(type, len, offset);

        if (__builtin_expect(len < 2, 0))
            return logInvalidAvp(type, len, offset);

        if (__builtin_expect(offset + len > payloadLen, 0))
            return logInvalidAvp(type, len, offset);

        const uint8_t *value = p + 2;
        const uint16_t valueLen = len - 2;

        switch (type)
        {
        /* =========================================================
         * ACCT STATUS TYPE
         * ========================================================= */
        case ACCT_STATUS_TYPE:
        {
            if (__builtin_expect(valueLen != 4, 0))
                return logInvalidAvp(type, len, offset);

            uint32_t v;

            memcpy(&v, value, sizeof(v));
            pSession->u8AccountStatusType = (uint8_t)ntohl(v);
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

        /* =========================================================
         * SESSION ID
         * ========================================================= */
        case ACCT_SESSION_ID:
        {
            const uint8_t copyLen = (valueLen < sizeof(pSession->acAccountSessionId) - 1) ? valueLen : sizeof(pSession->acAccountSessionId) - 1;
            memcpy(pSession->acAccountSessionId, value, copyLen);
            pSession->acAccountSessionId[copyLen] = '\0';
            pSession->u64ValidAttributes |= VALID_ACCT_SESSION_ID;
            break;
        }

        /* =========================================================
         * CALLING STATION ID
         * ========================================================= */
        case CALLING_STATION_ID:
        {
            if (__builtin_expect(valueLen < 3, 0))
                return -1;

            if (__builtin_expect(valueLen >= sizeof(pSession->acCallingStationId), 0))
            {
                return -1;
            }

            memcpy(pSession->acCallingStationId, value, valueLen);
            pSession->acCallingStationId[valueLen] = '\0';
            pSession->u64ValidAttributes |= VALID_CALLING_STATION_ID;

            /*
             * O(1) WHITELIST LOOKUP
             */
            WhitelistInfo wlInfo;

            if (wl_lookup(pSession->acCallingStationId, &wlInfo))
            {
                pSession->u8IsWL = wlInfo.status ? 1 : 0;
            }
            break;
        }

        /* =========================================================
         * EVENT TIMESTAMP
         * ========================================================= */
        case EVENT_TIMESTAMP:
        {
            if (__builtin_expect(valueLen != 4, 0))
                return logInvalidAvp(type, len, offset);

            uint32_t ts;

            memcpy(&ts, value, sizeof(ts));
            pSession->u32EventTimestamp = ntohl(ts);
            pSession->u64ValidAttributes |= VALID_EVENT_TIMESTAMP;
            break;
        }

        /* =========================================================
         * FRAMED IPV4
         * ========================================================= */
        case FRAMED_IP_ADDRESS:
        {
            if (__builtin_expect(valueLen != IPV4_OCTETS, 0))
                return -1;

            memcpy(pSession->u8FramedIpv4Address, value, IPV4_OCTETS);
            pSession->u64ValidAttributes |= VALID_FRAMED_IPV4;

            /*
             * O(1) CGNAT LOOKUP
             */
            char ip_str[16];

            ipv4_to_str(pSession->u8FramedIpv4Address, ip_str);
            CgnatEntry entry;
            if (cgnat_lookup(ip_str, &entry))
            {
                struct in_addr addr;

                if (inet_pton(AF_INET, entry.nat_ip, &addr) == 1)
                {
                    memcpy(pSession->u8FramedIpv4PubAddress, &addr.s_addr, IPV4_OCTETS);
                    pSession->portStart = entry.start_port;
                    pSession->portEnd = entry.end_port;
                }
            }

            break;
        }

        /* =========================================================
         * FRAMED IPV6 PREFIX
         * ========================================================= */
        case FRAMED_IPV6_PREFIX:
        {
            if (__builtin_expect(valueLen < 2, 0))
                return -1;

            if (__builtin_expect(valueLen > IPV6_PREFIX_MAX_LEN, 0))
            {
                return -1;
            }

            memcpy(pSession->u8FramedIpv6Prefix, value, valueLen);
            pSession->u64ValidAttributes |= VALID_FRAMED_IPV6_PREFIX;
            break;
        }

        /* =========================================================
         * MULTI SESSION ID
         * ========================================================= */
        case ACCT_MULTI_SESSION_ID:
        {
            const uint8_t copyLen = (valueLen < sizeof(pSession->acMultiSessionId) - 1) ? valueLen : sizeof(pSession->acMultiSessionId) - 1;
            memcpy(pSession->acMultiSessionId, value, copyLen);
            pSession->acMultiSessionId[copyLen] = '\0';
            pSession->u64ValidAttributes |= VALID_ACCT_MULTI_SESSION_ID;
            break;
        }

        /* =========================================================
         * EXTRA AVPS
         * ========================================================= */
        default:
        {
            if (opt_extract_all)
            {
                if (pSession->extra_avp_count < MAX_EXTRA_AVPS)
                {
                    extra_avps *avp = &pSession->extra_avps[pSession->extra_avp_count++];
                    avp->type = type;
                    avp->len = len;
                    const uint8_t copyLen = (valueLen > MAX_AVP_VALUE) ? MAX_AVP_VALUE : valueLen;
                    memcpy(avp->value, value, copyLen);
                }
            }
            break;
        }
        } /* switch */
        offset += len;
    } /* while */
    return 0;
}