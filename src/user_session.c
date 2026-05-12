#include "user_session.h"

/* =========================================================
 * MAIN SESSION LOGGER
 * ========================================================= */
void printUserSession(const UserSessionInfo *s)
{
    if (!s)
        return;

    char logbuf[16384];
    size_t off = 0;

    char ipv4_priv[32] = "[not present]";
    char ipv4_pub[32] = "[not present]";
    char ipv6[INET6_ADDRSTRLEN] = "[not present]";
    char tsbuf[64] = "[not present]";

    /*
     * IPv4 Private
     */
    if (s->u64ValidAttributes & VALID_FRAMED_IPV4)
    {
        snprintf(ipv4_priv, sizeof(ipv4_priv), "%u.%u.%u.%u", s->u8FramedIpv4Address[0], s->u8FramedIpv4Address[1], s->u8FramedIpv4Address[2], s->u8FramedIpv4Address[3]);
    }

    /*
     * IPv4 Public
     */
    if (s->portStart != 0 || s->portEnd != 0)
    {
        snprintf(ipv4_pub, sizeof(ipv4_pub), "%u.%u.%u.%u", s->u8FramedIpv4PubAddress[0], s->u8FramedIpv4PubAddress[1], s->u8FramedIpv4PubAddress[2], s->u8FramedIpv4PubAddress[3]);
    }

    /*
     * IPv6
     */
    if (s->u64ValidAttributes & VALID_FRAMED_IPV6_PREFIX)
    {
        inet_ntop(AF_INET6, s->u8FramedIpv6Prefix + 2, ipv6, sizeof(ipv6));
    }

    /*
     * Timestamp
     */
    if (s->u64ValidAttributes & VALID_EVENT_TIMESTAMP)
    {
        struct tm tm_info;
        time_t t = (time_t)s->u32EventTimestamp;
        localtime_r(&t, &tm_info);
        strftime(tsbuf, sizeof(tsbuf), "%Y-%m-%d %H:%M:%S", &tm_info);
    }

    off += snprintf(logbuf + off, sizeof(logbuf) - off, "[SESSION] Type=%s | SessionId=%s | MultiSessionId=%s | CallingStation=%s | IPv4Private=%s | IPv4Public=%s | IPv6=%s | Ports=%u-%u | Timestamp=%u | Time=%s | WL=%s", session_type_str(s->nSessionIndicator), (s->u64ValidAttributes & VALID_ACCT_SESSION_ID) ? s->acAccountSessionId : "[not present]", (s->u64ValidAttributes & VALID_ACCT_MULTI_SESSION_ID) ? s->acMultiSessionId : "[not present]", (s->u64ValidAttributes & VALID_CALLING_STATION_ID) ? s->acCallingStationId : "[not present]", ipv4_priv, ipv4_pub, ipv6, s->portStart, s->portEnd, s->u32EventTimestamp, tsbuf, s->u8IsWL ? "YES" : "NO");
    if (opt_extract_all && s->extra_avp_count > 0)
    {
        off += snprintf(logbuf + off, sizeof(logbuf) - off, " | AVPs=[");
        for (uint16_t i = 0; i < s->extra_avp_count; i++)
        {
            const extra_avps *avp = &s->extra_avps[i];
            char hexbuf[512];
            size_t hexoff = 0;
            const uint16_t payloadLen = avp->len - 2;
            for (uint16_t j = 0; j < payloadLen && j < MAX_AVP_VALUE; j++)
            {
                hexoff += snprintf(hexbuf + hexoff, sizeof(hexbuf) - hexoff, "%02x", avp->value[j]);
                if (j + 1 < payloadLen)
                {
                    hexoff += snprintf(hexbuf + hexoff, sizeof(hexbuf) - hexoff, ":");
                }

                if (hexoff >= sizeof(hexbuf))
                    break;
            }

            off += snprintf(logbuf + off, sizeof(logbuf) - off, "{Type=%u,Len=%u,Value=%s}", avp->type, avp->len, hexbuf);
            if (i + 1 < s->extra_avp_count)
            {
                off += snprintf(logbuf + off, sizeof(logbuf) - off, ",");
            }

            if (off >= sizeof(logbuf))
                break;
        }
        off += snprintf(logbuf + off, sizeof(logbuf) - off, "]");
    }

    syslog(LOG_INFO, "%s", logbuf);
}