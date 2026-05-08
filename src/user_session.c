#include <stdio.h>
#include <arpa/inet.h>

#include "user_session.h"
#include "parser.h"

void printUserSession(const UserSessionInfo *pSession)
{
    if (!pSession)
        return;

    printf("┌─────────────────────────────────────────\n");
    printf("│ USER SESSION\n");
    printf("├─────────────────────────────────────────\n");

    // Session indicator
    const char *pcIndicator = "UNKNOWN";
    switch (pSession->nSessionIndicator)
    {
    case SESSION_START:
        pcIndicator = "START";
        break;
    case SESSION_STOP:
        pcIndicator = "STOP";
        break;
    case SESSION_UPDATE:
        pcIndicator = "UPDATE";
        break;
    default:
        pcIndicator = "UNKNOWN";
        break;
    }
    printf("│ Session Type     : %s\n", pcIndicator);

    // Acct-Status-Type
    if (pSession->u64ValidAttributes & VALID_ACCT_STATUS_TYPE)
        printf("│ Status Type      : %u\n", pSession->u8AccountStatusType);
    else
        printf("│ Status Type      : [not present]\n");

    // Acct-Session-Id
    if (pSession->u64ValidAttributes & VALID_ACCT_SESSION_ID)
        printf("│ Session ID       : %s\n", pSession->acAccountSessionId);
    else
        printf("│ Session ID       : [not present]\n");

    // Calling-Station-Id
    if (pSession->u64ValidAttributes & VALID_CALLING_STATION_ID)
        printf("│ Calling Station  : %s\n", pSession->acCallingStationId);
    else
        printf("│ Calling Station  : [not present]\n");

    // Framed-IP-Address
    if (pSession->u64ValidAttributes & VALID_FRAMED_IPV4)
    {
        char acIpStr[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, pSession->u8FramedIpv4Address, acIpStr, sizeof(acIpStr));
        printf("│ Framed IPv4      : %s\n", acIpStr);
    }
    else
        printf("│ Framed IPv4      : [not present]\n");

    // Framed-IPv6-Prefix
    if (pSession->u64ValidAttributes & VALID_FRAMED_IPV6_PREFIX)
    {
        // value[0] = reserved, value[1] = prefix length, value[2+] = address
        uint8_t u8PrefixLen = pSession->u8FramedIpv6Prefix[1];
        char acIpv6Str[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, pSession->u8FramedIpv6Prefix + 2, acIpv6Str, sizeof(acIpv6Str));
        printf("│ Framed IPv6      : %s/%u\n", acIpv6Str, u8PrefixLen);
    }
    else
        printf("│ Framed IPv6      : [not present]\n");

    // Event Timestamp
    if (pSession->u64ValidAttributes & VALID_EVENT_TIMESTAMP)
    {
        printf("│ Event Timestamp  : %u (epoch)\n", pSession->u32EventTimestamp);

        // Convert to readable time (only for display)
        time_t t = pSession->u32EventTimestamp;
        struct tm tm_info;
        localtime_r(&t, &tm_info);

        char acTimeBuf[64];
        strftime(acTimeBuf, sizeof(acTimeBuf), "%Y-%m-%d %H:%M:%S", &tm_info);

        printf("│ Event Time       : %s\n", acTimeBuf);
    }
    else
    {
        printf("│ Event Timestamp  : [not present]\n");
    }

    // Whitelist
    printf("│ Whitelisted      : %s\n", pSession->u8IsWL ? "YES" : "NO");

    printf("└─────────────────────────────────────────\n");
}