#pragma once

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

#define IPV6_PREFIX_MAX_LEN 18 /**< length of max ipv6 prefix including 2 bytes of dialing code */
#define SESSION_START 1        /**< Session start on RADIUS START message */
#define SESSION_STOP 2         /**< Session stop on RADIUS STOP message */
#define SESSION_UPDATE 3       /**< Session update on RADIUS UPDATE message */
#define IPV4_OCTETS 4          /**< Octets in IPv4 Address */

#define SESSION_ID_MAX_LEN 64

typedef struct
{
    struct tm sSessionStartTime;
    struct tm sSessionEndTime;

    int nSessionIndicator;

    uint64_t u64ValidAttributes;
    uint32_t u32EventTimestamp;

    uint8_t u8AccountStatusType;                 /**< enum [RFC2866]*/
    char acAccountSessionId[SESSION_ID_MAX_LEN]; /**< text [RFC2866]*/
    char acCallingStationId[32];                 /**< text [RFC2865]*/

    uint8_t u8FramedIpv4Address[IPV4_OCTETS];        /**< ipv4addr [RFC2865]*/
    uint8_t u8FramedIpv6Prefix[IPV6_PREFIX_MAX_LEN]; /**< ipv6prefix [RFC3162]*/

    // CGNAT populated fields
    uint8_t u8NatPublicIp[IPV4_OCTETS];
    uint16_t u16PortMin;
    uint16_t u16PortMax;
    uint8_t u8IsCgnatMatched;

    uint8_t u8IsWL;

    int nSessionTimeout;                          /**< integer [RFC2865]*/
    int nIdleTimeout;                             /**< integer [RFC2865]*/
    int nTerminationAction; /**< enum [RFC2865]*/ // TODO: enum
} UserSessionInfo;

// uint8_t u8NasIpAddress[IPV4_OCTETS];             /**< ipv4addr [RFC2865]*/
// uint16_t u16NasPort;                             /**< integer [RFC2865]*/
// VENDOR_SPECIFIC 26  /**< vsa [RFC2865]*/ //TODO: Vendor Specific

// uint8_t u8AccountInputOctets;                          /**< integer [RFC2866]*/
// NAS_IDENTIFIER  32  /**< text [RFC2865]*/
// ACCT_DELAY_TIME 41  /**< integer [RFC2866]*/
// ACCT_OUTPUT_OCTETS  43  /**< integer [RFC2866]*/

// ACCT_SESSION_TIME   46  /**< integer [RFC2866]*/
// ACCT_INPUT_PACKETS  47  /**< integer [RFC2866]*/
// ACCT_OUTPUT_PACKETS 48  /**< integer [RFC2866]*/
// ACCT_MULTI_SESSION_ID   50  /**< text [RFC2866]*/
// ACCT_LINK_COUNT 51  /**< integer [RFC2866]*/

void printUserSession(const UserSessionInfo *pSession);