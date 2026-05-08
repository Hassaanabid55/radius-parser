#pragma once

#include <stdint.h>
#include <stdio.h>

#include "macros.h"

typedef struct
{
    uint16_t type;
    const char *name;
} RadiusAttributeMap;

static const RadiusAttributeMap g_radiusAttributeMap[] =
    {
        {USER_NAME, "User-Name"},
        {USER_PASSWORD, "User-Password"},
        {CHAP_PASSWORD, "CHAP-Password"},
        {NAS_IP_ADDRESS, "NAS-IP-Address"},
        {NAS_PORT, "NAS-Port"},
        {SERVICE_TYPE, "Service-Type"},
        {FRAMED_PROTOCOL, "Framed-Protocol"},
        {FRAMED_IP_ADDRESS, "Framed-IP-Address"},
        {FRAMED_IP_NETMASK, "Framed-IP-Netmask"},
        {FRAMED_ROUTING, "Framed-Routing"},
        {FILTER_ID, "Filter-Id"},
        {FRAMED_MTU, "Framed-MTU"},
        {FRAMED_COMPRESSION, "Framed-Compression"},
        {LOGIN_IP_HOST, "Login-IP-Host"},
        {LOGIN_SERVICE, "Login-Service"},
        {LOGIN_TCP_PORT, "Login-TCP-Port"},
        {REPLY_MESSAGE, "Reply-Message"},
        {CALLBACK_NUMBER, "Callback-Number"},
        {CALLBACK_ID, "Callback-Id"},
        {FRAMED_ROUTE, "Framed-Route"},
        {FRAMED_IPX_NETWORK, "Framed-IPX-Network"},
        {STATE, "State"},
        {CLASS, "Class"},
        {VENDOR_SPECIFIC, "Vendor-Specific"},
        {SESSION_TIMEOUT, "Session-Timeout"},
        {IDLE_TIMEOUT, "Idle-Timeout"},
        {TERMINATION_ACTION, "Termination-Action"},
        {CALLED_STATION_ID, "Called-Station-Id"},
        {CALLING_STATION_ID, "Calling-Station-Id"},
        {NAS_IDENTIFIER, "NAS-Identifier"},
        {PROXY_STATE, "Proxy-State"},
        {LOGIN_LAT_SERVICE, "Login-LAT-Service"},
        {LOGIN_LAT_NODE, "Login-LAT-Node"},
        {LOGIN_LAT_GROUP, "Login-LAT-Group"},
        {FRAMED_APPLETALK_LINK, "Framed-Appletalk-Link"},
        {FRAMED_APPLETALK_NETWORK, "Framed-Appletalk-Network"},
        {FRAMED_APPLETALK_ZONE, "Framed-Appletalk-Zone"},
        {ACCT_STATUS_TYPE, "Acct-Status-Type"},
        {ACCT_DELAY_TIME, "Acct-Delay-Time"},
        {ACCT_INPUT_OCTETS, "Acct-Input-Octets"},
        {ACCT_OUTPUT_OCTETS, "Acct-Output-Octets"},
        {ACCT_SESSION_ID, "Acct-Session-Id"},
        {ACCT_AUTHENTIC, "Acct-Authentic"},
        {ACCT_SESSION_TIME, "Acct-Session-Time"},
        {ACCT_INPUT_PACKETS, "Acct-Input-Packets"},
        {ACCT_OUTPUT_PACKETS, "Acct-Output-Packets"},
        {ACCT_TERMINATE_CAUSE, "Acct-Terminate-Cause"},
        {ACCT_MULTI_SESSION_ID, "Acct-Multi-Session-Id"},
        {ACCT_LINK_COUNT, "Acct-Link-Count"},
        {ACCT_INPUT_GIGAWORDS, "Acct-Input-Gigawords"},
        {ACCT_OUTPUT_GIGAWORDS, "Acct-Output-Gigawords"},
        {EVENT_TIMESTAMP, "Event-Timestamp"},
        {EGRESS_VLANID, "Egress-VLANID"},
        {INGRESS_FILTERS, "Ingress-Filters"},
        {EGRESS_VLAN_NAME, "Egress-VLAN-Name"},
        {USER_PRIORITY_TABLE, "User-Priority-Table"},
        {CHAP_CHALLENGE, "CHAP-Challenge"},
        {NAS_PORT_TYPE, "NAS-Port-Type"},
        {PORT_LIMIT, "Port-Limit"},
        {LOGIN_LAT_PORT, "Login-LAT-Port"},
        {TUNNEL_TYPE, "Tunnel-Type"},
        {TUNNEL_MEDIUM_TYPE, "Tunnel-Medium-Type"},
        {TUNNEL_CLIENT_ENDPOINT, "Tunnel-Client-Endpoint"},
        {TUNNEL_SERVER_ENDPOINT, "Tunnel-Server-Endpoint"},
        {ACCT_TUNNEL_CONNECTION, "Acct-Tunnel-Connection"},
        {TUNNEL_PASSWORD, "Tunnel-Password"},
        {ARAP_PASSWORD, "ARAP-Password"},
        {ARAP_FEATURES, "ARAP-Features"},
        {ARAP_ZONE_ACCESS, "ARAP-Zone-Access"},
        {ARAP_SECURITY, "ARAP-Security"},
        {ARAP_SECURITY_DATA, "ARAP-Security-Data"},
        {PASSWORD_RETRY, "Password-Retry"},
        {PROMPT, "Prompt"},
        {CONNECT_INFO, "Connect-Info"},
        {CONFIGURATION_TOKEN, "Configuration-Token"},
        {EAP_MESSAGE, "EAP-Message"},
        {MESSAGE_AUTHENTICATOR, "Message-Authenticator"},
        {TUNNEL_PRIVATE_GROUP_ID, "Tunnel-Private-Group-Id"},
        {TUNNEL_ASSIGNMENT_ID, "Tunnel-Assignment-Id"},
        {TUNNEL_PREFERENCE, "Tunnel-Preference"},
        {ARAP_CHALLENGE_RESPONSE, "ARAP-Challenge-Response"},
        {ACCT_INTERIM_INTERVAL, "Acct-Interim-Interval"},
        {ACCT_TUNNEL_PACKETS_LOST, "Acct-Tunnel-Packets-Lost"},
        {NAS_PORT_ID, "NAS-Port-Id"},
        {FRAMED_POOL, "Framed-Pool"},
        {CUI, "CUI"},
        {TUNNEL_CLIENT_AUTH_ID, "Tunnel-Client-Auth-Id"},
        {TUNNEL_SERVER_AUTH_ID, "Tunnel-Server-Auth-Id"},
        {NAS_FILTER_RULE, "NAS-Filter-Rule"},
        {ORIGINATING_LINE_INFO, "Originating-Line-Info"},
        {NAS_IPV6_ADDRESS, "NAS-IPv6-Address"},
        {FRAMED_INTERFACE_ID, "Framed-Interface-Id"},
        {FRAMED_IPV6_PREFIX, "Framed-IPv6-Prefix"},
        {LOGIN_IPV6_HOST, "Login-IPv6-Host"},
        {FRAMED_IPV6_ROUTE, "Framed-IPv6-Route"},
        {FRAMED_IPV6_POOL, "Framed-IPv6-Pool"},
        {ERROR_CAUSE, "Error-Cause"},
        {EAP_KEY_NAME, "EAP-Key-Name"},
        {DIGEST_RESPONSE, "Digest-Response"},
        {DIGEST_REALM, "Digest-Realm"},
        {DIGEST_NONCE, "Digest-Nonce"},
        {DIGEST_RESPONSE_AUTH, "Digest-Response-Auth"},
        {DIGEST_NEXTNONCE, "Digest-Nextnonce"},
        {DIGEST_METHOD, "Digest-Method"},
        {DIGEST_URI, "Digest-URI"},
        {DIGEST_QOP, "Digest-QOP"},
        {DIGEST_ALGORITHM, "Digest-Algorithm"},
        {DIGEST_ENTITY_BODY_HASH, "Digest-Entity-Body-Hash"},
        {DIGEST_CNONCE, "Digest-CNonce"},
        {DIGEST_NONCE_COUNT, "Digest-Nonce-Count"},
        {DIGEST_USERNAME, "Digest-Username"},
        {DIGEST_OPAQUE, "Digest-Opaque"},
        {DIGEST_AUTH_PARAM, "Digest-Auth-Param"},
        {DIGEST_AKA_AUTS, "Digest-AKA-AUTS"},
        {DIGEST_DOMAIN, "Digest-Domain"},
        {DIGEST_STALE, "Digest-Stale"},
        {DIGEST_HA1, "Digest-HA1"},
        {SIP_AOR, "SIP-AOR"},
        {DELEGATED_IPV6_PREFIX, "Delegated-IPv6-Prefix"},
        {MIP6_FEATURE_VECTOR, "MIP6-Feature-Vector"},
        {MIP6_HOME_LINK_PREFIX, "MIP6-Home-Link-Prefix"},
        {OPERATOR_NAME, "Operator-Name"},
        {LOCATION_INFORMATION, "Location-Information"},
        {LOCATION_DATA, "Location-Data"},
        {BASIC_LOCATION_POLICY_RULES, "Basic-Location-Policy-Rules"},
        {EXTENDED_LOCATION_POLICY_RULES, "Extended-Location-Policy-Rules"},
        {LOCATION_CAPABLE, "Location-Capable"},
        {REQUESTED_LOCATION_INFO, "Requested-Location-Info"}};

static inline const char *getRadiusAttributeName(uint16_t type)
{
    size_t count = sizeof(g_radiusAttributeMap) / sizeof(g_radiusAttributeMap[0]);

    for (size_t i = 0; i < count; i++)
    {
        if (g_radiusAttributeMap[i].type == type)
        {
            return g_radiusAttributeMap[i].name;
        }
    }

    return "Unknown-Attribute";
}