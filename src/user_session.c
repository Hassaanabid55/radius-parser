#include "user_session.h"

/* =========================================================
 * MAIN SESSION LOGGER
 * ========================================================= */
void printUserSession(const UserSessionInfo *s)
{
    if (__builtin_expect(!s, 0))
        return;

    LOG_HEADER();

    /*
     * Session Type
     */
    print_string_field("Session Type", session_type_str(s->nSessionIndicator), 1);

    /*
     * Session ID
     */
    print_string_field("Session ID", s->acAccountSessionId, s->u64ValidAttributes & VALID_ACCT_SESSION_ID);

    /*
     * Multi Session ID
     */
    print_string_field("Multi Session ID", s->acMultiSessionId, s->u64ValidAttributes & VALID_ACCT_MULTI_SESSION_ID);

    /*
     * Calling Station
     */
    print_string_field("Calling Station", s->acCallingStationId, s->u64ValidAttributes & VALID_CALLING_STATION_ID);

    /*
     * Private IPv4
     */
    print_ipv4_field("Framed IPv4 (Private)", s->u8FramedIpv4Address, s->u64ValidAttributes & VALID_FRAMED_IPV4);

    /*
     * Public IPv4
     */
    print_ipv4_field("Framed IPv4 (Public)", s->u8FramedIpv4PubAddress, (s->portStart != 0 || s->portEnd != 0));

    /*
     * IPv6 Prefix
     */
    print_ipv6_prefix_field("Framed IPv6 Prefix", s->u8FramedIpv6Prefix, s->u64ValidAttributes & VALID_FRAMED_IPV6_PREFIX);

    /*
     * NAT Port Range
     */
    print_port_range(s);

    /*
     * Timestamp
     */
    print_timestamp(s->u32EventTimestamp, s->u64ValidAttributes & VALID_EVENT_TIMESTAMP);

    /*
     * WL Status
     */
    print_string_field("WL Status", s->u8IsWL ? "YES" : "NO", 1);

    /*
     * Extra AVPs
     */
    print_extra_avps(s);
    LOG_FOOTER();
}