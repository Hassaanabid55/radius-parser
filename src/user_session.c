#include "user_session.h"

static const char *session_type_str(uint8_t type)
{
    switch (type)
    {
    case SESSION_START:
        return "START";

    case SESSION_STOP:
        return "STOP";

    case SESSION_UPDATE:
        return "UPDATE";

    default:
        return "UNKNOWN";
    }
}

static void print_separator(void)
{
    syslog(LOG_INFO, "├──────────────────────────────────────────────────────────────");
}

static void print_header(void)
{
    syslog(LOG_INFO, "┌──────────────────────────────────────────────────────────────");
    syslog(LOG_INFO, "│ USER SESSION\n");
    print_separator();
}

static void print_footer(void)
{
    syslog(LOG_INFO, "└──────────────────────────────────────────────────────────────");
}

static void print_string_field(const char *label,
                               const char *value,
                               int valid)
{
    syslog(LOG_INFO, "│ %-22s : %s\n",
           label,
           valid ? value : "[not present]");
}

static void print_uint_field(const char *label,
                             uint32_t value,
                             int valid)
{
    if (valid)
    {
        syslog(LOG_INFO, "│ %-22s : %u\n", label, value);
    }
    else
    {
        syslog(LOG_INFO, "│ %-22s : [not present]\n", label);
    }
}

static void print_ipv4_field(const char *label,
                             const uint8_t *ip,
                             int valid)
{
    if (valid)
    {
        syslog(LOG_INFO, "│ %-22s : %u.%u.%u.%u\n",
               label,
               ip[0],
               ip[1],
               ip[2],
               ip[3]);
    }
    else
    {
        syslog(LOG_INFO, "│ %-22s : [not present]\n", label);
    }
}

static void print_ipv6_prefix_field(const char *label,
                                    const uint8_t *prefix,
                                    int valid)
{
    if (valid)
    {
        uint8_t prefixLen = prefix[1];

        char ip6[INET6_ADDRSTRLEN] = {0};

        inet_ntop(AF_INET6,
                  prefix + 2,
                  ip6,
                  sizeof(ip6));

        syslog(LOG_INFO, "│ %-22s : %s/%u\n",
               label,
               ip6,
               prefixLen);
    }
    else
    {
        syslog(LOG_INFO, "│ %-22s : [not present]\n", label);
    }
}

static void print_timestamp(uint32_t epoch, int valid)
{
    if (!valid)
    {
        syslog(LOG_INFO, "│ %-22s : [not present]\n", "Event Timestamp");
        return;
    }

    time_t t = (time_t)epoch;

    struct tm tm_info;
    localtime_r(&t, &tm_info);

    char buf[64] = {0};

    strftime(buf,
             sizeof(buf),
             "%Y-%m-%d %H:%M:%S",
             &tm_info);

    syslog(LOG_INFO, "│ %-22s : %u\n",
           "Event Timestamp",
           epoch);

    syslog(LOG_INFO, "│ %-22s : %s\n",
           "Event Time",
           buf);
}

static void print_extra_avps(const UserSessionInfo *s)
{
    if (!opt_extract_all)
        return;

    print_separator();

    syslog(LOG_INFO, "│ EXTRA AVPs (%u)\n",
           s->extra_avp_count);

    print_separator();

    for (uint16_t i = 0; i < s->extra_avp_count; i++)
    {
        const extra_avps *avp = &s->extra_avps[i];

        const char *name =
            getRadiusAttributeName(avp->type);

        syslog(LOG_INFO, "│ [%03u] %-30s Type=%-3u Len=%-3u\n",
               i + 1,
               name,
               avp->type,
               avp->len);

        syslog(LOG_INFO, "│ %-22s : ",
               "Value");

        for (uint16_t j = 0;
             j < avp->len - 2 && j < MAX_AVP_VALUE;
             j++)
        {
            syslog(LOG_INFO, "│ %-22s : %02x ",
                   "Value",
                   avp->value[j]);
        }

        syslog(LOG_INFO, "\n");
    }
}

void printUserSession(const UserSessionInfo *s)
{
    if (!s)
        return;

    print_header();

    print_string_field("Session Type",
                       session_type_str(s->nSessionIndicator),
                       1);

    print_uint_field("Radius Length",
                     s->radiusLength,
                     1);

    print_string_field("Session ID",
                       s->acAccountSessionId,
                       s->u64ValidAttributes & VALID_ACCT_SESSION_ID);

    print_string_field("Multi Session ID",
                       s->acMultiSessionId,
                       s->u64ValidAttributes & VALID_ACCT_MULTI_SESSION_ID);

    print_string_field("Calling Station",
                       s->acCallingStationId,
                       s->u64ValidAttributes & VALID_CALLING_STATION_ID);

    print_ipv4_field("Framed IPv4",
                     s->u8FramedIpv4Address,
                     s->u64ValidAttributes & VALID_FRAMED_IPV4);

    print_ipv6_prefix_field("Framed IPv6 Prefix",
                            s->u8FramedIpv6Prefix,
                            s->u64ValidAttributes & VALID_FRAMED_IPV6_PREFIX);

    print_timestamp(s->u32EventTimestamp,
                    s->u64ValidAttributes & VALID_EVENT_TIMESTAMP);

    print_string_field("WL Status",
                       s->u8IsWL ? "YES" : "NO",
                       1);

    print_extra_avps(s);

    print_footer();
}