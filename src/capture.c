#include "capture.h"

pcap_t *g_pcap_handle = NULL;

bool build_radius_task(Task *task, const struct pcap_pkthdr *header, const uint8_t *packet)
{
    memset(task, 0, sizeof(Task));
    task->packet_length = header->caplen;
    task->timestamp = header->ts;

    /*
     * Ethernet
     */

    if (header->caplen < sizeof(struct ethhdr))
    {
        return false;
    }

    task->pEthernet = packet;
    struct ethhdr *eth =
        (struct ethhdr *)packet;
    task->ethertype = ntohs(eth->h_proto);
    if (task->ethertype != ETH_P_IP)
    {
        return false;
    }

    /*
     * IPv4
     */

    task->ip_offset = sizeof(struct ethhdr);
    if (header->caplen <
        task->ip_offset + sizeof(struct iphdr))
    {
        return false;
    }

    task->pIp = packet + task->ip_offset;
    struct iphdr *ip =
        (struct iphdr *)task->pIp;
    task->ip_version = ip->version;
    task->ip_protocol = ip->protocol;
    if (ip->protocol != IPPROTO_UDP)
    {
        return false;
    }
    task->ip_header_length = ip->ihl * 4;
    task->src_ip = ip->saddr;
    task->dst_ip = ip->daddr;

    /*
     * UDP
     */

    task->udp_offset =
        task->ip_offset + task->ip_header_length;
    if (header->caplen <
        task->udp_offset + sizeof(struct udphdr))
    {
        return false;
    }
    task->pUdp = packet + task->udp_offset;
    struct udphdr *udp =
        (struct udphdr *)task->pUdp;
    task->src_port = ntohs(udp->source);
    task->dst_port = ntohs(udp->dest);

    /*
     * RADIUS port validation
     */

    if (task->src_port == RADIUS_ACCT_PORT_1 ||
        task->dst_port == RADIUS_ACCT_PORT_1)
    {
        task->packet_type = PKT_RADIUS_AUTH;
    }
    else if (task->src_port == RADIUS_ACCT_PORT_2 ||
             task->dst_port == RADIUS_ACCT_PORT_2)
    {
        task->packet_type = PKT_RADIUS_ACCT;
    }
    else
    {
        return false;
    }

    /*
     * RADIUS layer
     */

    task->radius_offset =
        task->udp_offset + sizeof(struct udphdr);

    if (header->caplen <
        (bpf_u_int32)(task->radius_offset + RADIUS_HDR_LEN))
    {
        return false;
    }

    task->pRadius =
        packet + task->radius_offset;

    /*
     * Validate RADIUS length
     */

    uint16_t radiusLen;

    memcpy(&radiusLen,
           task->pRadius + 2,
           sizeof(radiusLen));

    radiusLen = ntohs(radiusLen);
    if (radiusLen < RADIUS_HDR_LEN)
    {
        return false;
    }
    if (task->radius_offset + radiusLen >
        header->caplen)
    {
        return false;
    }
    task->radius_length = radiusLen;

    return true;
}

/* =========================
 PACKET CALLBACK
 ========================= */
void packet_handler(unsigned char *user,
                    const struct pcap_pkthdr *header,
                    const unsigned char *packet)
{
    (void)user;

    if (!g_running)
    {
        return;
    }

    Task task;

    if (!build_radius_task(&task, header, packet))
    {
        return;
    }

    /*
     * Copy packet
     */

    task.data = malloc(header->caplen);

    if (!task.data)
    {
        return;
    }

    memcpy(task.data,
           packet,
           header->caplen);

    /*
     * Rebase pointers after memcpy
     */
    task.pEthernet =
        task.data + task.ethernet_offset;
    task.pIp =
        task.data + task.ip_offset;
    task.pUdp =
        task.data + task.udp_offset;
    task.pRadius =
        task.data + task.radius_offset;

    submit_task(&task);
}

/* =========================
 INTERFACE CAPTURE
 ========================= */

void start_interface_capture()
{
    char errbuf[PCAP_ERRBUF_SIZE];

    while (g_running)
    {
        pcap_t *handle = pcap_create(opt_interface_name, errbuf);

        if (!handle)
        {
            syslog(LOG_ERR,
                   "pcap_create failed: %s",
                   errbuf);

            sleep(1);

            continue;
        }

        /*
         * Configure capture
         */

        if (pcap_set_snaplen(handle, opt_caplen) != 0)
        {
            syslog(LOG_ERR,
                   "pcap_set_snaplen failed");

            pcap_close(handle);

            sleep(1);

            continue;
        }

        /*
         * Promiscuous mode
         */

        if (pcap_set_promisc(handle, 1) != 0)
        {
            syslog(LOG_ERR,
                   "pcap_set_promisc failed");

            pcap_close(handle);

            sleep(1);

            continue;
        }

        /*
         * Immediate mode for low latency
         */

#ifdef PCAP_ERROR_ACTIVATED
        pcap_set_immediate_mode(handle, 1);
#endif

        /*
         * Set interface kernel ring buffer size
         */

        if (pcap_set_buffer_size(handle,
                                 opt_ring_buffer_size) != 0)
        {
            syslog(LOG_ERR,
                   "pcap_set_buffer_size failed");
        }

        /*
         * Read timeout
         */

        if (pcap_set_timeout(handle, 0) != 0)
        {
            syslog(LOG_ERR,
                   "pcap_set_timeout failed");
        }

        /*
         * Activate interface
         */

        int ret = pcap_activate(handle);

        if (ret < 0)
        {
            syslog(LOG_ERR,
                   "pcap_activate failed: %s",
                   pcap_geterr(handle));

            pcap_close(handle);

            sleep(1);

            continue;
        }

        g_pcap_handle = handle;

        syslog(LOG_INFO,
               "Listening on interface: %s",
               opt_interface_name);

        /*
         * Persistent capture loop
         */

        while (g_running)
        {
            ret = pcap_dispatch(handle,
                                -1,
                                packet_handler,
                                NULL);

            if (ret == PCAP_ERROR)
            {
                syslog(LOG_ERR,
                       "pcap_dispatch error: %s",
                       pcap_geterr(handle));

                break;
            }

            if (ret == PCAP_ERROR_BREAK)
            {
                break;
            }
        }

        syslog(LOG_INFO,
               "Capture loop exited, closing interface...");
        pcap_close(handle);

        g_pcap_handle = NULL;

        /*
         * Retry interface setup
         */

        if (g_running)
        {
            syslog(LOG_INFO,
                   "Reconnecting capture interface...");

            sleep(1);
        }
    }
}

void stop_interface_capture()
{
    if (g_pcap_handle)
    {
        pcap_breakloop(g_pcap_handle);
        pcap_close(g_pcap_handle);
        g_pcap_handle = NULL;
    }
}