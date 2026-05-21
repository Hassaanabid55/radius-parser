#include "capture.h"

pcap_t *g_pcap_handle = NULL;

/* =========================
 BUILD TASK
 ========================= */
bool build_radius_task(Task *restrict task, const struct pcap_pkthdr *restrict header, const uint8_t *restrict packet)
{
    memset(task, 0, sizeof(Task));
    const uint32_t caplen = header->caplen;
    task->packet_length = caplen;
    task->timestamp = header->ts;

    /*
     * Ethernet validation
     */
    if (__builtin_expect(caplen < sizeof(struct ethhdr), 0))
    {
        return false;
    }

    task->pEthernet = packet;

    const struct ethhdr *eth = (const struct ethhdr *)packet;
    const uint16_t ethertype = ntohs(eth->h_proto);
    task->ethertype = ethertype;
    if (__builtin_expect(!is_ipv4_packet(ethertype), 1))
    {
        return false;
    }

    /*
     * IPv4
     */
    task->ethernet_offset = 0;
    task->ip_offset = sizeof(struct ethhdr);
    const struct iphdr *ip = (const struct iphdr *)(packet + task->ip_offset);
    if (__builtin_expect(caplen < task->ip_offset + sizeof(struct iphdr), 0))
    {
        return false;
    }

    const uint8_t ip_hdr_len = (uint8_t)(ip->ihl << 2);
    if (__builtin_expect(ip_hdr_len < sizeof(struct iphdr), 0))
    {
        return false;
    }

    task->ip_header_length = ip_hdr_len;
    task->ip_version = ip->version;
    task->ip_protocol = ip->protocol;
    if (__builtin_expect(!is_udp_packet(ip->protocol), 1))
    {
        return false;
    }

    task->src_ip = ip->saddr;
    task->dst_ip = ip->daddr;

    task->pIp = (const uint8_t *)ip;

    /*
     * UDP
     */
    task->udp_offset = task->ip_offset + ip_hdr_len;
    if (__builtin_expect(caplen < task->udp_offset + sizeof(struct udphdr), 0))
    {
        return false;
    }

    const struct udphdr *udp = (const struct udphdr *)(packet + task->udp_offset);
    task->pUdp = (const uint8_t *)udp;
    const uint16_t src_port = ntohs(udp->source);
    const uint16_t dst_port = ntohs(udp->dest);
    task->src_port = src_port;
    task->dst_port = dst_port;

    /*
     * Validate RADIUS ports
     */
    fprintf(stderr, "ports: src=%u dst=%u\n", src_port, dst_port);
    if (__builtin_expect(!is_radius_port(src_port, dst_port, &task->packet_type), 1))
    {
        return false;
    }

    /*
     * RADIUS
     */
    task->radius_offset = task->udp_offset + sizeof(struct udphdr);
    const uint32_t min_radius_size = (uint32_t)(task->radius_offset + RADIUS_HDR_LEN);
    if (__builtin_expect(caplen < min_radius_size, 0))
    {
        return false;
    }

    const uint8_t *radius = packet + task->radius_offset;
    task->pRadius = radius;

    /*
     * Validate RADIUS length
     */
    uint16_t radius_len;
    memcpy(&radius_len, radius + 2, sizeof(uint16_t));
    radius_len = ntohs(radius_len);
    if (__builtin_expect(radius_len < RADIUS_HDR_LEN, 0))
    {
        return false;
    }

    if (__builtin_expect(task->radius_offset + radius_len > caplen, 0))
    {
        return false;
    }
    task->radius_length = radius_len;
    return true;
}

/* =========================
 PACKET CALLBACK
 ========================= */
void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet)
{
    (void)user;
    if (__builtin_expect(!g_running, 0))
    {
        return;
    }

    Task task;
    if (__builtin_expect(!build_radius_task(&task, header, packet), 1))
    {
        return;
    }

    /*
     * Allocate packet memory
     */
    uint8_t *pkt = malloc(header->caplen);
    if (__builtin_expect(pkt == NULL, 0))
    {
        return;
    }

    memcpy(pkt, packet, header->caplen);
    task.data = pkt;

    /*
     * Rebase pointers
     */
    task.pEthernet = pkt + task.ethernet_offset;
    task.pIp = pkt + task.ip_offset;
    task.pUdp = pkt + task.udp_offset;
    task.pRadius = pkt + task.radius_offset;
    submit_task(&task);
}

/* =========================
 INTERFACE CAPTURE
 ========================= */
void start_interface_capture(void)
{
    char errbuf[PCAP_ERRBUF_SIZE];
    while (__builtin_expect(g_running, 1))
    {
        pcap_t *handle = pcap_create(opt_interface_name, errbuf);

        if (__builtin_expect(handle == NULL, 0))
        {
            syslog(LOG_ERR, "pcap_create failed: %s", errbuf);
            sleep(1);
            continue;
        }

        /*
         * Snap length
         */
        if (__builtin_expect(pcap_set_snaplen(handle, opt_caplen) != 0, 0))
        {
            syslog(LOG_ERR, "pcap_set_snaplen failed");
            pcap_close(handle);
            sleep(1);
            continue;
        }

        /*
         * Promisc
         */
        pcap_set_promisc(handle, 1);

        /*
         * Immediate mode
         */
#ifdef PCAP_ERROR_ACTIVATED
        pcap_set_immediate_mode(handle, 1);
#endif

        /*
         * Kernel buffer
         */
        pcap_set_buffer_size(handle, opt_ring_buffer_size);

        /*
         * Non-buffered reads
         */
        pcap_set_timeout(handle, 0);

        /*
         * Activate
         */
        const int ret = pcap_activate(handle);
        if (__builtin_expect(ret < 0, 0))
        {
            syslog(LOG_ERR, "pcap_activate failed: %s", pcap_geterr(handle));
            pcap_close(handle);
            sleep(1);
            continue;
        }
        g_pcap_handle = handle;
        if (opt_verbosity > 0)
            syslog(LOG_INFO, "Listening on interface: %s", opt_interface_name);

        /*
         * Main capture loop
         */
        while (__builtin_expect(g_running, 1))
        {
            const int dispatch_ret = pcap_dispatch(handle, -1, packet_handler, NULL);
            if (__builtin_expect(dispatch_ret == PCAP_ERROR, 0))
            {
                syslog(LOG_ERR, "pcap_dispatch error: %s", pcap_geterr(handle));
                break;
            }

            if (__builtin_expect(dispatch_ret == PCAP_ERROR_BREAK, 0))
            {
                break;
            }
        }

        if (opt_verbosity > 0)
            syslog(LOG_INFO, "Capture stopped");
        pcap_close(handle);
        g_pcap_handle = NULL;
        if (__builtin_expect(g_running, 1))
        {
            sleep(1);
        }
    }
}

void stop_interface_capture(void)
{
    pcap_t *handle = g_pcap_handle;
    if (handle)
    {
        g_pcap_handle = NULL;
        pcap_breakloop(handle);
        pcap_close(handle);
    }
}

void print_session_map(void)
{
    SessionNode *s, *tmp;
    size_t count = 0;

    syslog(LOG_INFO, "========== SESSION MAP DUMP ==========");

    HASH_ITER(hh, g_session_map, s, tmp)
    {
        syslog(LOG_INFO,
               "SessionID: %s",
               s->acAccountSessionId);

        count++;
    }

    syslog(LOG_INFO, "Total sessions: %zu", count);
    syslog(LOG_INFO, "======================================");
}

/* =========================
 PCAP FILE CAPTURE
 ========================= */
void start_file_capture(const char *file_path)
{
    char errbuf[PCAP_ERRBUF_SIZE];

    if (__builtin_expect(opt_verbosity > 0, 0))
        syslog(LOG_INFO, "Opening pcap file: %s", file_path);

    pcap_t *handle = pcap_open_offline(file_path, errbuf);
    if (__builtin_expect(handle == NULL, 0))
    {
        syslog(LOG_ERR, "pcap_open_offline failed: %s", errbuf);
        return;
    }

    g_pcap_handle = handle;

    if (opt_verbosity > 0)
        syslog(LOG_INFO, "Processing pcap file: %s", file_path);

    struct pcap_pkthdr *header;
    const unsigned char *packet;
    int ret;
    uint64_t pkt_num = 0;
    while (__builtin_expect(g_running, 1))
    {
        ret = pcap_next_ex(handle, &header, &packet);
        if (__builtin_expect(ret == 1, 1))
        {
            pkt_num++;
            packet_handler(NULL, header, packet);
        }
        else if (ret == 0)
        {
            continue; // timeout (rare in offline, safe ignore)
        }
        else if (ret == -1)
        {
            syslog(LOG_ERR, "pcap_next_ex error at packet #%lu: %s", pkt_num, pcap_geterr(handle));
            continue;
        }
        else if (ret == -2)
        {
            syslog(LOG_INFO, "End of pcap file reached");
            break;
        }
    }
    pcap_close(handle);
    if (opt_verbosity > 0)
        syslog(LOG_INFO, "PCAP finished. Waiting for task queue to drain...");

    while (__builtin_expect(atomic_load(&g_inflight_tasks) > 0, 1))
    {
        usleep(1000); // avoid busy spin
    }
    
    if (opt_verbosity > 2)
        print_session_map();

    if (opt_verbosity > 0)
        syslog(LOG_INFO, "Task queue drained. File capture completed");
}