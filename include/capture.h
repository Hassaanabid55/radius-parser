#pragma once

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <pcap.h>
#include <sys/syslog.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "worker.h"

extern char opt_interface_name[64];
extern uint16_t opt_caplen;
extern volatile sig_atomic_t g_running;
extern uint32_t opt_ring_buffer_size; // 512MB
extern pcap_t *g_pcap_handle;

static inline bool is_ipv4_packet(uint16_t ethertype)
{
    return ethertype == ETH_P_IP;
}

static inline bool is_udp_packet(uint8_t proto)
{
    return proto == IPPROTO_UDP;
}

static inline bool is_radius_port(uint16_t src, uint16_t dst, PacketType *pkt_type)
{
    if (__builtin_expect(src == RADIUS_ACCT_PORT_1 || dst == RADIUS_ACCT_PORT_1, 0))
    {
        *pkt_type = PKT_RADIUS_AUTH;
        return true;
    }

    if (__builtin_expect(src == RADIUS_ACCT_PORT_2 || dst == RADIUS_ACCT_PORT_2, 1))
    {
        *pkt_type = PKT_RADIUS_ACCT;
        return true;
    }

    return false;
}

bool build_radius_task(Task *restrict task, const struct pcap_pkthdr *restrict header, const uint8_t *restrict packet);
void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet);
void start_interface_capture(void);
void stop_interface_capture(void);
void print_session_map(void);
void start_file_capture(const char *file_path);