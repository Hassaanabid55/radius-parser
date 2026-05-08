#pragma once

#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>
#include <pcap.h>

#include <netinet/ip.h>
#include <netinet/udp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#include "worker.h"
#include "parser.h"

extern char opt_interface_name[64];
extern uint16_t opt_caplen;
extern volatile bool g_running;
extern uint32_t opt_ring_buffer_size; // 512MB
extern pcap_t *g_pcap_handle;

bool build_radius_task(Task *task, const struct pcap_pkthdr *header, const uint8_t *packet);
void packet_handler(unsigned char *user, const struct pcap_pkthdr *header, const unsigned char *packet);
void start_interface_capture();
void cleanup_interface();