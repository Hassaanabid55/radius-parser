#pragma once

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <pthread.h>
#include <sys/time.h>

#include "parser.h"

#define MAX_QUEUE_SIZE 4096
#define MAX_THREADS 64

typedef enum
{
    L4_UNKNOWN = 0,
    L4_TCP,
    L4_UDP

} L4Protocol;

/* =========================
 TASK STRUCTURE
 ========================= */

typedef enum
{
    PKT_UNKNOWN = 0,
    PKT_RADIUS_AUTH,
    PKT_RADIUS_ACCT

} PacketType;

typedef struct
{
    /*
     * Raw packet
     */
    uint8_t *data;
    uint32_t packet_length;

    /*
     * Timestamp
     */
    struct timeval timestamp;

    /*
     * Layer offsets
     */
    uint16_t ethernet_offset;
    uint16_t ip_offset;
    uint16_t udp_offset;
    uint16_t radius_offset;

    /*
     * Layer lengths
     */
    uint16_t ip_header_length;
    uint16_t udp_length;
    uint16_t radius_length;

    /*
     * Parsed protocol info
     */
    uint16_t ethertype;
    uint8_t ip_version;
    uint8_t ip_protocol;
    uint32_t src_ip;
    uint32_t dst_ip;
    uint16_t src_port;
    uint16_t dst_port;

    /*
     * Packet classification
     */
    PacketType packet_type;

    /*
     * Direct protocol pointers
     */
    const uint8_t *pEthernet;
    const uint8_t *pIp;
    const uint8_t *pUdp;
    const uint8_t *pRadius;
} Task;

/* =========================
 SHARED QUEUE
 ========================= */

typedef struct
{
    Task tasks[MAX_QUEUE_SIZE];
    int head;
    int tail;
    int count;
    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;
} TaskQueue;

extern uint8_t opt_threads;
extern volatile bool g_running;
extern TaskQueue global_queue;
extern pthread_t worker_threads[MAX_THREADS];

void queue_init(TaskQueue *q);
bool queue_push(TaskQueue *q, Task *task);
bool queue_pop(TaskQueue *q, Task *task);
void *worker_thread(void *arg);
void start_worker_threads();
void submit_task(Task *task);
void cleanup_queue(TaskQueue *q);