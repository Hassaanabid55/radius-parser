#pragma once

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <sched.h>
#include <errno.h>
#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <signal.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <sys/time.h>
#include <stdatomic.h>

#include "parser.h"

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
    bool shutdown;
} TaskQueue;

extern char opt_threads_str[128];
extern volatile sig_atomic_t g_running;
extern TaskQueue global_queue __attribute__((aligned(64)));
extern pthread_t worker_threads[MAX_THREADS];
extern pthread_t stats_worker_threads;
extern pthread_t timeout_tid;
extern int cores[MAX_CORE_COUNT];
extern uint16_t core_count;
extern atomic_uint_fast64_t g_inflight_tasks;

static inline void queue_signal_not_empty(TaskQueue *q)
{
    pthread_cond_signal(&q->not_empty);
}

static inline void queue_signal_not_full(TaskQueue *q)
{
    pthread_cond_signal(&q->not_full);
}

static inline uint64_t timespec_diff_ns(const struct timespec *start, const struct timespec *end)
{
    return (((uint64_t)(end->tv_sec - start->tv_sec) * 1000000000ULL) + ((uint64_t)(end->tv_nsec - start->tv_nsec)));
}

void queue_init(TaskQueue *q);
bool queue_push(TaskQueue *restrict q, const Task *restrict task);
bool queue_pop(TaskQueue *restrict q, Task *restrict task);
void cleanup_queue(TaskQueue *q);
bool parse_core_ids(const char *core_list, int *cores, uint16_t *core_count);
void *worker_thread(void *arg);
void session_print_stats();
void wake_worker_threads(void);
void start_worker_threads(void);
void submit_task(Task *task);