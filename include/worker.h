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

typedef struct SessionNode
{
    char acAccountSessionId[SESSION_ID_MAX_LEN];
    UserSessionInfo entry;
    UT_hash_handle hh;
} SessionNode;

extern char opt_threads_str[128];
extern volatile sig_atomic_t g_running;
extern TaskQueue global_queue __attribute__((aligned(64)));
extern pthread_t worker_threads[MAX_THREADS];
extern pthread_t stats_worker_threads;

extern SessionNode *g_session_map;
extern pthread_mutex_t g_session_mutex;
extern int cores[MAX_CORE_COUNT];
extern uint16_t core_count;

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

static inline SessionNode *session_find(const char *id)
{
    if (__builtin_expect(!id, 0))
        return NULL;

    SessionNode *node = NULL;
    HASH_FIND_STR(g_session_map, id, node);
    return node;
}

static inline void session_insert(const UserSessionInfo *s)
{
    SessionNode *node = malloc(sizeof(SessionNode));
    if (!node)
        return;

    memset(node, 0, sizeof(*node));
    strncpy(node->acAccountSessionId, s->acAccountSessionId, sizeof(node->acAccountSessionId));
    node->entry = *s;
    HASH_ADD_STR(g_session_map, acAccountSessionId, node);
}

static inline void session_delete(SessionNode *node)
{
    HASH_DEL(g_session_map, node);
    free(node);
}

static inline bool session_ip_changed(SessionNode *node, const UserSessionInfo *s)
{
    return (memcmp(node->entry.u8FramedIpv4Address, s->u8FramedIpv4Address, IPV4_OCTETS) != 0 || memcmp(node->entry.u8FramedIpv6Prefix, s->u8FramedIpv6Prefix, IPV6_PREFIX_MAX_LEN) != 0);
}

static inline int bind_thread_to_core(int core_id)
{
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    int ret = pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    if (ret != 0)
    {
        syslog(LOG_ERR, "pthread_setaffinity_np failed for core %d: %s", core_id, strerror(ret));
        return -1;
    }
    cpu_set_t verify_set;
    CPU_ZERO(&verify_set);
    ret = pthread_getaffinity_np(pthread_self(), sizeof(cpu_set_t), &verify_set);
    if (ret != 0)
    {
        syslog(LOG_ERR, "pthread_getaffinity_np failed: %s", strerror(ret));
        return -1;
    }

    for (int i = 0; i < CPU_SETSIZE; i++)
    {
        if (i == core_id)
        {
            if (!CPU_ISSET(i, &verify_set))
            {
                syslog(LOG_ERR, "Core %d not set in affinity mask", core_id);
                return -1;
            }
        }
        else
        {
            if (CPU_ISSET(i, &verify_set))
            {
                syslog(LOG_ERR, "Thread affinity leaked to core %d", i);
                return -1;
            }
        }
    }
    if (opt_verbosity > 0)
        syslog(LOG_INFO, "Thread hard-bound to CPU core %d", core_id);
    return 0;
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