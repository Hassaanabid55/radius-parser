#include "worker.h"

TaskQueue global_queue __attribute__((aligned(64)));
pthread_t worker_threads[MAX_THREADS];
pthread_t stats_worker_threads;
pthread_t timeout_tid;
pthread_t stats_tid;
atomic_uint_fast64_t g_inflight_tasks = 0;

void queue_init(TaskQueue *q)
{
    memset(q, 0, sizeof(*q));

    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);

    q->shutdown = false;
}

bool queue_push(TaskQueue *restrict q, const Task *restrict task)
{
    pthread_mutex_lock(&q->mutex);
    while (__builtin_expect(q->count >= MAX_QUEUE_SIZE, 0) && !q->shutdown)
    {
        pthread_cond_wait(&q->not_full, &q->mutex);
    }

    if (__builtin_expect(q->shutdown, 0))
    {
        pthread_mutex_unlock(&q->mutex);
        return false;
    }

    q->tasks[q->tail] = *task;
    q->tail++;
    if (__builtin_expect(q->tail >= MAX_QUEUE_SIZE, 0))
        q->tail = 0;

    q->count++;
    queue_signal_not_empty(q);
    pthread_mutex_unlock(&q->mutex);
    return true;
}

bool queue_pop(TaskQueue *restrict q, Task *restrict task)
{
    pthread_mutex_lock(&q->mutex);
    while (__builtin_expect(q->count == 0, 0) && !q->shutdown)
    {
        pthread_cond_wait(&q->not_empty, &q->mutex);
    }

    if (__builtin_expect(q->count == 0 && q->shutdown, 0))
    {
        pthread_mutex_unlock(&q->mutex);
        return false;
    }

    *task = q->tasks[q->head];
    q->head++;
    if (__builtin_expect(q->head >= MAX_QUEUE_SIZE, 0))
        q->head = 0;

    q->count--;
    queue_signal_not_full(q);
    pthread_mutex_unlock(&q->mutex);
    return true;
}

void cleanup_queue(TaskQueue *q)
{
    pthread_mutex_lock(&q->mutex);
    while (q->count > 0)
    {
        Task *t = &q->tasks[q->head];
        if (t->data)
        {
            free(t->data);
            t->data = NULL;
        }
        q->head++;
        if (__builtin_expect(q->head >= MAX_QUEUE_SIZE, 0))
            q->head = 0;
        q->count--;
    }

    pthread_mutex_unlock(&q->mutex);
    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->not_full);
}

/* =========================
 THREAD CONTROL
 ========================= */
bool parse_core_ids(const char *core_list, int *cores, uint16_t *core_count)
{
    if (!core_list || !cores || !core_count)
    {
        return false;
    }

    *core_count = 0;
    char buffer[512];
    strncpy(buffer, core_list, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    char *saveptr = NULL;
    char *token = strtok_r(buffer, ",", &saveptr);
    while (token)
    {
        while (*token == ' ' || *token == '\t')
        {
            token++;
        }
        if (*token == '\0')
        {
            token = strtok_r(NULL, ",", &saveptr);
            continue;
        }
        char *dash = strchr(token, '-');

        if (!dash)
        {
            char *endptr = NULL;
            long core = strtol(token, &endptr, 10);
            if (*endptr != '\0' || core < 0)
            {
                syslog(LOG_ERR, "Invalid core specification: %s", token);
                return false;
            }
            if (*core_count >= MAX_CORE_COUNT)
            {
                syslog(LOG_ERR, "Too many cores");
                return false;
            }
            cores[(*core_count)++] = (int)core;
        }
        else
        {
            *dash = '\0';
            const char *start_str = token;
            const char *end_str = dash + 1;
            char *endptr1 = NULL;
            char *endptr2 = NULL;
            long start = strtol(start_str, &endptr1, 10);
            long end = strtol(end_str, &endptr2, 10);
            if (*endptr1 != '\0' || *endptr2 != '\0' || start < 0 || end < 0)
            {
                syslog(LOG_ERR, "Invalid core range: %s-%s", start_str, end_str);
                return false;
            }
            if (start > end)
            {
                syslog(LOG_ERR, "Invalid core range: %ld-%ld", start, end);
                return false;
            }
            for (long i = start; i <= end; i++)
            {
                if (*core_count >= MAX_CORE_COUNT)
                {
                    syslog(LOG_ERR, "Too many cores");
                    return false;
                }
                cores[(*core_count)++] = (int)i;
            }
        }
        token = strtok_r(NULL, ",", &saveptr);
    }
    for (uint16_t i = 0; i < *core_count; i++)
    {
        for (uint16_t j = i + 1; j < *core_count;)
        {
            if (cores[i] == cores[j])
            {
                memmove(&cores[j], &cores[j + 1], ((*core_count - j - 1) * sizeof(int)));
                (*core_count)--;
            }
            else
            {
                j++;
            }
        }
    }
    return true;
}

void wake_worker_threads(void)
{
    pthread_mutex_lock(&global_queue.mutex);
    pthread_cond_broadcast(&global_queue.not_empty);
    pthread_cond_broadcast(&global_queue.not_full);
    pthread_mutex_unlock(&global_queue.mutex);
}

/* =========================
 WORKER THREAD
 ========================= */
void *worker_thread(void *arg)
{
    int core_id = *(int *)arg;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(core_id, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    if (opt_verbosity > 0)
        syslog(LOG_INFO, "Worker thread started on core %d", core_id);
    Task task;
    struct timespec start;
    struct timespec end;
    uint64_t total_packets = 0;
    uint64_t total_processing_ns = 0;
    uint64_t parse_failures = 0;
    uint64_t attribute_failures = 0;
    while (__builtin_expect(g_running, 1))
    {
        if (__builtin_expect(!queue_pop(&global_queue, &task), 0))
        {
            break;
        }
        clock_gettime(CLOCK_MONOTONIC, &start);
        RadiusPacket radiusPkt;
        if (__builtin_expect(parseRadiusPkt((const char *)task.data, task.packet_length, &radiusPkt) == 0, 1))
        {
            UserSessionInfo session;
            if (__builtin_expect(readRadiusAttributes(&radiusPkt, &session) == 0, 1))
            {
                if (opt_verbosity > 1)
                {
                    printUserSession(&session);
                }
                switch (session.u8AccountStatusType)
                {
                case SESSION_START:
                {
                    rabbitmq_publish_session_start(&g_rabbitmq, &session);
                    rabbitmq_publish_session_sync(&g_rabbitmq, &session);
                }
                break;
                case SESSION_STOP:
                {
                    rabbitmq_publish_session_stop(&g_rabbitmq, &session);
                    rabbitmq_publish_session_delete(&g_rabbitmq, session.acAccountSessionId);
                }
                break;
                default:
                    break;
                }
            }
            else
            {
                attribute_failures++;
            }
        }
        else
        {
            parse_failures++;
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        total_processing_ns += timespec_diff_ns(&start, &end);
        total_packets++;
        atomic_fetch_sub(&g_inflight_tasks, 1);
        free(task.data);
    }
    const double total_ms = (double)total_processing_ns / 1000000.0;
    const double avg_us = (total_packets > 0) ? ((double)total_processing_ns / (double)total_packets / 1000.0) : 0.0;
    const double throughput_pps = (total_processing_ns > 0) ? ((double)total_packets / ((double)total_processing_ns / 1000000000.0)) : 0.0;
    if (opt_verbosity > 1)
        syslog(LOG_INFO, "Worker %d exiting | Packets=%lu | ParseFail=%lu | AttrFail=%lu | Total=%.3f ms | Avg=%.3f us/pkt | Throughput=%.2f pkt/sec", core_id, total_packets, parse_failures, attribute_failures, total_ms, avg_us, throughput_pps);
    return NULL;
}

void *session_stats_thread(void *arg)
{
    (void)arg;

    while (__builtin_expect(g_running, 1))
    {
        sleep(5);
        session_print_stats();
    }

    return NULL;
}

/* =========================
 THREAD INITIALIZATION
 ========================= */
void start_worker_threads(void)
{
    queue_init(&global_queue);
    parse_core_ids(opt_threads_str, cores, &core_count);
    for (uint16_t i = 0; i < core_count; i++)
    {
        pthread_create(&worker_threads[i], NULL, worker_thread, &cores[i]);
    }
    pthread_create(&timeout_tid, NULL, session_timeout_thread, NULL);
    pthread_create(&stats_tid, NULL, rabbitmq_stats_worker, NULL);
    if (opt_verbosity > 1)
        pthread_create(&stats_worker_threads, NULL, session_stats_thread, (void *)(intptr_t)0);
}

/* =========================
 TASK SUBMISSION
 ========================= */
void submit_task(Task *task)
{
    atomic_fetch_add(&g_inflight_tasks, 1);
    if (__builtin_expect(!queue_push(&global_queue, task), 0))
    {
        atomic_fetch_sub(&g_inflight_tasks, 1);
        free(task->data);
        task->data = NULL;
    }
}