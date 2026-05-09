#include "worker.h"

TaskQueue global_queue;
pthread_t worker_threads[MAX_THREADS];

/* =========================
 QUEUE FUNCTIONS
 ========================= */

void queue_init(TaskQueue *q)
{
    memset(q, 0, sizeof(*q));

    pthread_mutex_init(&q->mutex, NULL);
    pthread_cond_init(&q->not_empty, NULL);
    pthread_cond_init(&q->not_full, NULL);

    q->shutdown = false;
}

bool queue_push(TaskQueue *q, Task *task)
{
    pthread_mutex_lock(&q->mutex);

    while (q->count >= MAX_QUEUE_SIZE && !q->shutdown)
    {
        pthread_cond_wait(&q->not_full, &q->mutex);
    }

    if (q->shutdown)
    {
        pthread_mutex_unlock(&q->mutex);
        return false;
    }

    q->tasks[q->tail] = *task;
    q->tail = (q->tail + 1) % MAX_QUEUE_SIZE;
    q->count++;

    pthread_cond_signal(&q->not_empty);

    pthread_mutex_unlock(&q->mutex);

    return true;
}

bool queue_pop(TaskQueue *q, Task *task)
{
    pthread_mutex_lock(&q->mutex);

    while (q->count == 0 && !q->shutdown)
    {
        pthread_cond_wait(&q->not_empty, &q->mutex);
    }

    if (q->count == 0 && q->shutdown)
    {
        pthread_mutex_unlock(&q->mutex);
        return false;
    }

    *task = q->tasks[q->head];
    q->head = (q->head + 1) % MAX_QUEUE_SIZE;
    q->count--;

    pthread_cond_signal(&q->not_full);

    pthread_mutex_unlock(&q->mutex);

    return true;
}

void cleanup_queue(TaskQueue *q)
{
    pthread_mutex_lock(&q->mutex);

    /* free remaining tasks */
    while (q->count > 0)
    {
        // Task *t = &q->tasks[q->head];

        if (q->tasks[q->head].data)
        {
            free(q->tasks[q->head].data);
            q->tasks[q->head].data = NULL;
        }

        q->head = (q->head + 1) % MAX_QUEUE_SIZE;
        q->count--;
    }

    pthread_mutex_unlock(&q->mutex);

    pthread_mutex_destroy(&q->mutex);
    pthread_cond_destroy(&q->not_empty);
    pthread_cond_destroy(&q->not_full);
}

/* =========================
 WORKER THREAD
 ========================= */

void wake_worker_threads()
{
    pthread_mutex_lock(&global_queue.mutex);
    pthread_cond_broadcast(&global_queue.not_empty);
    pthread_cond_broadcast(&global_queue.not_full);
    pthread_mutex_unlock(&global_queue.mutex);
}

void *worker_thread(void *arg)
{
    Task task;
    int id = (intptr_t)arg;
    struct timespec start;
    struct timespec end;
    uint64_t total_packets = 0;
    uint64_t total_processing_ns = 0;
    syslog(LOG_INFO, "Worker thread started (ID: %d)", id);

    while (1)
    {
        if (!queue_pop(&global_queue, &task))
            break;

        if (!g_running)
            break;

        clock_gettime(CLOCK_MONOTONIC, &start);
        RadiusPacket radiusPkt;

        if (parseRadiusPkt((const char *)task.data, task.packet_length, &radiusPkt) == 0)
        {
            UserSessionInfo session;
            if (readRadiusAttributes(&radiusPkt, &session) == 0)
            {
                printUserSession(&session);
            }
        }
        clock_gettime(CLOCK_MONOTONIC, &end);
        uint64_t elapsed_ns = ((uint64_t)(end.tv_sec - start.tv_sec) * 1000000000ULL) + (uint64_t)(end.tv_nsec - start.tv_nsec);
        total_processing_ns += elapsed_ns;
        total_packets++;

        /*
         * Optional per-packet timing
         */

        syslog(LOG_DEBUG, "Worker %d processed packet in %.3f ms", id, (double)elapsed_ns / 1000000.0);
        free(task.data);
    }
    double total_ms = (double)total_processing_ns / 1000000.0;
    double avg_ms = (total_packets > 0) ? (total_ms / total_packets) : 0.0;

    syslog(LOG_INFO,
           "Worker thread exiting (ID: %d) | "
           "Packets: %lu | "
           "Total Time: %.3f ms | "
           "Average: %.3f ms/packet",
           id,
           total_packets,
           total_ms,
           avg_ms);

    return NULL;
}

/* =========================
 THREAD INITIALIZATION
 ========================= */

void start_worker_threads()
{
    queue_init(&global_queue);

    for (uint8_t i = 0; i < opt_threads; i++)
    {
        int *thread_id = malloc(sizeof(int));
        *thread_id = i;
        pthread_create(&worker_threads[i], NULL, worker_thread, (void *)(intptr_t)i);
    }
}

/* =========================
 TASK SUBMISSION
 ========================= */

void submit_task(Task *task)
{
    if (!queue_push(&global_queue, task))
    {
        free(task->data);
    }
}