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
        Task *t = &q->tasks[q->head];

        // if (t->data)
        // {
        //     free(t->data);
        //     t->data = NULL;
        // }

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

    syslog(LOG_INFO, "Worker thread started (ID: %d)\n", id);

    while (1)
    {
        if (!queue_pop(&global_queue, &task))
            break;

        if (!g_running)
            break;

        RadiusPacket radiusPkt;

        if (parseRadiusPkt((const char *)task.data, task.packet_length, &radiusPkt) == 0)
        {
            UserSessionInfo session;
            if (readRadiusAttributes(&radiusPkt, &session) == 0)
            {
                printUserSession(&session);
            }
        }

        free(task.data);
    }
    syslog(LOG_INFO, "Worker thread exiting (ID: %d)\n", id);

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