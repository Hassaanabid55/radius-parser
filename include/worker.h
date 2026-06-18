#include "parser.h"

extern char opt_threads_str[128];
extern volatile sig_atomic_t g_running;
extern TaskQueue global_queue __attribute__((aligned(64)));
extern pthread_t worker_threads[MAX_THREADS];
extern pthread_t stats_worker_threads;
extern pthread_t timeout_tid;
extern pthread_t rabbit_pub_tid;
extern pthread_t stats_tid;
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

extern void *role_election_thread(void *arg);