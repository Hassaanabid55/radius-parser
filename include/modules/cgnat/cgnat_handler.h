#include "datatypes/radius_attribute_list.h"

extern CgnatNode *g_cgnat_map;
extern pthread_mutex_t g_cgnat_mutex;
extern uint8_t opt_verbosity;
extern RabbitMQClient g_rabbitmq;

extern uint64_t g_session_count;
extern uint64_t g_session_inserts;
extern uint64_t g_session_deletes;
extern uint64_t g_session_updates;
extern uint64_t cgnat_table_size;
extern uint64_t wl_table_size;
extern uint64_t g_session_total_starts;
extern uint64_t g_session_total_updates;
extern uint64_t g_session_total_deletes;

int cgnat_load_from_csv(const char *path);
bool cgnat_lookup(const char *inside_ip, CgnatEntry *out);