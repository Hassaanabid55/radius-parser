#include "datatypes/radius_attribute_list.h"

extern CgnatNode *g_cgnat_map;
extern pthread_mutex_t g_cgnat_mutex;
extern uint8_t opt_verbosity;

int cgnat_load_from_csv(const char *path);
bool cgnat_lookup(const char *inside_ip, CgnatEntry *out);