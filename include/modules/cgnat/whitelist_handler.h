#include "modules/cgnat/cgnat_handler.h"

extern WlNode *g_wl_map;
extern pthread_mutex_t g_wl_mutex;
extern uint8_t opt_verbosity;

int wl_load_from_file(const char *path);
bool wl_lookup(const char *msisdn, WhitelistInfo *out);