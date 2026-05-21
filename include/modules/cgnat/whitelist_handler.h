#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "uthash.h"

#include "modules/cgnat/cgnat_handler.h"

typedef struct
{
    char msisdn[32];
    bool status;
} WhitelistInfo;

typedef struct WlNode
{
    char msisdn[32];
    WhitelistInfo info;
    UT_hash_handle hh;
} WlNode;

extern WlNode *g_wl_map;
extern uint8_t opt_verbosity;

int wl_load_from_file(const char *path);
bool wl_lookup(const char *msisdn, WhitelistInfo *out);