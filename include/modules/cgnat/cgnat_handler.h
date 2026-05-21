#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

#include "uthash.h"

#include "radius_attribute_list.h"

typedef struct
{
    char inside_ip[16];
    char nat_ip[16];
    uint16_t start_port;
    uint16_t end_port;
} CgnatEntry;

typedef struct CgnatNode
{
    char inside_ip[16];
    CgnatEntry entry;
    UT_hash_handle hh;
} CgnatNode;

extern CgnatNode *g_cgnat_map;
extern uint8_t opt_verbosity;

int cgnat_load_from_csv(const char *path);
bool cgnat_lookup(const char *inside_ip, CgnatEntry *out);