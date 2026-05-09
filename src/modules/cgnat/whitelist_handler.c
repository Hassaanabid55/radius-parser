#include "modules/cgnat/whitelist_handler.h"
#include "uthash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

typedef struct WlNode
{
    char msisdn[32]; /* KEY */

    WhitelistInfo info;

    UT_hash_handle hh;

} WlNode;

static WlNode *g_wl_map = NULL;

int wl_load_from_file(const char *path)
{
    FILE *fp = fopen(path, "r");

    if (!fp)
    {
        syslog(LOG_ERR,
               "Failed to open whitelist file: %s",
               path);

        return -1;
    }

    char line[256];

    while (fgets(line, sizeof(line), fp))
    {
        char msisdn[32];
        int status;

        if (sscanf(line,
                   "%31[^,],%d",
                   msisdn,
                   &status) != 2)
        {
            continue;
        }

        WlNode *node =
            malloc(sizeof(WlNode));

        if (!node)
            continue;

        memset(node, 0, sizeof(WlNode));

        snprintf(node->msisdn,
                 sizeof(node->msisdn),
                 "%s",
                 msisdn);

        snprintf(node->info.msisdn,
                 sizeof(node->info.msisdn),
                 "%s",
                 msisdn);

        node->info.status =
            status ? true : false;

        HASH_ADD_STR(g_wl_map,
                     msisdn,
                     node);
    }

    fclose(fp);

    syslog(LOG_INFO,
           "Whitelist loaded into memory");

    return 0;
}

bool wl_lookup(const char *msisdn,
               WhitelistInfo *out)
{
    WlNode *node = NULL;

    HASH_FIND_STR(g_wl_map,
                  msisdn,
                  node);

    if (!node)
        return false;

    if (out)
    {
        memcpy(out,
               &node->info,
               sizeof(WhitelistInfo));
    }

    return true;
}