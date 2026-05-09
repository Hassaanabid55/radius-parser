#include "modules/cgnat/cgnat_handler.h"
#include "uthash.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>

typedef struct CgnatNode
{
    char inside_ip[16]; /* KEY */

    CgnatEntry entry;

    UT_hash_handle hh;

} CgnatNode;

static CgnatNode *g_cgnat_map = NULL;

int cgnat_load_from_csv(const char *path)
{
    FILE *fp = fopen(path, "r");

    if (!fp)
    {
        syslog(LOG_ERR,
               "Failed to open CGNAT CSV: %s",
               path);

        return -1;
    }

    char line[256];

    /* skip header */
    if (!fgets(line, sizeof(line), fp))
    {
        fclose(fp);
        return false;
    }

    while (fgets(line, sizeof(line), fp))
    {
        char nat_ip[16];
        char inside_ip[16];

        uint16_t start_port;
        uint16_t end_port;

        if (sscanf(line,
                   "%15[^,],%15[^,],%hu,%hu",
                   nat_ip,
                   inside_ip,
                   &start_port,
                   &end_port) != 4)
        {
            continue;
        }

        CgnatNode *node =
            malloc(sizeof(CgnatNode));

        if (!node)
            continue;

        memset(node, 0, sizeof(CgnatNode));

        snprintf(node->inside_ip,
                 sizeof(node->inside_ip),
                 "%s",
                 inside_ip);

        snprintf(node->entry.inside_ip,
                 sizeof(node->entry.inside_ip),
                 "%s",
                 inside_ip);

        snprintf(node->entry.nat_ip,
                 sizeof(node->entry.nat_ip),
                 "%s",
                 nat_ip);

        node->entry.start_port = start_port;
        node->entry.end_port = end_port;

        HASH_ADD_STR(g_cgnat_map,
                     inside_ip,
                     node);
    }

    fclose(fp);

    syslog(LOG_INFO,
           "CGNAT mappings loaded into memory");

    return 0;
}

bool cgnat_lookup(const char *inside_ip,
                  CgnatEntry *out)
{
    CgnatNode *node = NULL;

    HASH_FIND_STR(g_cgnat_map,
                  inside_ip,
                  node);

    if (!node)
        return false;

    if (out)
    {
        memcpy(out,
               &node->entry,
               sizeof(CgnatEntry));
    }

    return true;
}