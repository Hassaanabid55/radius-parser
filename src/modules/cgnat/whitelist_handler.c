#include "modules/cgnat/whitelist_handler.h"

WlNode *g_wl_map = NULL;
pthread_mutex_t g_wl_mutex = PTHREAD_MUTEX_INITIALIZER;

/* =========================
 LOAD FROM FILE
 ========================= */
int wl_load_from_file(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (__builtin_expect(!fp, 0))
    {
        syslog(LOG_ERR, "Failed to open whitelist file: %s", path);
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), fp))
    {
        char msisdn[32];
        int status;
        if (__builtin_expect(sscanf(line, "%31[^,],%d", msisdn, &status) != 2, 0))
        {
            continue;
        }

        WlNode *node = (WlNode *)malloc(sizeof(WlNode));
        if (__builtin_expect(!node, 0))
            continue;

        memset(node, 0, sizeof(WlNode));
        strncpy(node->msisdn, msisdn, sizeof(node->msisdn));
        strncpy(node->info.msisdn, msisdn, sizeof(node->info.msisdn));
        node->info.status = (status != 0);
        HASH_ADD_STR(g_wl_map, msisdn, node);
        wl_table_size++;
    }

    fclose(fp);
    if (opt_verbosity > 0)
        syslog(LOG_INFO, "Whitelist loaded into memory");

    return 0;
}

/* =========================
 FAST LOOKUP (HOT PATH)
 ========================= */
bool wl_lookup(const char *msisdn, WhitelistInfo *out)
{
    if (__builtin_expect(!msisdn, 0))
        return false;

    WlNode *node = NULL;
    HASH_FIND_STR(g_wl_map, msisdn, node);
    if (__builtin_expect(!node, 0))
        return false;

    if (out)
    {
        *out = node->info;
    }
    return true;
}