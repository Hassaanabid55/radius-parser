#include "modules/cgnat/cgnat_handler.h"

CgnatNode *g_cgnat_map = NULL;
pthread_mutex_t g_cgnat_mutex = PTHREAD_MUTEX_INITIALIZER;

uint64_t g_session_count = 0;
uint64_t g_session_inserts = 0;
uint64_t g_session_deletes = 0;
uint64_t g_session_updates = 0;
uint64_t cgnat_table_size = 0;
uint64_t wl_table_size = 0;
uint64_t g_session_total_starts = 0;
uint64_t g_session_total_updates = 0;
uint64_t g_session_total_deletes = 0;

/* =========================
 LOAD FROM CSV
 ========================= */
int cgnat_load_from_csv(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (__builtin_expect(!fp, 0))
    {
        syslog(LOG_ERR, "Failed to open CGNAT CSV: %s", path);
        return -1;
    }

    char line[256];
    if (!fgets(line, sizeof(line), fp))
    {
        fclose(fp);
        return -1;
    }

    while (fgets(line, sizeof(line), fp))
    {
        char nat_ip[16];
        char inside_ip[16];
        uint16_t start_port;
        uint16_t end_port;
        if (__builtin_expect(
                sscanf(line, "%15[^,],%15[^,],%hu,%hu", nat_ip, inside_ip, &start_port, &end_port) != 4, 0))
        {
            continue;
        }

        CgnatNode *node = (CgnatNode *)malloc(sizeof(CgnatNode));
        if (__builtin_expect(!node, 0))
            continue;

        memset(node, 0, sizeof(CgnatNode));
        strncpy(node->inside_ip, inside_ip, sizeof(node->inside_ip));
        strncpy(node->entry.inside_ip, inside_ip, sizeof(node->entry.inside_ip));
        strncpy(node->entry.nat_ip, nat_ip, sizeof(node->entry.nat_ip));
        node->entry.start_port = start_port;
        node->entry.end_port = end_port;
        HASH_ADD_STR(g_cgnat_map, inside_ip, node);
        cgnat_table_size++;
    }

    fclose(fp);
    if (opt_verbosity > 0)
        syslog(LOG_INFO, "CGNAT mappings loaded into memory");

    return 0;
}

/* =========================
 FAST LOOKUP (HOT PATH)
 ========================= */
bool cgnat_lookup(const char *inside_ip, CgnatEntry *out)
{
    if (__builtin_expect(!inside_ip, 0))
        return false;

    CgnatNode *node = NULL;
    HASH_FIND_STR(g_cgnat_map, inside_ip, node);
    if (__builtin_expect(!node, 0))
        return false;

    if (out)
    {
        *out = node->entry;
    }
    return true;
}