#include "modules/cgnat/whitelist_handler.h"

extern bool opt_extract_all;
extern SessionNode *g_session_map;
extern pthread_mutex_t g_session_mutex;

/* =========================================================
 * SESSION TYPE STRING
 * ========================================================= */
static inline const char *session_type_str(uint8_t type)
{
    switch (type)
    {
    case SESSION_START:
        return "START";

    case SESSION_STOP:
        return "STOP";

    case SESSION_UPDATE:
        return "UPDATE";

    default:
        return "UNKNOWN";
    }
}

void printUserSession(const UserSessionInfo *pSession);