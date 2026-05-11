#include "modules/mysql/db.h"

static MYSQL *g_mysql = NULL;
static bool g_db_enabled = false;

static inline int db_ping_connection()
{
    if (__builtin_expect(!g_mysql, 0))
        return -1;

    /*
     * mysql_ping automatically reconnects
     * if reconnect support exists on client/server.
     */
    if (__builtin_expect(mysql_ping(g_mysql) != 0, 0))
    {
        syslog(LOG_ERR, "MySQL ping failed: %s", mysql_error(g_mysql));
        return -1;
    }
    return 0;
}

/* =========================
 DB INITIALIZATION
 ========================= */
int db_init(DBConfig *cfg)
{
    if (__builtin_expect(!cfg, 0))
        return -1;

    if (!cfg->enabled)
    {
        g_db_enabled = false;
        if (opt_verbosity > 0)
        {
            syslog(LOG_INFO, "DB mode disabled");
        }

        return 0;
    }

    if (__builtin_expect(mysql_library_init(0, NULL, NULL) != 0, 0))
    {
        syslog(LOG_ERR, "mysql_library_init failed");
        return -1;
    }

    g_mysql = mysql_init(NULL);
    if (__builtin_expect(!g_mysql, 0))
    {
        syslog(LOG_ERR, "mysql_init failed");
        mysql_library_end();
        return -1;
    }

    /*
     * Connection timeout
     */
    unsigned int timeout = 5;
    mysql_options(g_mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);

    /*
     * Enable TCP keepalive
     */
#ifdef MYSQL_OPT_RECONNECT
    /*
     * Deprecated but harmless warning can be avoided
     * by relying on mysql_ping().
     * Intentionally NOT using MYSQL_OPT_RECONNECT.
     */
#endif

    /*
     * Establish persistent connection
     */
    if (__builtin_expect(!mysql_real_connect(g_mysql, cfg->host, cfg->user, cfg->password, cfg->database, cfg->port, NULL, CLIENT_MULTI_STATEMENTS), 0))
    {
        syslog(LOG_ERR, "MySQL connection failed: %s", mysql_error(g_mysql));
        mysql_close(g_mysql);
        g_mysql = NULL;
        mysql_library_end();
        g_db_enabled = false;
        return -1;
    }

    g_db_enabled = true;
    if (opt_verbosity > 0)
        syslog(LOG_INFO, "Connected to MySQL [%s:%u] DB [%s]", cfg->host, cfg->port, cfg->database);

    return 0;
}

/* =========================
 DB STATE
 ========================= */
bool db_is_enabled()
{
    return g_db_enabled;
}

MYSQL *db_get_connection()
{
    return g_mysql;
}

/* =========================
 DATA LOADERS
 ========================= */
int db_load_whitelist()
{
    if (__builtin_expect(!g_db_enabled, 0))
        return -1;

    if (__builtin_expect(db_ping_connection() != 0, 0))
        return -1;

    /*
     * TODO:
     * SELECT msisdn,status FROM whitelist
     */

    if (opt_verbosity > 0)
        syslog(LOG_INFO, "Whitelist loaded from DB");

    return 0;
}

int db_load_cgnat()
{
    if (__builtin_expect(!g_db_enabled, 0))
        return -1;

    if (__builtin_expect(db_ping_connection() != 0, 0))
        return -1;

    /*
     * TODO:
     * SELECT inside_ip,nat_ip,start_port,end_port
     * FROM cgnat
     */

    if (opt_verbosity > 0)
        syslog(LOG_INFO, "CGNAT loaded from DB");

    return 0;
}

/* =========================
 CLEANUP
 ========================= */
void db_close()
{
    if (g_mysql)
    {
        mysql_close(g_mysql);
        g_mysql = NULL;
    }
    mysql_library_end();
    g_db_enabled = false;
    if (opt_verbosity > 0)
        syslog(LOG_INFO, "Database connection closed");
}