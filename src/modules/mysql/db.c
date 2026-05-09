#include "modules/mysql/db.h"

static MYSQL *g_mysql = NULL;
static bool g_db_enabled = false;

int db_init(DBConfig *cfg)
{
    if (!cfg)
        return -1;

    if (!cfg->enabled)
    {
        g_db_enabled = false;
        syslog(LOG_INFO, "DB mode disabled");
        return 0;
    }

    mysql_library_init(0, NULL, NULL);
    g_mysql = mysql_init(NULL);
    if (!g_mysql)
    {
        syslog(LOG_ERR, "mysql_init failed");
        return -1;
    }

    /*
     * Connection timeout
     */
    unsigned int timeout = 5;
    mysql_options(g_mysql, MYSQL_OPT_CONNECT_TIMEOUT, &timeout);

    /*
     * Establish persistent connection
     */
    if (!mysql_real_connect(g_mysql, cfg->host, cfg->user, cfg->password, cfg->database, cfg->port, NULL, CLIENT_MULTI_STATEMENTS))
    {
        syslog(LOG_ERR, "MySQL connection failed: %s", mysql_error(g_mysql));
        mysql_close(g_mysql);
        g_mysql = NULL;
        g_db_enabled = false;
        return -1;
    }
    g_db_enabled = true;
    syslog(LOG_INFO, "Connected to MySQL [%s:%u] DB [%s]", cfg->host, cfg->port, cfg->database);

    return 0;
}

bool db_is_enabled()
{
    return g_db_enabled;
}

MYSQL *db_get_connection()
{
    return g_mysql;
}

int db_load_whitelist()
{
    if (!g_db_enabled)
        return -1;

    /*
     * TODO:
     * SELECT msisdn,status FROM whitelist
     */

    syslog(LOG_INFO,
           "Whitelist loaded from DB");

    return 0;
}

int db_load_cgnat()
{
    if (!g_db_enabled)
        return -1;

    /*
     * TODO:
     * SELECT inside_ip,nat_ip,start_port,end_port
     * FROM cgnat
     */

    syslog(LOG_INFO,
           "CGNAT loaded from DB");

    return 0;
}

void db_close()
{
    if (g_mysql)
    {
        mysql_close(g_mysql);
        g_mysql = NULL;
    }
    mysql_library_end();
    g_db_enabled = false;
    syslog(LOG_INFO, "Database connection closed");
}