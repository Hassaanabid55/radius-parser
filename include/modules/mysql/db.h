#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <mysql/mysql.h>

typedef struct
{
    bool enabled;
    char host[128];
    char user[64];
    char password[64];
    char database[64];
    uint16_t port;
} DBConfig;

extern uint8_t opt_verbosity;

int db_init(DBConfig *cfg);
bool db_is_enabled();
MYSQL *db_get_connection();
int db_load_whitelist();
int db_load_cgnat();
void db_close();