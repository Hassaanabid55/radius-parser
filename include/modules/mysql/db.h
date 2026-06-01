#include "user_session.h"

extern uint8_t opt_verbosity;

int db_init(DBConfig *cfg);
bool db_is_enabled();
MYSQL *db_get_connection();
int db_load_whitelist();
int db_load_cgnat();
void db_close();