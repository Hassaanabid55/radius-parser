#include <stdbool.h>

typedef struct
{
    char msisdn[32];

    bool status;

} WhitelistInfo;

int wl_load_from_file(const char *path);

bool wl_lookup(const char *msisdn,
               WhitelistInfo *out);