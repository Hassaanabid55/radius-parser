#include <stdint.h>
#include <stdbool.h>

typedef struct
{
    char inside_ip[16];
    char nat_ip[16];
    uint16_t start_port;
    uint16_t end_port;
} CgnatEntry;

int cgnat_load_from_csv(const char *path);
bool cgnat_lookup(const char *inside_ip, CgnatEntry *out);