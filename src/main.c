#include "worker.h"
#include "capture.h"

#include <stdlib.h>
#include <string.h>
#include <signal.h>

#define MAX_LINE 512

typedef enum
{
    ARG_UNKNOWN,
    ARG_CONFIG,
    ARG_OUTPUT,
    ARG_INTERFACE,
    ARG_THREADS,
    ARG_INPUT_FILE,

    ARG_CGNAT_FILE,
    ARG_EXTRACT_ALL,
    ARG_CAPLEN,
    ARG_UPDATE_TIMEOUT,
    ARG_BYE_TIMEOUT,
    ARG_RING_BUFFER_SIZE,

    ARG_MYSQL_HOST,
    ARG_MYSQL_DATABASE,
    ARG_MYSQL_USER,
    ARG_MYSQL_PASSWORD,
    ARG_MYSQL_PORT,
} ArgType;

/* =========================
 CONFIGURATION OPTIONS
 ========================= */

char opt_output_folder[256] = "";
char opt_config_file[256] = "";
char opt_cgnat_file_path[256] = "";
char opt_interface_name[64] = "lo";
uint8_t opt_threads = 1;
bool opt_extract_all = false;
uint16_t opt_caplen = 3200;
uint16_t opt_update_timeout = 900;       // 15 minutes
uint16_t opt_bye_timeout = 43200;        // 12 hours
uint32_t opt_ring_buffer_size = 1048576; // 512MB
char opt_input_files[256] = "";
char opt_mysql_host[256] = "127.0.0.1";
char opt_mysql_database[256] = "MDF";
char opt_mysql_user[256] = "root";
char opt_mysql_password[256] = "";
uint16_t opt_mysql_port = 0;

/* =========================
 GLOBALS
 ========================= */

volatile bool g_running = true;

void signal_handler(int sig)
{
    if (sig == SIGINT || sig == SIGTERM)
    {
        printf("\nShutdown signal received...\n");
        g_running = 0;

        for (int i = 0; i < opt_threads; i++)
        {
            printf("Waiting for worker thread %d to finish...\n", i);
            pthread_join(worker_threads[i], NULL);
        }

        cleanup_queue(&global_queue);
        cleanup_interface();
    }
}

/* =========================
 COMMAND-LINE ARGUMENT PARSING
 ========================= */

ArgType get_arg_type(const char *arg)
{
    if (strcmp(arg, "-c") == 0 || strcmp(arg, "--config-file") == 0)
        return ARG_CONFIG;
    if (strcmp(arg, "-o") == 0 || strcmp(arg, "--output") == 0)
        return ARG_OUTPUT;
    if (strcmp(arg, "-i") == 0 || strcmp(arg, "--interface") == 0)
        return ARG_INTERFACE;
    if (strcmp(arg, "-t") == 0 || strcmp(arg, "--threads") == 0)
        return ARG_THREADS;
    if (strcmp(arg, "--cgnat-file") == 0)
        return ARG_CGNAT_FILE;
    if (strcmp(arg, "--extract-all") == 0)
        return ARG_EXTRACT_ALL;
    if (strcmp(arg, "--caplen") == 0)
        return ARG_CAPLEN;
    if (strcmp(arg, "--update-timeout") == 0)
        return ARG_UPDATE_TIMEOUT;
    if (strcmp(arg, "--bye-timeout") == 0)
        return ARG_BYE_TIMEOUT;
    if (strcmp(arg, "--ring-buffer-size") == 0)
        return ARG_RING_BUFFER_SIZE;
    if (strcmp(arg, "-H") == 0 || strcmp(arg, "--mysql-host") == 0)
        return ARG_MYSQL_HOST;
    if (strcmp(arg, "-D") == 0 || strcmp(arg, "--mysql-database") == 0)
        return ARG_MYSQL_DATABASE;
    if (strcmp(arg, "-U") == 0 || strcmp(arg, "--mysql-user") == 0)
        return ARG_MYSQL_USER;
    if (strcmp(arg, "-P") == 0 || strcmp(arg, "--mysql-password") == 0)
        return ARG_MYSQL_PASSWORD;
    if (strcmp(arg, "-p") == 0 || strcmp(arg, "--mysql-port") == 0)
        return ARG_MYSQL_PORT;
    if (strcmp(arg, "--input-file") == 0)
        return ARG_INPUT_FILE;
    return ARG_UNKNOWN;
}

static uint8_t parse_u8(const char *s)
{
    return (uint8_t)atoi(s);
}

static uint16_t parse_u16(const char *s)
{
    return (uint16_t)atoi(s);
}

static uint32_t parse_u32(const char *s)
{
    return (uint32_t)strtoul(s, NULL, 10);
}

static int parse_bool(const char *s)
{
    return (strcmp(s, "1") == 0 ||
            strcmp(s, "true") == 0 ||
            strcmp(s, "yes") == 0 ||
            strcmp(s, "on") == 0);
}

static char *trim(char *s)
{
    char *end;

    while (*s == ' ' || *s == '\t')
        s++;

    end = s + strlen(s) - 1;

    while (end > s && (*end == '\n' || *end == ' ' || *end == '\t'))
        *end-- = '\0';

    return s;
}

/* Config loader (same as before, simplified here) */
void load_config(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
    {
        perror("Config open failed");
        return;
    }

    char line[MAX_LINE];

    while (fgets(line, sizeof(line), fp))
    {
        char *eq = strchr(line, '=');
        if (!eq)
            continue;

        *eq = '\0';
        char *key = line;
        char *val = eq + 1;

        trim(key);
        trim(val);

        /* ---------------- GENERAL ---------------- */
        if (strcmp(key, "output_folder") == 0)
        {
            strncpy(opt_output_folder, val, sizeof(opt_output_folder) - 1);
            opt_output_folder[sizeof(opt_output_folder) - 1] = '\0';
        }
        else if (strcmp(key, "cgnat_file_path") == 0)
        {
            strncpy(opt_cgnat_file_path, val, sizeof(opt_cgnat_file_path) - 1);
            opt_cgnat_file_path[sizeof(opt_cgnat_file_path) - 1] = '\0';
        }
        else if (strcmp(key, "interface_name") == 0)
        {
            strncpy(opt_interface_name, val, sizeof(opt_interface_name) - 1);
            opt_interface_name[sizeof(opt_interface_name) - 1] = '\0';
        }
        else if (strcmp(key, "threads") == 0)
        {
            opt_threads = (uint8_t)atoi(val);
        }
        else if (strcmp(key, "extract_all") == 0)
        {
            opt_extract_all = (strcmp(val, "1") == 0 || strcmp(val, "true") == 0 || strcmp(val, "yes") == 0 || strcmp(val, "on") == 0);
        }

        /* ---------------- CAPTURE SETTINGS ---------------- */
        else if (strcmp(key, "caplen") == 0)
        {
            opt_caplen = (uint16_t)atoi(val);
        }
        else if (strcmp(key, "update_timeout") == 0)
        {
            opt_update_timeout = (uint16_t)atoi(val);
        }
        else if (strcmp(key, "bye_timeout") == 0)
        {
            opt_bye_timeout = (uint16_t)atoi(val);
        }
        else if (strcmp(key, "ring_buffer_size") == 0)
        {
            opt_ring_buffer_size = (uint32_t)strtoul(val, NULL, 10);
        }

        /* ---------------- INPUT FILE ---------------- */
        else if (strcmp(key, "input_file") == 0)
        {
            strncpy(opt_input_files, val, sizeof(opt_input_files) - 1);
            opt_input_files[sizeof(opt_input_files) - 1] = '\0';
        }

        /* ---------------- MYSQL ---------------- */
        else if (strcmp(key, "mysql_host") == 0)
        {
            strncpy(opt_mysql_host, val, sizeof(opt_mysql_host) - 1);
            opt_mysql_host[sizeof(opt_mysql_host) - 1] = '\0';
        }
        else if (strcmp(key, "mysql_database") == 0)
        {
            strncpy(opt_mysql_database, val, sizeof(opt_mysql_database) - 1);
            opt_mysql_database[sizeof(opt_mysql_database) - 1] = '\0';
        }
        else if (strcmp(key, "mysql_user") == 0)
        {
            strncpy(opt_mysql_user, val, sizeof(opt_mysql_user) - 1);
            opt_mysql_user[sizeof(opt_mysql_user) - 1] = '\0';
        }
        else if (strcmp(key, "mysql_password") == 0)
        {
            strncpy(opt_mysql_password, val, sizeof(opt_mysql_password) - 1);
            opt_mysql_password[sizeof(opt_mysql_password) - 1] = '\0';
        }
        else if (strcmp(key, "mysql_port") == 0)
        {
            opt_mysql_port = atoi(val);
        }
    }

    fclose(fp);
}

/* =========================
 MAIN FUNCTION
 ========================= */
int main(int argc, char *argv[])
{
    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);

    for (int i = 1; i < argc; i++)
    {
        if ((strcmp(argv[i], "-c") == 0 || strcmp(argv[i], "--config-file") == 0) && i + 1 < argc)
        {
            strncpy(opt_config_file, argv[i + 1], sizeof(opt_config_file) - 1);
            opt_config_file[sizeof(opt_config_file) - 1] = '\0';
            break;
        }
    }

    if (opt_config_file[0] != '\0')
    {
        load_config(opt_config_file);
    }

    for (int i = 1; i < argc; i++)
    {

        ArgType type = get_arg_type(argv[i]);

        switch (type)
        {
        case ARG_OUTPUT:
            if (i + 1 < argc)
            {
                strncpy(opt_output_folder, argv[++i], sizeof(opt_output_folder) - 1);
                opt_output_folder[sizeof(opt_output_folder) - 1] = '\0';
            }

            break;

        case ARG_INTERFACE:
            if (i + 1 < argc)
            {
                strncpy(opt_interface_name, argv[++i], sizeof(opt_interface_name) - 1);
                opt_interface_name[sizeof(opt_interface_name) - 1] = '\0';
            }
            break;

        case ARG_THREADS:
            if (i + 1 < argc)
                opt_threads = parse_u8(argv[++i]);
            break;

        case ARG_CGNAT_FILE:
            if (i + 1 < argc)
            {
                strncpy(opt_cgnat_file_path, argv[++i], sizeof(opt_cgnat_file_path) - 1);
                opt_cgnat_file_path[sizeof(opt_cgnat_file_path) - 1] = '\0';
            }
            break;

        case ARG_EXTRACT_ALL:
            opt_extract_all = parse_bool(argv[++i]);
            break;

        case ARG_CAPLEN:
            if (i + 1 < argc)
                opt_caplen = parse_u16(argv[++i]);
            break;

        case ARG_UPDATE_TIMEOUT:
            if (i + 1 < argc)
                opt_update_timeout = parse_u16(argv[++i]);
            break;

        case ARG_BYE_TIMEOUT:
            if (i + 1 < argc)
                opt_bye_timeout = parse_u16(argv[++i]);
            break;

        case ARG_RING_BUFFER_SIZE:
            if (i + 1 < argc)
                opt_ring_buffer_size = parse_u32(argv[++i]);
            break;

        case ARG_INPUT_FILE:
            if (i + 1 < argc)
            {
                strncpy(opt_input_files, argv[++i], sizeof(opt_input_files) - 1);
                opt_input_files[sizeof(opt_input_files) - 1] = '\0';
            }
            break;

        default:
            break;
        }
    }

    start_worker_threads();

    if (opt_input_files[0] != '\0')
    {
        printf("Processing input file: %s\n", opt_input_files);
    }
    else if (opt_interface_name[0] != '\0')
    {
        start_interface_capture();
    }

    return 0;
}