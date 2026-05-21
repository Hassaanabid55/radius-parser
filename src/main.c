#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdbool.h>
#include <signal.h>
#include <unistd.h>
#include <syslog.h>
#include <string.h>
#include <time.h>

#include <capture.h>

typedef enum
{
    ARG_UNKNOWN = 0,
    ARG_CONFIG,
    ARG_VERBOSE,
    ARG_INTERFACE,
    ARG_THREADS,
    ARG_INPUT_FILE,
    ARG_WHITELIST_FILE,
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
    ARG_RABBITMQ_HOST,
    ARG_RABBITMQ_VHOST,
    ARG_RABBITMQ_USER,
    ARG_RABBITMQ_PASSWORD,
    ARG_RABBITMQ_EXCHANGE,
    ARG_RABBITMQ_PORT,
} ArgType;

/* =========================
 CONFIGURATION OPTIONS
 ========================= */
char opt_config_file[256] = "";
char opt_cgnat_file_path[256] = "";
char opt_whitelist_file_path[256] = "";
char opt_interface_name[64] = "lo";
char opt_input_files[256] = "";
char opt_mysql_host[128] = "";
char opt_mysql_database[64] = "";
char opt_mysql_user[64] = "";
char opt_mysql_password[64] = "";
char opt_threads_str[128] = "";
char opt_rabbitmq_host[128] = "";
char opt_rabbitmq_vhost[64] = "";
char opt_rabbitmq_user[64] = "";
char opt_rabbitmq_password[64] = "";
char opt_rabbitmq_exchange[64] = "";

uint8_t opt_verbosity = 0;
uint16_t opt_caplen = 3200;
uint16_t opt_bye_timeout = 43200;
uint16_t opt_mysql_port = 0;
uint16_t opt_rabbitmq_port = 0;
uint32_t opt_update_timeout = 900;
uint32_t opt_ring_buffer_size = 1048576;

bool opt_extract_all = false;

/* =========================
 GLOBALS
 ========================= */
volatile sig_atomic_t g_running = 1;
int cores[MAX_CORE_COUNT];
uint16_t core_count;

/* =========================
 FAST SAFE STRING COPY
 ========================= */
static inline void safe_strcpy(char *dst, size_t dst_size, const char *src)
{
    if (__builtin_expect(!dst || !src || dst_size == 0, 0))
        return;

    strncpy(dst, src, dst_size - 1);
    dst[dst_size - 1] = '\0';
}

/* =========================
 CLEANUP FUNCTION
 ========================= */
void cleanup(void)
{
    pthread_mutex_lock(&global_queue.mutex);
    global_queue.shutdown = true;
    pthread_cond_broadcast(&global_queue.not_empty);
    pthread_cond_broadcast(&global_queue.not_full);
    pthread_mutex_unlock(&global_queue.mutex);
    if (g_pcap_handle)
    {
        if (!opt_input_files[0])
            pcap_breakloop(g_pcap_handle);
        g_pcap_handle = NULL;
    }
    g_running = 0;
}

/* =========================
 SIGNAL HANDLER
 ========================= */
void signal_handler(int sig)
{
    if (sig != SIGINT && sig != SIGTERM)
        return;

    if (opt_verbosity > 0)
        syslog(LOG_INFO, "Shutdown signal received");
    cleanup();
}

/* =========================
 ARGUMENT PARSING
 ========================= */
static inline ArgType get_arg_type(const char *arg)
{
    if (!arg)
        return ARG_UNKNOWN;

    switch (arg[1])
    {
    case 'c':
        if (!strcmp(arg, "-c") || !strcmp(arg, "--config-file"))
            return ARG_CONFIG;
        break;

    case 'v':
        if (!strcmp(arg, "-v") || !strcmp(arg, "--verbose"))
            return ARG_VERBOSE;
        break;

    case 'i':
        if (!strcmp(arg, "-i") || !strcmp(arg, "--interface"))
            return ARG_INTERFACE;
        break;

    case 't':
        if (!strcmp(arg, "-t") || !strcmp(arg, "--threads"))
            return ARG_THREADS;
        break;

    case 'H':
        if (!strcmp(arg, "-H") || !strcmp(arg, "--mysql-host"))
            return ARG_MYSQL_HOST;
        break;

    case 'D':
        if (!strcmp(arg, "-D") || !strcmp(arg, "--mysql-database"))
            return ARG_MYSQL_DATABASE;
        break;

    case 'U':
        if (!strcmp(arg, "-U") || !strcmp(arg, "--mysql-user"))
            return ARG_MYSQL_USER;
        break;

    case 'P':
        if (!strcmp(arg, "-P") || !strcmp(arg, "--mysql-password"))
            return ARG_MYSQL_PASSWORD;
        break;

    case 'p':
        if (!strcmp(arg, "-p") || !strcmp(arg, "--mysql-port"))
            return ARG_MYSQL_PORT;
        break;

    default:
        break;
    }

    if (!strcmp(arg, "--rabbitmq-host"))
        return ARG_RABBITMQ_HOST;

    if (!strcmp(arg, "--rabbitmq-vhost"))
        return ARG_RABBITMQ_VHOST;

    if (!strcmp(arg, "--rabbitmq-user"))
        return ARG_RABBITMQ_USER;

    if (!strcmp(arg, "--rabbitmq-password"))
        return ARG_RABBITMQ_PASSWORD;

    if (!strcmp(arg, "--rabbitmq-exchange"))
        return ARG_RABBITMQ_EXCHANGE;

    if (!strcmp(arg, "--rabbitmq-port"))
        return ARG_RABBITMQ_PORT;

    if (!strcmp(arg, "--whitelist-file"))
        return ARG_WHITELIST_FILE;

    if (!strcmp(arg, "--cgnat-file"))
        return ARG_CGNAT_FILE;

    if (!strcmp(arg, "--extract-all"))
        return ARG_EXTRACT_ALL;

    if (!strcmp(arg, "--caplen"))
        return ARG_CAPLEN;

    if (!strcmp(arg, "--update-timeout"))
        return ARG_UPDATE_TIMEOUT;

    if (!strcmp(arg, "--bye-timeout"))
        return ARG_BYE_TIMEOUT;

    if (!strcmp(arg, "--ring-buffer-size"))
        return ARG_RING_BUFFER_SIZE;

    if (!strcmp(arg, "--input-file"))
        return ARG_INPUT_FILE;

    return ARG_UNKNOWN;
}

/* =========================
 FAST PARSERS
 ========================= */
static inline uint8_t parse_u8(const char *s)
{
    return (uint8_t)strtoul(s, NULL, 10);
}

static inline uint16_t parse_u16(const char *s)
{
    return (uint16_t)strtoul(s, NULL, 10);
}

static inline uint32_t parse_u32(const char *s)
{
    return (uint32_t)strtoul(s, NULL, 10);
}

static inline bool parse_bool(const char *s)
{
    if (!s)
        return false;

    return (!strcmp(s, "1") || !strcmp(s, "true") || !strcmp(s, "yes") || !strcmp(s, "on"));
}

/* =========================
 STRING TRIM
 ========================= */
static inline char *trim(char *s)
{
    if (!s)
        return s;

    while (*s == ' ' || *s == '\t')
        ++s;

    char *end = s + strlen(s);
    while (end > s)
    {
        char c = *(end - 1);
        if (c != '\n' && c != '\r' && c != ' ' && c != '\t')
        {
            break;
        }
        --end;
    }
    *end = '\0';
    return s;
}

/* =========================
 CONFIG LOADER
 ========================= */
void load_config(const char *path)
{
    FILE *fp = fopen(path, "r");
    if (!fp)
    {
        syslog(LOG_ERR, "Failed opening config: %s", path);
        return;
    }

    char line[MAX_LINE];
    while (fgets(line, sizeof(line), fp))
    {
        char *eq = strchr(line, '=');
        if (!eq)
            continue;

        *eq = '\0';
        char *key = trim(line);
        char *val = trim(eq + 1);
        if (!*key || !*val)
            continue;

        /* ---------- GENERAL ---------- */

        if (!strcmp(key, "verbosity"))
            opt_verbosity = parse_u8(val);

        else if (!strcmp(key, "cgnat_file_path"))
            safe_strcpy(opt_cgnat_file_path, sizeof(opt_cgnat_file_path), val);

        else if (!strcmp(key, "whitelist_file_path"))
            safe_strcpy(opt_whitelist_file_path, sizeof(opt_whitelist_file_path), val);

        else if (!strcmp(key, "interface_name"))
            safe_strcpy(opt_interface_name, sizeof(opt_interface_name), val);

        else if (!strcmp(key, "threads"))
            safe_strcpy(opt_threads_str, sizeof(opt_threads_str), val);

        else if (!strcmp(key, "extract_all"))
            opt_extract_all = parse_bool(val);

        /* ---------- CAPTURE ---------- */

        else if (!strcmp(key, "caplen"))
            opt_caplen = parse_u16(val);

        else if (!strcmp(key, "update_timeout"))
            opt_update_timeout = parse_u16(val);

        else if (!strcmp(key, "bye_timeout"))
            opt_bye_timeout = parse_u16(val);

        else if (!strcmp(key, "ring_buffer_size"))
            opt_ring_buffer_size = parse_u32(val);

        /* ---------- INPUT ---------- */

        else if (!strcmp(key, "input_file"))
            safe_strcpy(opt_input_files, sizeof(opt_input_files), val);

        /* ---------- MYSQL ---------- */

        else if (!strcmp(key, "mysql_host"))
            safe_strcpy(opt_mysql_host, sizeof(opt_mysql_host), val);

        else if (!strcmp(key, "mysql_database"))
            safe_strcpy(opt_mysql_database, sizeof(opt_mysql_database), val);

        else if (!strcmp(key, "mysql_user"))
            safe_strcpy(opt_mysql_user, sizeof(opt_mysql_user), val);

        else if (!strcmp(key, "mysql_password"))
            safe_strcpy(opt_mysql_password, sizeof(opt_mysql_password), val);

        else if (!strcmp(key, "mysql_port"))
            opt_mysql_port = parse_u16(val);

        /* ---------- RABBITMQ ---------- */

        else if (!strcmp(key, "rabbitmq_host"))
            safe_strcpy(opt_rabbitmq_host, sizeof(opt_rabbitmq_host), val);

        else if (!strcmp(key, "rabbitmq_vhost"))
            safe_strcpy(opt_rabbitmq_vhost, sizeof(opt_rabbitmq_vhost), val);

        else if (!strcmp(key, "rabbitmq_user"))
            safe_strcpy(opt_rabbitmq_user, sizeof(opt_rabbitmq_user), val);

        else if (!strcmp(key, "rabbitmq_password"))
            safe_strcpy(opt_rabbitmq_password, sizeof(opt_rabbitmq_password), val);

        else if (!strcmp(key, "rabbitmq_exchange"))
            safe_strcpy(opt_rabbitmq_exchange, sizeof(opt_rabbitmq_exchange), val);

        else if (!strcmp(key, "rabbitmq_port"))
            opt_rabbitmq_port = parse_u16(val);
    }

    fclose(fp);
}

/* =========================
 MAIN
 ========================= */
int main(int argc, char *argv[])
{
    openlog("radius_parser", LOG_PID | LOG_CONS, LOG_USER);

    signal(SIGINT, signal_handler);
    signal(SIGTERM, signal_handler);
    if (opt_verbosity > 0)
        syslog(LOG_INFO, "Radius parser started");

    /* =========================
     LOAD CONFIG FIRST
     ========================= */
    for (int i = 1; i < argc - 1; ++i)
    {
        if (!strcmp(argv[i], "-c") || !strcmp(argv[i], "--config-file"))
        {
            safe_strcpy(opt_config_file, sizeof(opt_config_file), argv[i + 1]);
            load_config(opt_config_file);
            break;
        }
    }

    /* =========================
     CLI OVERRIDES
     ========================= */
    for (int i = 1; i < argc; ++i)
    {
        ArgType type = get_arg_type(argv[i]);
        switch (type)
        {
        case ARG_VERBOSE:
            if (i + 1 < argc)
                opt_verbosity = parse_u8(argv[++i]);
            break;

        case ARG_INTERFACE:
            if (i + 1 < argc)
                safe_strcpy(opt_interface_name, sizeof(opt_interface_name), argv[++i]);
            break;

        case ARG_THREADS:
            if (i + 1 < argc)
                safe_strcpy(opt_threads_str, sizeof(opt_threads_str), argv[++i]);
            break;

        case ARG_CGNAT_FILE:
            if (i + 1 < argc)
                safe_strcpy(opt_cgnat_file_path, sizeof(opt_cgnat_file_path), argv[++i]);
            break;

        case ARG_WHITELIST_FILE:
            if (i + 1 < argc)
                safe_strcpy(opt_whitelist_file_path, sizeof(opt_whitelist_file_path), argv[++i]);
            break;

        case ARG_EXTRACT_ALL:
            if (i + 1 < argc)
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
                safe_strcpy(opt_input_files, sizeof(opt_input_files), argv[++i]);
            break;

        case ARG_MYSQL_HOST:
            if (i + 1 < argc)
                safe_strcpy(opt_mysql_host, sizeof(opt_mysql_host), argv[++i]);
            break;

        case ARG_MYSQL_DATABASE:
            if (i + 1 < argc)
                safe_strcpy(opt_mysql_database, sizeof(opt_mysql_database), argv[++i]);
            break;

        case ARG_MYSQL_USER:
            if (i + 1 < argc)
                safe_strcpy(opt_mysql_user, sizeof(opt_mysql_user), argv[++i]);
            break;

        case ARG_MYSQL_PASSWORD:
            if (i + 1 < argc)
                safe_strcpy(opt_mysql_password, sizeof(opt_mysql_password), argv[++i]);
            break;

        case ARG_MYSQL_PORT:
            if (i + 1 < argc)
                opt_mysql_port = parse_u16(argv[++i]);
            break;

        case ARG_RABBITMQ_HOST:
            if (i + 1 < argc)
                safe_strcpy(opt_rabbitmq_host, sizeof(opt_rabbitmq_host), argv[++i]);
            break;

        case ARG_RABBITMQ_VHOST:
            if (i + 1 < argc)
                safe_strcpy(opt_rabbitmq_vhost, sizeof(opt_rabbitmq_vhost), argv[++i]);
            break;

        case ARG_RABBITMQ_USER:
            if (i + 1 < argc)
                safe_strcpy(opt_rabbitmq_user, sizeof(opt_rabbitmq_user), argv[++i]);
            break;

        case ARG_RABBITMQ_PASSWORD:
            if (i + 1 < argc)
                safe_strcpy(opt_rabbitmq_password, sizeof(opt_rabbitmq_password), argv[++i]);
            break;

        case ARG_RABBITMQ_EXCHANGE:
            if (i + 1 < argc)
                safe_strcpy(opt_rabbitmq_exchange, sizeof(opt_rabbitmq_exchange), argv[++i]);
            break;

        case ARG_RABBITMQ_PORT:
            if (i + 1 < argc)
                opt_rabbitmq_port = parse_u16(argv[++i]);
            break;

        default:
            break;
        }
    }

    RabbitMQBootstrapState mq_state;

    RabbitMQConfig cfg;
    safe_strcpy(cfg.host, sizeof(cfg.host), opt_rabbitmq_host);
    safe_strcpy(cfg.vhost, sizeof(cfg.vhost), opt_rabbitmq_vhost);
    safe_strcpy(cfg.user, sizeof(cfg.user), opt_rabbitmq_user);
    safe_strcpy(cfg.password, sizeof(cfg.password), opt_rabbitmq_password);
    safe_strcpy(cfg.exchange, sizeof(cfg.exchange), opt_rabbitmq_exchange);
    cfg.port = opt_rabbitmq_port;

    /* 1. RabbitMQ init */
    rabbitmq_init(&cfg);

    /* =========================
     DATABASE INIT
     ========================= */
    DBConfig dbcfg = {0};
    dbcfg.enabled = (opt_mysql_host[0] && opt_mysql_database[0]);
    safe_strcpy(dbcfg.host, sizeof(dbcfg.host), opt_mysql_host);
    safe_strcpy(dbcfg.user, sizeof(dbcfg.user), opt_mysql_user);
    safe_strcpy(dbcfg.password, sizeof(dbcfg.password), opt_mysql_password);
    safe_strcpy(dbcfg.database, sizeof(dbcfg.database), opt_mysql_database);
    dbcfg.port = opt_mysql_port;
    db_init(&dbcfg);

    /* =========================
     DATA LOADING
     ========================= */

    rabbitmq_bootstrap_state(&g_rabbitmq, &g_session_map, &g_cgnat_map, &g_wl_map, &mq_state);

    if (!mq_state.has_session_state)
    {
        if (db_is_enabled())
        {
            if (opt_verbosity > 0)
                syslog(LOG_INFO, "Loading data from DB");

            if (__builtin_expect(db_load_whitelist() != 0, 0))
            {
                syslog(LOG_ERR, "Failed loading whitelist from DB");
                return EXIT_FAILURE;
            }

            if (__builtin_expect(db_load_cgnat() != 0, 0))
            {
                syslog(LOG_ERR, "Failed loading CGNAT from DB");
                return EXIT_FAILURE;
            }
        }
        else
        {
            if (opt_verbosity > 0)
                syslog(LOG_INFO, "Loading data from files");
            if (!opt_whitelist_file_path[0] || !opt_cgnat_file_path[0])
            {
                syslog(LOG_ERR, "Whitelist/CGNAT file missing");
                return EXIT_FAILURE;
            }

            if (__builtin_expect(wl_load_from_file(opt_whitelist_file_path) != 0, 0))
            {
                syslog(LOG_ERR, "Failed loading whitelist file");
                return EXIT_FAILURE;
            }

            if (__builtin_expect(cgnat_load_from_csv(opt_cgnat_file_path) != 0, 0))
            {
                syslog(LOG_ERR, "Failed loading CGNAT CSV");
                return EXIT_FAILURE;
            }
        }
    }
    else
    {
        syslog(LOG_INFO, "Session state restored from RabbitMQ");
    }

    /* =========================
     START WORKERS
     ========================= */
    start_worker_threads();

    /* =========================
     START INPUT
     ========================= */
    if (opt_input_files[0])
    {
        if (opt_verbosity > 0)
            syslog(LOG_INFO, "Processing input file: %s", opt_input_files);

        start_file_capture(opt_input_files);
        cleanup();
    }
    else
    {
        start_interface_capture();
    }

    /* =========================
     WAIT FOR SHUTDOWN
     ========================= */
    while (g_running)
    {
        sleep(1);
    }

    if (opt_verbosity > 0)
        syslog(LOG_INFO, "Waiting for worker threads...");

    for (uint8_t i = 0; i < core_count; ++i)
    {
        pthread_join(worker_threads[i], NULL);
    }
    pthread_join(timeout_tid, NULL);
    if (opt_verbosity > 1)
        pthread_join(stats_worker_threads, NULL);

    db_close();
    rabbitmq_cleanup(&g_rabbitmq);
    cleanup_queue(&global_queue);
    closelog();
    return EXIT_SUCCESS;
}