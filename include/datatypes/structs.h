#include "datatypes/macros.h"

/* =========================================================
 * CGNAT
 * ========================================================= */

typedef struct
{
    char inside_ip[16];
    char nat_ip[16];
    uint16_t start_port;
    uint16_t end_port;

} CgnatEntry;

typedef struct CgnatNode
{
    char inside_ip[16];
    CgnatEntry entry;
    UT_hash_handle hh;

} CgnatNode;

/* =========================================================
 * WHITELIST
 * ========================================================= */

typedef struct
{
    char msisdn[32];
    bool status;

} WhitelistInfo;

typedef struct WlNode
{
    char msisdn[32];
    WhitelistInfo info;
    UT_hash_handle hh;

} WlNode;

/* =========================================================
 * EXTRA AVPS
 * ========================================================= */

typedef struct
{
    uint8_t type;
    uint8_t len;
    uint8_t value[MAX_AVP_VALUE];

} extra_avps;

/* =========================================================
 * USER SESSION
 * ========================================================= */

typedef struct
{
    /* ================= FAST MODE FIELDS ================= */

    uint64_t u64ValidAttributes;

    uint32_t u32EventTimestamp;
    uint32_t packet_count;
    uint32_t destroy_time;

    uint8_t u8AccountStatusType;
    uint8_t u8IsWL;

    char acAccountSessionId[SESSION_ID_MAX_LEN];
    char acMultiSessionId[SESSION_ID_MAX_LEN];
    char acCallingStationId[32];

    uint8_t u8FramedIpv4Address[IPV4_OCTETS];
    uint8_t u8FramedIpv4PubAddress[IPV4_OCTETS];
    uint8_t u8FramedIpv6Prefix[IPV6_PREFIX_MAX_LEN];

    uint16_t portStart;
    uint16_t portEnd;

    struct tm sSessionStartTime;
    struct tm sSessionEndTime;

    /* ================= OPTIONAL AVPS ================= */

    uint16_t extra_avp_count;
    extra_avps extra_avps[MAX_EXTRA_AVPS];

} UserSessionInfo;

typedef struct SessionNode
{
    char acAccountSessionId[SESSION_ID_MAX_LEN];
    UserSessionInfo entry;
    UT_hash_handle hh;

} SessionNode;

/* =========================================================
 * RABBITMQ CONFIGURATION
 * ========================================================= */

typedef struct
{
    char host[128];
    char vhost[64];
    char user[64];
    char password[64];
    char exchange[64];
    uint16_t port;

} RabbitMQConfig;

/* =========================================================
 * RABBITMQ CLIENT
 * ========================================================= */

typedef struct
{
    amqp_connection_state_t conn;
    amqp_socket_t *socket;
    int channel;
    RabbitMQConfig cfg;

} RabbitMQClient;

/* =========================================================
 * RABBITMQ BOOTSTRAP
 * ========================================================= */

typedef struct
{
    int sessions_loaded;
} RabbitMQBootstrapState;

typedef void (*RabbitMQSyncHandler)(
    const char *routing_key,
    const void *body,
    size_t len,
    void *ctx);

typedef struct RabbitMQBootstrapCtx
{
    SessionNode **session_map;
    RabbitMQBootstrapState *state;

} RabbitMQBootstrapCtx;

/* =========================================================
 * DATABASE CONFIGURATION
 * ========================================================= */

typedef struct
{
    bool enabled;
    char host[128];
    char user[64];
    char password[64];
    char database[64];
    uint16_t port;

} DBConfig;

/* =========================================================
 * RADIUS PACKET
 * ========================================================= */

typedef struct
{
    const uint8_t *pData;
    const uint8_t *pPayload;

    uint16_t length;
    uint16_t payloadLen;

    uint8_t code;
    uint8_t identifier;

} RadiusPacket;

typedef struct
{
    uint16_t type;
    const char *name;

} RadiusAttributeMap;

/* =========================================================
 * TASK / PACKET CONTEXT
 * ========================================================= */

typedef struct
{
    /* ================= RAW PACKET ================= */

    uint8_t *data;
    uint32_t packet_length;

    /* ================= TIMESTAMP ================= */

    struct timeval timestamp;

    /* ================= LAYER OFFSETS ================= */

    uint16_t ethernet_offset;
    uint16_t ip_offset;
    uint16_t udp_offset;
    uint16_t radius_offset;

    /* ================= LAYER LENGTHS ================= */

    uint16_t ip_header_length;
    uint16_t udp_length;
    uint16_t radius_length;

    /* ================= PARSED PROTOCOL INFO ================= */

    uint16_t ethertype;

    uint8_t ip_version;
    uint8_t ip_protocol;

    uint32_t src_ip;
    uint32_t dst_ip;

    uint16_t src_port;
    uint16_t dst_port;

    /* ================= PACKET CLASSIFICATION ================= */

    PacketType packet_type;

    /* ================= DIRECT PROTOCOL POINTERS ================= */

    const uint8_t *pEthernet;
    const uint8_t *pIp;
    const uint8_t *pUdp;
    const uint8_t *pRadius;

} Task;

/* =========================================================
 * SHARED TASK QUEUE
 * ========================================================= */

typedef struct
{
    Task tasks[MAX_QUEUE_SIZE];

    int head;
    int tail;
    int count;

    pthread_mutex_t mutex;
    pthread_cond_t not_empty;
    pthread_cond_t not_full;

    bool shutdown;

} TaskQueue;