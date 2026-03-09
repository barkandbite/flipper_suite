/**
 * marauder.c — Marauder command abstraction over WiFi UART.
 *
 * Marauder text output format (relevant lines)
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *   scanap results:
 *     <idx> <SSID> <RSSI> <Channel> <BSSID> <Encryption>
 *     e.g.  0 MyNetwork -45 6 AA:BB:CC:DD:EE:FF WPA2
 *
 *   pingscan results:
 *     <IP> alive
 *     <IP> dead
 *
 *   portscan results:
 *     <port> open <service>
 *     <port> closed
 *
 *   Prompts start with ">"; binary PCAP framing with "[BUF/" — both are
 *   filtered upstream in wifi_uart.c before reaching this callback.
 *
 * Parsing strategy
 * ~~~~~~~~~~~~~~~~
 *   strtok is unavailable in the Flipper SDK libc.  All tokenising uses
 *   strchr to locate space delimiters and manual pointer arithmetic.
 */

#include "marauder.h"

#include <string.h>
#include <stdlib.h>

#define TAG "FPwn"

/* --------------------------------------------------------------------------
 * Internal struct
 * -------------------------------------------------------------------------- */
struct FPwnMarauder {
    FPwnWifiUart* uart;
    FPwnMarauderState state;

    FPwnWifiAP aps[FPWN_MAX_APS];
    uint32_t ap_count;

    FPwnNetHost hosts[FPWN_MAX_HOSTS];
    uint32_t host_count;

    FPwnPortResult ports[FPWN_MAX_PORTS];
    uint32_t port_count;

    FuriMutex* mutex;

    uint32_t scan_start_tick; /* furi_get_tick() when the current AP scan started */

    /* Secondary log callback — fires for every received line after parsing. */
    FPwnWifiRxCallback log_callback;
    void* log_callback_ctx;
};

/* --------------------------------------------------------------------------
 * Parser helpers
 * -------------------------------------------------------------------------- */

/* Copy at most `n-1` bytes of the current token (up to the next space or
 * end-of-string) into `dst`, then null-terminate.
 * Returns a pointer to the start of the NEXT token (after any trailing
 * spaces), or NULL if there is no further token. */
static const char* copy_token(const char* src, char* dst, size_t n) {
    size_t i = 0;
    while(*src && *src != ' ' && i < n - 1) {
        dst[i++] = *src++;
    }
    dst[i] = '\0';
    /* Advance past delimiter spaces to the next token. */
    while(*src == ' ')
        src++;
    return (*src) ? src : NULL;
}

/* --------------------------------------------------------------------------
 * Marauder output parsers
 * -------------------------------------------------------------------------- */

/*
 * Try to parse a scanap result line into `ap`.
 *
 * Expected format (space-separated):
 *   <idx> <SSID> <RSSI> <Channel> <BSSID> <Encryption>
 *
 * Returns true on success.
 */
static bool parse_ap_line(const char* line, FPwnWifiAP* ap) {
    const char* p = line;

    /* Field 0: index (decimal integer, discarded).
     * copy_token advances p to the start of the next token. */
    if(!p || *p < '0' || *p > '9') return false;
    char idx_buf[8];
    p = copy_token(p, idx_buf, sizeof(idx_buf));
    if(!p) return false;

    /* Field 1: SSID */
    p = copy_token(p, ap->ssid, sizeof(ap->ssid));
    if(!p) return false;

    /* Field 2: RSSI (signed, atoi handles leading '-') */
    char rssi_buf[8];
    p = copy_token(p, rssi_buf, sizeof(rssi_buf));
    ap->rssi = (int8_t)atoi(rssi_buf);
    if(!p) return false;

    /* Field 3: Channel */
    char ch_buf[4];
    p = copy_token(p, ch_buf, sizeof(ch_buf));
    ap->channel = (uint8_t)atoi(ch_buf);
    if(!p) return false;

    /* Field 4: BSSID */
    p = copy_token(p, ap->bssid, sizeof(ap->bssid));
    if(!p) return false;

    /* Field 5: Encryption label (last field — NULL return is fine) */
    char enc_buf[8];
    copy_token(p, enc_buf, sizeof(enc_buf));

    if(strcmp(enc_buf, "Open") == 0 || strcmp(enc_buf, "OPEN") == 0) {
        ap->encryption = 0;
    } else if(strcmp(enc_buf, "WEP") == 0) {
        ap->encryption = 1;
    } else if(strcmp(enc_buf, "WPA") == 0) {
        ap->encryption = 2;
    } else {
        /* WPA2, WPA2-EAP, unknown — default to WPA2 */
        ap->encryption = 3;
    }

    return true;
}

/*
 * Try to parse a pingscan result line into `host`.
 *
 * Expected format:  <IP> alive   or   <IP> dead
 */
static bool parse_host_line(const char* line, FPwnNetHost* host) {
    const char* p = line;

    /* Field 0: IP address — must start with a digit. */
    if(*p < '0' || *p > '9') return false;

    /* copy_token advances p to the "alive"/"dead" token. */
    p = copy_token(p, host->ip, sizeof(host->ip));
    if(!p) return false;

    host->alive = (strncmp(p, "alive", 5) == 0);
    return true;
}

/*
 * Try to parse a portscan result line into `port`.
 *
 * Expected formats:
 *   <port> open <service>
 *   <port> closed
 */
static bool parse_port_line(const char* line, FPwnPortResult* result) {
    const char* p = line;

    /* Field 0: port number — must start with a digit. */
    if(*p < '0' || *p > '9') return false;

    char port_buf[8];
    /* copy_token advances p to the "open"/"closed" token. */
    p = copy_token(p, port_buf, sizeof(port_buf));
    result->port = (uint16_t)atoi(port_buf);
    if(!p) return false;

    if(strncmp(p, "open", 4) == 0) {
        result->open = true;
        /* Advance p past the "open" token; copy_token returns a pointer
         * to the next token (the service name) or NULL. */
        char discard[8];
        const char* svc_start = copy_token(p, discard, sizeof(discard));
        if(svc_start && *svc_start) {
            copy_token(svc_start, result->service, sizeof(result->service));
        } else {
            result->service[0] = '\0';
        }
    } else if(strncmp(p, "closed", 6) == 0) {
        result->open = false;
        result->service[0] = '\0';
    } else {
        return false;
    }

    return true;
}

/* --------------------------------------------------------------------------
 * UART RX callback — dispatches parsed results into arrays
 * -------------------------------------------------------------------------- */
static void fpwn_marauder_rx_cb(const char* line, void* ctx) {
    FPwnMarauder* m = (FPwnMarauder*)ctx;

    /* Marauder prompt lines start with ">"; skip them. */
    if(line[0] == '>') return;

    furi_mutex_acquire(m->mutex, FuriWaitForever);

    switch(m->state) {
    case FPwnMarauderStateScanning: {
        /* "Scan complete" or "Scanning" status messages — ignore. */
        if(strstr(line, "Scan complete") || strstr(line, "Scanning")) break;

        FPwnWifiAP ap;
        memset(&ap, 0, sizeof(ap));
        if(parse_ap_line(line, &ap)) {
            if(m->ap_count < FPWN_MAX_APS) {
                m->aps[m->ap_count++] = ap;
                FURI_LOG_D(
                    TAG, "AP[%lu]: %s %s", (unsigned long)m->ap_count - 1, ap.ssid, ap.bssid);
            }
        }
        break;
    }

    case FPwnMarauderStatePingScan: {
        FPwnNetHost host;
        memset(&host, 0, sizeof(host));
        if(parse_host_line(line, &host)) {
            if(m->host_count < FPWN_MAX_HOSTS) {
                m->hosts[m->host_count++] = host;
                FURI_LOG_D(
                    TAG,
                    "Host[%lu]: %s %s",
                    (unsigned long)m->host_count - 1,
                    host.ip,
                    host.alive ? "alive" : "dead");
            }
        }
        break;
    }

    case FPwnMarauderStatePortScan: {
        FPwnPortResult pr;
        memset(&pr, 0, sizeof(pr));
        if(parse_port_line(line, &pr)) {
            if(m->port_count < FPWN_MAX_PORTS) {
                m->ports[m->port_count++] = pr;
                FURI_LOG_D(
                    TAG,
                    "Port[%lu]: %u %s",
                    (unsigned long)m->port_count - 1,
                    pr.port,
                    pr.open ? "open" : "closed");
            }
        }
        break;
    }

    default:
        /* Other states: log but don't parse structured output. */
        FURI_LOG_D(TAG, "RX[idle]: %s", line);
        break;
    }

    furi_mutex_release(m->mutex);

    /* Forward every line to the optional log callback (status TextBox). */
    if(m->log_callback) {
        m->log_callback(line, m->log_callback_ctx);
    }
}

/* --------------------------------------------------------------------------
 * Lifecycle
 * -------------------------------------------------------------------------- */

FPwnMarauder* fpwn_marauder_alloc(FPwnWifiUart* uart) {
    furi_assert(uart);

    FPwnMarauder* m = malloc(sizeof(FPwnMarauder));
    furi_assert(m);
    memset(m, 0, sizeof(FPwnMarauder));

    m->uart = uart;
    m->state = FPwnMarauderStateIdle;

    m->mutex = furi_mutex_alloc(FuriMutexTypeNormal);
    furi_assert(m->mutex);

    fpwn_wifi_uart_set_rx_callback(uart, fpwn_marauder_rx_cb, m);

    FURI_LOG_I(TAG, "Marauder layer initialised");
    return m;
}

void fpwn_marauder_free(FPwnMarauder* marauder) {
    furi_assert(marauder);
    /* Deregister callback so no stale calls fire after free. */
    fpwn_wifi_uart_set_rx_callback(marauder->uart, NULL, NULL);
    furi_mutex_free(marauder->mutex);
    free(marauder);
}

/* --------------------------------------------------------------------------
 * Commands
 * -------------------------------------------------------------------------- */

void fpwn_marauder_scan_ap(FPwnMarauder* m) {
    furi_assert(m);
    furi_mutex_acquire(m->mutex, FuriWaitForever);
    memset(m->aps, 0, sizeof(m->aps));
    m->ap_count = 0;
    m->state = FPwnMarauderStateScanning;
    m->scan_start_tick = furi_get_tick();
    furi_mutex_release(m->mutex);

    fpwn_wifi_uart_send(m->uart, "scanap");
    FURI_LOG_I(TAG, "scanap started");
}

void fpwn_marauder_stop_scan(FPwnMarauder* m) {
    furi_assert(m);
    fpwn_wifi_uart_send(m->uart, "stopscan");

    furi_mutex_acquire(m->mutex, FuriWaitForever);
    m->state = FPwnMarauderStateIdle;
    furi_mutex_release(m->mutex);

    FURI_LOG_I(TAG, "scan stopped");
}

void fpwn_marauder_join(FPwnMarauder* m, uint8_t ap_idx, const char* password) {
    furi_assert(m);
    furi_assert(password);

    char cmd[128];

    if(password[0] != '\0') {
        snprintf(cmd, sizeof(cmd), "join -a %u -p %s", (unsigned)ap_idx, password);
    } else {
        snprintf(cmd, sizeof(cmd), "join -a %u", (unsigned)ap_idx);
    }

    fpwn_wifi_uart_send(m->uart, cmd);

    furi_mutex_acquire(m->mutex, FuriWaitForever);
    m->state = FPwnMarauderStateJoined;
    furi_mutex_release(m->mutex);

    FURI_LOG_I(TAG, "join AP %u", (unsigned)ap_idx);
}

void fpwn_marauder_ping_scan(FPwnMarauder* m) {
    furi_assert(m);
    furi_mutex_acquire(m->mutex, FuriWaitForever);
    memset(m->hosts, 0, sizeof(m->hosts));
    m->host_count = 0;
    m->state = FPwnMarauderStatePingScan;
    furi_mutex_release(m->mutex);

    fpwn_wifi_uart_send(m->uart, "pingscan");
    FURI_LOG_I(TAG, "pingscan started");
}

void fpwn_marauder_port_scan(FPwnMarauder* m, uint8_t host_idx, bool all_ports) {
    furi_assert(m);
    furi_mutex_acquire(m->mutex, FuriWaitForever);
    memset(m->ports, 0, sizeof(m->ports));
    m->port_count = 0;
    m->state = FPwnMarauderStatePortScan;
    furi_mutex_release(m->mutex);

    char cmd[64];
    if(all_ports) {
        snprintf(cmd, sizeof(cmd), "portscan -t %u -a", (unsigned)host_idx);
    } else {
        snprintf(cmd, sizeof(cmd), "portscan -t %u", (unsigned)host_idx);
    }

    fpwn_wifi_uart_send(m->uart, cmd);
    FURI_LOG_I(TAG, "portscan host %u (all=%d)", (unsigned)host_idx, (int)all_ports);
}

void fpwn_marauder_deauth(FPwnMarauder* m) {
    furi_assert(m);
    fpwn_wifi_uart_send(m->uart, "attack -t deauth");

    furi_mutex_acquire(m->mutex, FuriWaitForever);
    m->state = FPwnMarauderStateDeauth;
    furi_mutex_release(m->mutex);

    FURI_LOG_I(TAG, "deauth attack started");
}

void fpwn_marauder_sniff_pmkid(FPwnMarauder* m) {
    furi_assert(m);
    fpwn_wifi_uart_send(m->uart, "sniffpmkid");

    furi_mutex_acquire(m->mutex, FuriWaitForever);
    m->state = FPwnMarauderStateSniffPmkid;
    furi_mutex_release(m->mutex);

    FURI_LOG_I(TAG, "pmkid sniff started");
}

void fpwn_marauder_stop(FPwnMarauder* m) {
    furi_assert(m);
    fpwn_wifi_uart_send(m->uart, "stopscan");

    furi_mutex_acquire(m->mutex, FuriWaitForever);
    m->state = FPwnMarauderStateIdle;
    furi_mutex_release(m->mutex);

    FURI_LOG_I(TAG, "stopped");
}

/* --------------------------------------------------------------------------
 * Log callback
 * -------------------------------------------------------------------------- */

void fpwn_marauder_set_log_callback(FPwnMarauder* m, FPwnWifiRxCallback cb, void* ctx) {
    furi_assert(m);
    m->log_callback_ctx = ctx;
    m->log_callback = cb;
}

/* --------------------------------------------------------------------------
 * Accessors
 * -------------------------------------------------------------------------- */

FPwnMarauderState fpwn_marauder_get_state(FPwnMarauder* m) {
    furi_assert(m);
    furi_mutex_acquire(m->mutex, FuriWaitForever);
    FPwnMarauderState s = m->state;
    furi_mutex_release(m->mutex);
    return s;
}

FPwnWifiAP* fpwn_marauder_get_aps(FPwnMarauder* m, uint32_t* count) {
    furi_assert(m);
    furi_assert(count);
    furi_mutex_acquire(m->mutex, FuriWaitForever);
    *count = m->ap_count;
    furi_mutex_release(m->mutex);
    return m->aps;
}

FPwnNetHost* fpwn_marauder_get_hosts(FPwnMarauder* m, uint32_t* count) {
    furi_assert(m);
    furi_assert(count);
    furi_mutex_acquire(m->mutex, FuriWaitForever);
    *count = m->host_count;
    furi_mutex_release(m->mutex);
    return m->hosts;
}

FPwnPortResult* fpwn_marauder_get_ports(FPwnMarauder* m, uint32_t* count) {
    furi_assert(m);
    furi_assert(count);
    furi_mutex_acquire(m->mutex, FuriWaitForever);
    *count = m->port_count;
    furi_mutex_release(m->mutex);
    return m->ports;
}

/* Returns the furi_get_tick() value recorded when the last AP scan started.
 * Used by the timer callback to auto-stop after a fixed interval. */
uint32_t fpwn_marauder_get_scan_start(FPwnMarauder* m) {
    furi_assert(m);
    return m->scan_start_tick;
}
