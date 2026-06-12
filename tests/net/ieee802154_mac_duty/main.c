#include <ctype.h>
#include <inttypes.h>
#include <math.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "event.h"
#include "event/thread.h"
#include "luid.h"
#include "byteorder.h"
#include "net/eui_provider.h"
#include "net/ieee802154.h"
#include "net/ieee802154/mac.h"
#include "net/ieee802154/radio.h"
#include "net/l2util.h"
#include "random.h"
#include "sema.h"
#include "shell.h"
#include "thread.h"
#include "ztimer.h"

#include "init_devs.h"
#if IS_ACTIVE(CONFIG_BOARD_IOTLAB_M3)
#define IEEE802154_MAC_TEST_BUF_SIZE (48U)
#else
#define IEEE802154_MAC_TEST_BUF_SIZE (64U)
#endif
#define IEEE802154_LONG_ADDRESS_LEN_STR_MAX \
        (sizeof("00:00:00:00:00:00:00:00"))
#define IEEE802154_SCAN_PAYLOAD_PRINT_MAX (16U)
#define SLEEPY_DATA_INDICATION_WAIT_MS   10U
#define SLEEPY_OFF_RETRY_DELAY_MS        1U
#define SLEEPY_OFF_RETRIES               20U
#define SLEEPY_RESPONSE_CONFIRM_TIMEOUT_MS 10U
#define SLEEPY_STOP_WAIT_MS              500U
#define RX_RETRY_DELAY_MS                1U
#define RX_RETRIES                       20U
#define AUTO_POLL_INTERVAL_MS            200U
#define QPOISSON_TIMEOUT_GUARD_MS         5000U
#define QPOISSON_RESPONSE_SEEN_MAX        256U

//static void _ev_data_confirm_handler(event_t *event);                        /**< TX Done event handler */                        /**< RX Done event handler */
static void _ev_radio_handler(event_t *event);                      /**< CRC Error event handler */
static void _ev_bh_request_handler(event_t *event);                 /**< BH Request event handler */
static void _ev_ack_timeout_handler(event_t *event);                /**< ACK Timeout event handler */
static void _ev_tick_handler(event_t *event);
static void _ev_scan_timer_handler(event_t *event);
static void _ev_rx_handler(event_t *event);
static void _ev_alloc_handler(event_t *event);                       /**< Set RX event handler */
static void _ev_assoc_indication_handler(event_t *event);
static void _ev_response_handler(event_t *event);
static void _ev_response_confirm_handler(event_t *event);

//static event_t ev_data_confirm = { .handler = _ev_data_confirm_handler };         /**< TX Done descriptor */         /**< RX Done descriptor */
static event_t ev_bh_request = { .handler = _ev_bh_request_handler };   /**< BH Request descriptor */
static event_t ev_ack_timeout = { .handler = _ev_ack_timeout_handler }; /**< ACK TO descriptor */
static event_t ev_tick = { .handler = _ev_tick_handler };
static event_t ev_scan_timer = { .handler = _ev_scan_timer_handler };
static event_t ev_rx = { .handler = _ev_rx_handler };
static event_t ev_alloc = { .handler = _ev_alloc_handler };               /**< Set RX descriptor */
static event_t ev_radio = { .handler = _ev_radio_handler };
static event_t ev_assoc_indication = { .handler = _ev_assoc_indication_handler };
static event_t ev_response = { .handler = _ev_response_handler };
static event_t ev_response_confirm = { .handler = _ev_response_confirm_handler };

typedef struct {
    bool in_use;
    uint8_t buf[IEEE802154_FRAME_LEN_MAX];
    iolist_t iolist;
} mac_buf_t;

ieee802154_mac_t mac;
static bool mac_ready;
mutex_t buf_lock;
static mutex_t print_lock;
mac_buf_t buf_pool[IEEE802154_MAC_TEST_BUF_SIZE];
static uint32_t tx_start_us[IEEE802154_MAC_TEST_BUF_SIZE];
static bool tx_start_valid[IEEE802154_MAC_TEST_BUF_SIZE];
static uint32_t tx_seq[IEEE802154_MAC_TEST_BUF_SIZE];
static bool tx_seq_valid[IEEE802154_MAC_TEST_BUF_SIZE];
static bool response_handle[IEEE802154_MAC_TEST_BUF_SIZE];
static uint16_t scan_channels[16];
static ieee802154_scan_result_t scan_results[16];
static size_t scan_results_used;
static ieee802154_mlme_scan_req_t scan_req;
static mutex_t assoc_lock;
static uint16_t assoc_short_addr_next = 0x0100;
static uint8_t beacon_payload[IEEE802154_FRAME_LEN_MAX];
static size_t beacon_payload_len;
static struct {
    bool pending;
    uint8_t addr[IEEE802154_LONG_ADDRESS_LEN];
    uint8_t addr_len;
    ieee802154_addr_mode_t addr_mode;
    ieee802154_assoc_capability_t cap;
} assoc_req;
static kernel_pid_t sleepy_pid = KERNEL_PID_UNDEF;
static volatile bool sleepy_run;
static volatile uint32_t sleepy_interval_ms;
static volatile uint32_t sleepy_awake_until_ms;
static volatile uint32_t sleepy_awake_started_ms;
static volatile uint32_t sleepy_poll_count;
static volatile uint32_t sleepy_last_poll_ms;
static volatile int sleepy_last_poll_res;
static volatile bool sleepy_trace;
static bool sleepy_radio_off;
static volatile bool sleepy_restore_rx_on_exit;
static volatile uint32_t sleepy_last_request_poll;
static volatile uint32_t sleepy_last_request_msg;
static volatile bool sleepy_last_request_valid;
static volatile uint32_t sleepy_last_response_msg;
static volatile bool sleepy_last_response_valid;
static sema_t sleepy_request_received;
static sema_t sleepy_response_confirmed;
static sema_t sleepy_stop_requested;
static sema_t qpoisson_data_confirmed;
static sema_t qpoisson_response_received;
static volatile bool qpoisson_response_wait_active;
static volatile uint32_t qpoisson_response_max_msg_id;
static bool qpoisson_response_seen[QPOISSON_RESPONSE_SEEN_MAX];
static struct {
    bool pending;
    uint32_t msg_id;
    uint32_t request_start_us;
} response;
static char sleepy_stack[THREAD_STACKSIZE_DEFAULT];

static const uint8_t payload[] =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Etiam ornare" \
    "lacinia mi elementum interdum ligula.";


static int start(int argc, char **argv);
static int poll(int argc, char **argv);
static int print_addr(int argc, char **argv);
static int scan(int argc, char **argv);
static int txtsnd(int argc, char **argv);
static int qpoisson(int argc, char **argv);
static int qserial(int argc, char **argv);
static int duty_cmd(int argc, char **argv);
static int measure_cmd(int argc, char **argv);
static int assoc_req_cmd(int argc, char **argv);
static int assoc_rsp_cmd(int argc, char **argv);
static int assoc_auto_cmd(int argc, char **argv);
static int set_panid_cmd(int argc, char **argv);
static int set_coord_cmd(int argc, char **argv);
static int set_coord_short_cmd(int argc, char **argv);
static int send_response(uint32_t msg_id, uint32_t request_start_us);
static int sleepy_start(uint32_t interval_ms);
static int sleepy_wake_rx_retry(void);
static void *sleepy_thread(void *arg);
static void sleepy_request_stop(bool restore_rx);
static void sleepy_wait_stopped(void);

static uint32_t _qpoisson_wait_timeout_ms(void)
{
    uint32_t sym_us = mac.sym_us ? mac.sym_us : 16U;
    uint64_t timeout_us = (uint64_t)IEEE802154_MAC_FRAME_TIMEOUT * sym_us;

    return (uint32_t)((timeout_us + 999U) / 1000U) + QPOISSON_TIMEOUT_GUARD_MS;
}

static bool require_mac_ready(void)
{
    if (!mac_ready) {
        puts("Error: IEEE 802.15.4 MAC radio not initialized");
        return false;
    }
    return true;
}

static const shell_command_t shell_commands[] = {
    { "print_addr", "Print IEEE 802.15.4 short and extended address", print_addr },
    { "txtsnd", "Send payload: txtsnd <addr> <len> <indirect (true/false)>", txtsnd },
    { "qpoisson", "Poisson indirect queue fill: qpoisson <first_short> <nodes> <count> <len> <mean_ms> [rr|random] | qpoisson <first_short> <nodes> <count> <len> <duty_ms> <load_factor> [rr|random]", qpoisson },
    { "qserial", "Serialized MAC RTT: qserial <first_short> <nodes> <count> <len> <mean_ms> [rr|random] | qserial <first_short> <nodes> <count> <len> <duty_ms> <load_factor> [rr|random]", qserial },
    { "duty", "Sleepy duty cycling: duty <interval_ms> | duty stop | duty off | duty status", duty_cmd },
    { "measure", "Power measurement: measure idle|active|cycle [phase_ms|duration_ms]", measure_cmd },
    { "poll", "MLME-POLL: poll <long_addr> (used if no coord short)", poll },
    { "scan", "Active scan: scan <duration_us> <ch1> [ch2 ...]", scan },
    { "start", "Start coordinator: start <channel> <panid> [ssid]", start },
    { "set_panid", "Set PAN ID: set_panid <0xNNNN>", set_panid_cmd },
    { "set_coord", "Set coordinator ext addr: set_coord <xx:.. (8 bytes)>", set_coord_cmd },
    { "set_coord_short", "Set coordinator short addr: set_coord_short <0xNNNN>", set_coord_short_cmd },
    { "assoc_req", "MLME-ASSOC.req: assoc_req <short|long> <addr> <panid> <channel>",
      assoc_req_cmd },
    { "assoc_rsp", "MLME-ASSOC.resp: assoc_rsp <short|long> <addr> <status> <short_addr>",
      assoc_rsp_cmd },
    { "assoc_auto", "Auto-assoc response: assoc_auto [on|off]", assoc_auto_cmd },
    { NULL, NULL, NULL }
};

static inline iolist_t *_mac_buf_alloc(void)
{
    mutex_lock(&buf_lock);
    for (uint8_t i = 0; i < IEEE802154_MAC_TEST_BUF_SIZE; i++) {
        mac_buf_t *p = &buf_pool[i];
        if (!p->in_use) {
            p->in_use = true;
            p->iolist.iol_base = p->buf;
            p->iolist.iol_len = IEEE802154_FRAME_LEN_MAX;
            memset(p->buf, 0, IEEE802154_FRAME_LEN_MAX);
            mutex_unlock(&buf_lock);
            return &p->iolist;
        }
    }
    mutex_unlock(&buf_lock);
    return NULL;
}

static inline void _mac_buf_free(ieee802154_mac_t *mac, mac_buf_t *p)
{
    if (!mac || !p) {
        return;
    }

    mutex_lock(&buf_lock);
    p->in_use = false;
    p->iolist.iol_len = 0;
    mutex_unlock(&buf_lock);
}

static const ieee802154_assoc_capability_t _assoc_cap_fixed = {
    .bits = {
        .device_type = 0,
        .power_source = 1,
        .rx_on_when_idle = 0,
        .allocate_address = 1,
    }
};
static bool assoc_auto = true;
static bool coord_mac_logging = false;

static void _log_printf(const char *fmt, ...)
{
    va_list args;

    mutex_lock(&print_lock);
    va_start(args, fmt);
    vprintf(fmt, args);
    va_end(args);
    puts("");
    mutex_unlock(&print_lock);
}

static const char *_frame_type_str(uint8_t frame_type)
{
    switch (frame_type) {
    case IEEE802154_FCF_TYPE_BEACON:
        return "beacon";
    case IEEE802154_FCF_TYPE_DATA:
        return "data";
    case IEEE802154_FCF_TYPE_ACK:
        return "ack";
    case IEEE802154_FCF_TYPE_MACCMD:
        return "maccmd";
    default:
        return "unknown";
    }
}

static const char *_mac_cmd_str(uint8_t cmd_id)
{
    switch (cmd_id) {
    case IEEE802154_CMD_ASSOCIATION_REQ:
        return "assoc_req";
    case IEEE802154_CMD_ASSOCIATION_RES:
        return "assoc_res";
    case IEEE802154_CMD_DISASSOCIATION:
        return "disassoc";
    case IEEE802154_CMD_DATA_REQ:
        return "data_req";
    case IEEE802154_CMD_BEACON_REQ:
        return "beacon_req";
    default:
        return "unknown";
    }
}


iolist_t * _allocate(void *mac, size_t len)
{
    (void)mac;
    (void)len;
    return _mac_buf_alloc();
}

static void my_confirm(void *arg, uint8_t handle, int status)
{
    (void)arg;
    uint32_t elapsed_us = 0;
    bool elapsed_valid = false;
    if ((handle < IEEE802154_MAC_TEST_BUF_SIZE) && tx_start_valid[handle]) {
        elapsed_us = ztimer_now(ZTIMER_USEC) - tx_start_us[handle];
        elapsed_valid = true;
        tx_start_valid[handle] = false;
    }

    if (handle < IEEE802154_MAC_TEST_BUF_SIZE) {
        if (response_handle[handle]) {
            response_handle[handle] = false;
            if (sleepy_trace) {
                _log_printf("sleepy: response_confirm handle=%u status=%d msg=%" PRIu32,
                            handle, status, sleepy_last_response_msg);
            }
            if (sleepy_run) {
                event_post(EVENT_PRIO_HIGHEST, &ev_response_confirm);
            }
        }
        else {
            bool has_qpoisson_seq = tx_seq_valid[handle];
            mutex_lock(&print_lock);
            printf("DATA confirm res=%d (%s) with handle: %d",
                   status, strerror(-status), handle);
            if (has_qpoisson_seq) {
                printf(" seq=%" PRIu32, tx_seq[handle]);
                tx_seq_valid[handle] = false;
            }
            if (elapsed_valid) {
                printf(" elapsed_us=%lu", (unsigned long)elapsed_us);
            }
            puts("");
            mutex_unlock(&print_lock);
            if (has_qpoisson_seq) {
                (void)sema_post(&qpoisson_data_confirmed);
            }
        }
        _mac_buf_free(&mac, &buf_pool[handle]);
    }
}

static void my_rx(void *mac)
{
    (void)mac;
    event_post(EVENT_PRIO_HIGHEST, &ev_rx);
}

static void my_ind(void *arg,
                   iolist_t *psdu,
                   const ieee802154_rx_info_t *info)
{
    (void)arg;

    size_t mhr_len = ieee802154_get_frame_hdr_len(psdu->iol_base);
    if (mhr_len == 0) {
        _log_printf("RX: get_frame_hdr_len failed");
        return;
    }
    if (mhr_len > psdu->iol_len) {
        _log_printf("RX: bad header length");
        return;
    }

    const uint8_t *payload = psdu->iol_base + mhr_len;
    size_t plen = psdu->iol_len - mhr_len;
    uint8_t frame_type = ((const uint8_t *)psdu->iol_base)[0] & IEEE802154_FCF_TYPE_MASK;

    if (coord_mac_logging) {
        int16_t rssi_dbm = 0;
        uint8_t lqi = 0;
        if (info) {
            rssi_dbm = (int16_t)ieee802154_rssi_to_dbm(info->rssi);
            lqi = info->lqi;
        }
        mutex_lock(&print_lock);
        printf("MAC RX type=%s len=%u lqi=%u rssi_dbm=%d",
               _frame_type_str(frame_type), (unsigned)psdu->iol_len,
               lqi, rssi_dbm);
        if (frame_type == IEEE802154_FCF_TYPE_MACCMD && plen > 0) {
            printf(" cmd=%s(0x%02x)", _mac_cmd_str(payload[0]), payload[0]);
        }
        puts("");
        mutex_unlock(&print_lock);
    }

    if (frame_type == IEEE802154_FCF_TYPE_DATA) {
        uint32_t msg_id;
        uint32_t request_start_us;
        char payload_str[IEEE802154_FRAME_LEN_MAX + 1];
        size_t payload_str_len = plen < IEEE802154_FRAME_LEN_MAX
                               ? plen : IEEE802154_FRAME_LEN_MAX;
        memcpy(payload_str, payload, payload_str_len);
        payload_str[payload_str_len] = '\0';

        if (sscanf(payload_str, "q:m=%" SCNu32 ":t=%" SCNu32,
                   &msg_id, &request_start_us) == 2) {
            if (sleepy_trace) {
                _log_printf("sleepy: rx_request poll=%" PRIu32 " msg=%" PRIu32
                            " now_ms=%" PRIu32,
                            sleepy_poll_count, msg_id,
                            ztimer_now(ZTIMER_MSEC));
            }
            if (!response.pending) {
                response.msg_id = msg_id;
                response.request_start_us = request_start_us;
                response.pending = true;
                sleepy_last_request_poll = sleepy_poll_count;
                sleepy_last_request_msg = msg_id;
                sleepy_last_request_valid = true;
                (void)sema_post(&sleepy_request_received);
                event_post(EVENT_PRIO_HIGHEST, &ev_response);
            }
            else {
                _log_printf("macq: response busy msg_id=%" PRIu32, msg_id);
            }
        }
        else if (sscanf(payload_str, "r:m=%" SCNu32 ":t=%" SCNu32,
                        &msg_id, &request_start_us) == 2) {
            uint32_t elapsed_us = ztimer_now(ZTIMER_USEC) - request_start_us;
            _log_printf("macq: response msg_id=%" PRIu32 " elapsed_us=%" PRIu32,
                        msg_id, elapsed_us);
            if (qpoisson_response_wait_active &&
                (msg_id > 0) && (msg_id <= qpoisson_response_max_msg_id)) {
                if (msg_id < QPOISSON_RESPONSE_SEEN_MAX) {
                    if (!qpoisson_response_seen[msg_id]) {
                        qpoisson_response_seen[msg_id] = true;
                        (void)sema_post(&qpoisson_response_received);
                    }
                }
                else {
                    (void)sema_post(&qpoisson_response_received);
                }
            }
        }
    }

    mac_buf_t *buf = container_of(psdu, mac_buf_t, iolist);
    _mac_buf_free(&mac, buf);
}

static void my_scan_confirm(void *arg, int status,
                            ieee802154_mlme_scan_req_t *req)
{
    (void)arg;
    printf("SCAN confirm res=%d (%s), results=%zu\n",
           status, strerror(-status), *req->results_used);
    for (size_t i = 0; i < *req->results_used; i++) {
        char addr_str[IEEE802154_LONG_ADDRESS_LEN_STR_MAX];
        const ieee802154_scan_result_t *res = &req->results[i];
        if (res->coord_addr.type == IEEE802154_ADDR_MODE_EXTENDED) {
            printf("[%u] ch=%u pan=0x%04x addr=%s lqi=%u rssi=%u",
                   (unsigned)i, res->channel, res->pan_id,
                   l2util_addr_to_str(res->coord_addr.v.ext_addr.uint8,
                                      IEEE802154_LONG_ADDRESS_LEN, addr_str),
                   res->lqi, res->rssi);
        }
        else if (res->coord_addr.type == IEEE802154_ADDR_MODE_SHORT) {
            printf("[%u] ch=%u pan=0x%04x addr=0x%04x lqi=%u rssi=%u",
                   (unsigned)i, res->channel, res->pan_id,
                   byteorder_ntohs(res->coord_addr.v.short_addr), res->lqi, res->rssi);
        }
        else {
            printf("[%u] ch=%u pan=0x%04x addr=none lqi=%u rssi=%u",
                   (unsigned)i, res->channel, res->pan_id,
                   res->lqi, res->rssi);
        }
        printf(" payload_len=%u payload=\"", res->beacon_payload_len);
        size_t payload_print = res->beacon_payload_len;
        if (payload_print > IEEE802154_SCAN_PAYLOAD_PRINT_MAX) {
            payload_print = IEEE802154_SCAN_PAYLOAD_PRINT_MAX;
        }
        for (size_t j = 0; j < payload_print; j++) {
            unsigned char c = res->beacon_payload[j];
            putchar(isprint(c) ? (char)c : '.');
        }
        if (payload_print < res->beacon_payload_len) {
            printf("..");
        }
        printf("\"\n");
    }
}

static void my_associate_indication(void *arg,
                                    const uint8_t *device_addr,
                                    uint8_t device_addr_len,
                                    ieee802154_addr_mode_t device_addr_mode,
                                    ieee802154_assoc_capability_t cap)
{
    (void)arg;
    if (!device_addr || (device_addr_len == 0)) {
        return;
    }

    mutex_lock(&assoc_lock);
    assoc_req.pending = true;
    assoc_req.addr_len = device_addr_len;
    assoc_req.addr_mode = device_addr_mode;
    assoc_req.cap = cap;
    memcpy(assoc_req.addr, device_addr, device_addr_len);
    mutex_unlock(&assoc_lock);

    if (!coord_mac_logging) {
        coord_mac_logging = true;
        _log_printf("macq: coordinator MAC logging enabled");
    }

    event_post(EVENT_PRIO_HIGHEST, &ev_assoc_indication);
}

static void my_associate_confirm(void *arg, int status, uint16_t short_addr)
{
    (void)arg;
    (void)short_addr;
    if (status == 0) {
        ieee802154_pib_value_t coord_short;
        ieee802154_mac_mlme_get_request(&mac, IEEE802154_PIB_COORD_SHORT_ADDRESS,
                                        &coord_short);
        if (coord_short.v.short_addr.u16 == 0xFFFFU) {
            coord_short.type = IEEE802154_PIB_TYPE_NUI16;
            coord_short.v.short_addr = byteorder_htons(0x0000);
            ieee802154_mac_mlme_set_request(&mac, IEEE802154_PIB_COORD_SHORT_ADDRESS,
                                            &coord_short);
        }
    }
}

static void _ev_tick_handler(event_t *event)
{
    (void)event;
    ieee802154_mac_tick(&mac);
}

static void my_alloc(void *mac, size_t len)
{
    (void)mac;
    (void)len;
    event_post(EVENT_PRIO_HIGHEST, &ev_alloc);
}

static void my_dealloc(void *arg, iolist_t *io)
{
    (void)arg;
    mac_buf_t *buf = container_of(io, mac_buf_t, iolist);

    _mac_buf_free(&mac, buf);
}

static void my_tick(void *mac)
{
    (void)mac;
    event_post(EVENT_PRIO_HIGHEST, &ev_tick);
}

static void my_scan_timer(void *mac)
{
    (void)mac;
    event_post(EVENT_PRIO_HIGHEST, &ev_scan_timer);
}

static void my_timeout(void *mac)
{
    (void)mac;
    event_post(EVENT_PRIO_HIGHEST, &ev_ack_timeout);
}

static void my_bh_cb(void *mac)
{
    (void)mac;
    event_post(EVENT_PRIO_HIGHEST, &ev_bh_request);
}
ieee802154_dev_t *_dev_radio_cb;
ieee802154_trx_ev_t _st_radio_cb;
static void my_radio_cb(ieee802154_dev_t *dev, ieee802154_trx_ev_t st)
{
    _dev_radio_cb = dev;
    _st_radio_cb = st;
    event_post(EVENT_PRIO_HIGHEST, &ev_radio);
}

static void _ev_radio_handler(event_t *event)
{
    (void)event;
    ieee802154_mac_handle_radio(_dev_radio_cb, _st_radio_cb);
}
static void _ev_scan_timer_handler(event_t *event)
{
    (void)event;
    ieee802154_mac_scan_timer_process(&mac);
}
static void _ev_bh_request_handler(event_t *event)
{
    (void)event;
    ieee802154_mac_bh_process(&mac);
}
static void _ev_ack_timeout_handler(event_t *event)
{
    (void)event;
    ieee802154_mac_ack_timeout_fired(&mac);
}
static void _ev_alloc_handler(event_t *event)
{
    (void)event;
    iolist_t *buf = _allocate(NULL, 0);
    if (!buf) {
        _log_printf("no RX buffer available");
        return;
    }
    ieee802154_mac_rx_process(&mac, buf);
}

static void _ev_rx_handler(event_t *event)
{
    (void)event;

    ieee802154_mac_rx_request_process(&mac);
}


static void _ev_assoc_indication_handler(event_t *event)
{
    (void)event;
    uint8_t addr_len;
    ieee802154_addr_mode_t mode;
    ieee802154_assoc_capability_t cap;
    uint8_t addr[IEEE802154_LONG_ADDRESS_LEN];

    mutex_lock(&assoc_lock);
    if (!assoc_req.pending) {
        mutex_unlock(&assoc_lock);
        return;
    }
    assoc_req.pending = false;
    addr_len = assoc_req.addr_len;
    mode = assoc_req.addr_mode;
    cap = assoc_req.cap;
    memcpy(addr, assoc_req.addr, addr_len);
    mutex_unlock(&assoc_lock);

    (void)cap;
    if (!assoc_auto) {
        _log_printf("ASSOC indication: auto response disabled");
        return;
    }

    int res;
    if ((mode == IEEE802154_ADDR_MODE_SHORT) && (addr_len >= 2)) {
        uint16_t assigned = assoc_short_addr_next++;
        network_uint16_t dst_short = { .u8 = { addr[0], addr[1] } };
        ieee802154_addr_t dst = { .type = mode, .v.short_addr = dst_short };
        res = ieee802154_mac_mlme_associate_response(&mac, &dst,
                                                     IEEE802154_ASSOC_STATUS_SUCCESS,
                                                     assigned);
        _log_printf("ASSOC indication mode=short response_res=%d assigned=0x%04x",
                    res, assigned);
    }
    else {
        uint16_t assigned = assoc_short_addr_next++;
        ieee802154_ext_addr_t ext;
        memcpy(ext.uint8, addr, IEEE802154_LONG_ADDRESS_LEN);
        ieee802154_addr_t dst = { .type = mode, .v.ext_addr = ext };
        res = ieee802154_mac_mlme_associate_response(&mac, &dst,
                                                     IEEE802154_ASSOC_STATUS_SUCCESS,
                                                     assigned);
        _log_printf("ASSOC indication mode=extended response_res=%d assigned=0x%04x",
                    res, assigned);
    }
    if (res < 0) {
        _log_printf("ASSOC response failed: %d (%s)", res, strerror(-res));
    }
}

static void _ev_response_handler(event_t *event)
{
    (void)event;

    if (!response.pending) {
        return;
    }

    uint32_t msg_id = response.msg_id;
    uint32_t request_start_us = response.request_start_us;
    response.pending = false;

    int res = send_response(msg_id, request_start_us);
    if ((res < 0) && sleepy_run) {
        event_post(EVENT_PRIO_HIGHEST, &ev_response_confirm);
    }
}

static void _ev_response_confirm_handler(event_t *event)
{
    (void)event;
    (void)sema_post(&sleepy_response_confirmed);
}


static int start(int argc, char **argv)
{
    if (!require_mac_ready()) {
        return 1;
    }

    sleepy_run = false;
    (void)sema_post(&sleepy_request_received);
    (void)sema_post(&sleepy_response_confirmed);

    if ((argc != 3) && (argc != 4)) {
        puts("Usage: start <channel> <panid> [ssid]\n");
        return 1;
    }

    uint16_t channel = (uint16_t)strtoul(argv[1], NULL, 0);
    uint16_t panid = (uint16_t)strtoul(argv[2], NULL, 0);

    ieee802154_pib_value_t pib_value;
    pib_value.type = IEEE802154_PIB_TYPE_U16;
    pib_value.v.u16 = panid;
    ieee802154_mac_mlme_set_request(&mac, IEEE802154_PIB_PAN_ID, &pib_value);
    coord_mac_logging = false;

    pib_value.type = IEEE802154_PIB_TYPE_NUI16;
    pib_value.v.short_addr = byteorder_htons(0x0000);
    ieee802154_mac_mlme_set_request(&mac, IEEE802154_PIB_SHORT_ADDR, &pib_value);

    /* Keep RX on when idle for polling device/coordinator interaction */
    pib_value.type = IEEE802154_PIB_TYPE_BOOL;
    pib_value.v.b = true;
    ieee802154_mac_mlme_set_request(&mac, IEEE802154_PIB_RX_ON_WHEN_IDLE, &pib_value);
    coord_mac_logging = true;

    if (argc == 4) {
        size_t ssid_len = strlen(argv[3]);
        if (ssid_len > sizeof(beacon_payload)) {
            puts("Error: ssid too long\n");
            return 1;
        }
        memcpy(beacon_payload, argv[3], ssid_len);
        beacon_payload_len = ssid_len;
        pib_value.type = IEEE802154_PIB_TYPE_BYTES;
        pib_value.v.bytes.ptr = beacon_payload;
        pib_value.v.bytes.len = beacon_payload_len;
        ieee802154_mac_mlme_set_request(&mac, IEEE802154_PIB_BEACON_PAYLOAD, &pib_value);
    }
    else {
        beacon_payload_len = 0;
        pib_value.type = IEEE802154_PIB_TYPE_BYTES;
        pib_value.v.bytes.ptr = NULL;
        pib_value.v.bytes.len = 0;
        ieee802154_mac_mlme_set_request(&mac, IEEE802154_PIB_BEACON_PAYLOAD, &pib_value);
    }

    int res = ieee802154_mlme_start_request(&mac, channel);
    if (res < 0) {
        puts("Error starting coordinator\n");
    }
    return 0;
}


static int poll(int argc, char **argv)
{
    if (!require_mac_ready()) {
        return 1;
    }

    uint8_t addr[IEEE802154_LONG_ADDRESS_LEN];
    int res;
    ieee802154_pib_value_t panid;
    ieee802154_pib_value_t coord_short;
    ieee802154_addr_mode_t coord_mode = IEEE802154_ADDR_MODE_EXTENDED;
    const void *coord_addr = addr;

    if (argc != 2) {
        puts("Usage: poll <long_addr>\n");
        return 1;
    }

    sleepy_request_stop(true);
    sleepy_wait_stopped();
    res = sleepy_wake_rx_retry();
    if (res < 0) {
        printf("poll: failed to wake radio: %d\n", res);
        return 1;
    }

    ieee802154_mac_mlme_get_request(&mac, IEEE802154_PIB_PAN_ID, &panid);
    ieee802154_mac_mlme_get_request(&mac, IEEE802154_PIB_COORD_SHORT_ADDRESS, &coord_short);
    if (coord_short.v.short_addr.u16 != 0xFFFFU) {
        coord_mode = IEEE802154_ADDR_MODE_SHORT;
        coord_addr = &coord_short.v.short_addr;
    }
    else {
        res = l2util_addr_from_str(argv[1], addr);
        if (res == 0) {
            puts("Usage: poll <long_addr>\n");
            return 1;
        }
    }

    res = ieee802154_mac_mlme_poll(&mac, coord_mode, panid.v.u16, coord_addr);
    return res < 0;
}

static int sleepy_set_rx_retry(void)
{
    int res = 0;
    for (unsigned i = 0; i <= SLEEPY_OFF_RETRIES; i++) {
        res = ieee802154_set_rx(&mac.submac);
        if (res >= 0) {
            return res;
        }
        if (res == -EALREADY) {
            return 0;
        }
        ztimer_sleep(ZTIMER_MSEC, SLEEPY_OFF_RETRY_DELAY_MS);
    }
    return res;
}

static int sleepy_set_idle_retry(void)
{
    int res = 0;
    for (unsigned i = 0; i <= SLEEPY_OFF_RETRIES; i++) {
        res = ieee802154_set_idle(&mac.submac);
        if (res >= 0) {
            return res;
        }
        if (res == -EALREADY) {
            return 0;
        }
        ztimer_sleep(ZTIMER_MSEC, SLEEPY_OFF_RETRY_DELAY_MS);
    }
    return res;
}

static void sleepy_set_rx_on_when_idle(bool enabled)
{
    ieee802154_pib_value_t pib_value = {
        .type = IEEE802154_PIB_TYPE_BOOL,
        .v.b = enabled,
    };
    ieee802154_mac_mlme_set_request(&mac, IEEE802154_PIB_RX_ON_WHEN_IDLE,
                                    &pib_value);
}

static int sleepy_set_off_retry(void)
{
    sleepy_set_rx_on_when_idle(false);

    int res = sleepy_set_idle_retry();
    if ((res < 0) && (res != -EALREADY)) {
        return res;
    }

    for (unsigned i = 0; i <= SLEEPY_OFF_RETRIES; i++) {
        res = ieee802154_radio_off(&mac.submac.dev);
        if (res >= 0) {
            sleepy_radio_off = true;
            return res;
        }
        ztimer_sleep(ZTIMER_MSEC, SLEEPY_OFF_RETRY_DELAY_MS);
    }
    return res;
}

static int sleepy_wake_rx_retry(void)
{
    int res = 0;
    if (!sleepy_radio_off) {
        sleepy_set_rx_on_when_idle(true);
        return sleepy_set_rx_retry();
    }

    for (unsigned i = 0; i <= SLEEPY_OFF_RETRIES; i++) {
        res = ieee802154_radio_request_on(&mac.submac.dev);
        if (res >= 0) {
            while (ieee802154_radio_confirm_on(&mac.submac.dev) == -EAGAIN) {}

            ieee802154_phy_conf_t phy_conf = {
                .channel = mac.submac.channel_num,
                .page = mac.submac.channel_page,
                .pow = mac.submac.tx_pow,
                .phy_mode = mac.submac.phy_mode,
            };
            res = ieee802154_radio_config_phy(&mac.submac.dev, &phy_conf);
            if (res < 0) {
                return res;
            }

            sleepy_radio_off = false;
            sleepy_set_rx_on_when_idle(true);
            return sleepy_set_rx_retry();
        }
        if (res == -EALREADY) {
            sleepy_radio_off = false;
            sleepy_set_rx_on_when_idle(true);
            return sleepy_set_rx_retry();
        }
        ztimer_sleep(ZTIMER_MSEC, SLEEPY_OFF_RETRY_DELAY_MS);
    }
    return res;
}

static void sleepy_wait_data_indication(uint32_t timeout_ms)
{
    sleepy_awake_started_ms = ztimer_now(ZTIMER_MSEC);
    sleepy_awake_until_ms = sleepy_awake_started_ms + timeout_ms;
    if (sema_wait_timed_ztimer(&sleepy_request_received, ZTIMER_MSEC,
                               timeout_ms) == 0) {
        if (sleepy_trace) {
            _log_printf("sleepy: data_indication poll=%" PRIu32 " msg=%" PRIu32
                        " wait_ms=%" PRIu32,
                        sleepy_last_request_poll, sleepy_last_request_msg,
                        ztimer_now(ZTIMER_MSEC) - sleepy_awake_started_ms);
        }
        sleepy_awake_until_ms = 0;
        int confirm_res = sema_wait_timed_ztimer(&sleepy_response_confirmed,
                                                 ZTIMER_MSEC,
                                                 SLEEPY_RESPONSE_CONFIRM_TIMEOUT_MS);
        if ((confirm_res != 0) && sleepy_trace) {
            _log_printf("sleepy: response_confirm_timeout poll=%" PRIu32
                        " msg=%" PRIu32 " timeout_ms=%u",
                        sleepy_last_request_poll, sleepy_last_request_msg,
                        SLEEPY_RESPONSE_CONFIRM_TIMEOUT_MS);
        }
        if ((confirm_res == 0) && sleepy_trace) {
            if (sleepy_last_response_valid) {
                _log_printf("sleepy: response_done poll=%" PRIu32 " msg=%" PRIu32
                            " total_awake_ms=%" PRIu32,
                            sleepy_last_request_poll, sleepy_last_response_msg,
                            ztimer_now(ZTIMER_MSEC) - sleepy_awake_started_ms);
            }
            else {
                _log_printf("sleepy: response_done poll=%" PRIu32
                            " msg=none total_awake_ms=%" PRIu32,
                            sleepy_last_request_poll,
                            ztimer_now(ZTIMER_MSEC) - sleepy_awake_started_ms);
            }
        }
    }
    else if (sleepy_trace) {
        _log_printf("sleepy: data_indication_timeout poll=%" PRIu32 " timeout_ms=%" PRIu32,
                    sleepy_poll_count, timeout_ms);
    }
}

static void sleepy_drain_response_events(void)
{
    while (sema_try_wait(&sleepy_request_received) == 0) {}
    while (sema_try_wait(&sleepy_response_confirmed) == 0) {}
}

static void sleepy_request_stop(bool restore_rx)
{
    sleepy_restore_rx_on_exit = restore_rx;
    sleepy_run = false;
    (void)sema_post(&sleepy_stop_requested);
    (void)sema_post(&sleepy_request_received);
    (void)sema_post(&sleepy_response_confirmed);
}

static void sleepy_wait_stopped(void)
{
    uint32_t started_ms = ztimer_now(ZTIMER_MSEC);

    while ((sleepy_pid != KERNEL_PID_UNDEF) &&
           ((ztimer_now(ZTIMER_MSEC) - started_ms) < SLEEPY_STOP_WAIT_MS)) {
        ztimer_sleep(ZTIMER_MSEC, SLEEPY_OFF_RETRY_DELAY_MS);
    }
}

static void sleepy_poll_once(void)
{
    int res;
    ieee802154_pib_value_t panid;
    ieee802154_pib_value_t coord_short;
    ieee802154_pib_value_t coord_ext;

    sleepy_poll_count++;
    sleepy_last_poll_ms = ztimer_now(ZTIMER_MSEC);
    sleepy_last_request_valid = false;
    sleepy_last_response_valid = false;

    ieee802154_mac_mlme_get_request(&mac, IEEE802154_PIB_PAN_ID, &panid);
    ieee802154_mac_mlme_get_request(&mac, IEEE802154_PIB_COORD_SHORT_ADDRESS,
                                    &coord_short);
    ieee802154_mac_mlme_get_request(&mac, IEEE802154_PIB_COORD_EXTENDED_ADDRESS,
                                    &coord_ext);

    sleepy_drain_response_events();
    if (coord_short.v.short_addr.u16 != 0xFFFFU) {
        res = ieee802154_mac_mlme_poll(&mac, IEEE802154_ADDR_MODE_SHORT,
                                       panid.v.u16, &coord_short.v.short_addr);
    }
    else {
        res = ieee802154_mac_mlme_poll(&mac, IEEE802154_ADDR_MODE_EXTENDED,
                                       panid.v.u16, &coord_ext.v.ext_addr);
    }
    sleepy_last_poll_res = res;
    if (sleepy_trace) {
        _log_printf("sleepy: poll count=%" PRIu32 " res=%d start_ms=%" PRIu32
                    " now_ms=%" PRIu32,
                    sleepy_poll_count, res, sleepy_last_poll_ms,
                    ztimer_now(ZTIMER_MSEC));
    }
}

static int sleepy_start(uint32_t interval_ms)
{
    sleepy_interval_ms = interval_ms;
    sleepy_run = true;

    if (sleepy_pid != KERNEL_PID_UNDEF) {
        return 0;
    }

    while (sema_try_wait(&sleepy_stop_requested) == 0) {}

    sleepy_pid = thread_create(sleepy_stack, sizeof(sleepy_stack),
                               THREAD_PRIORITY_MAIN - 1, 0,
                               sleepy_thread, NULL, "sleepy");
    if (sleepy_pid <= KERNEL_PID_UNDEF) {
        sleepy_pid = KERNEL_PID_UNDEF;
        sleepy_run = false;
        return -1;
    }

    return 0;
}

static void *sleepy_thread(void *arg)
{
    (void)arg;

    while (sleepy_run) {
        if (sleepy_set_off_retry() < 0) {
            ztimer_sleep(ZTIMER_MSEC, SLEEPY_OFF_RETRY_DELAY_MS);
            continue;
        }

        if (sema_wait_timed_ztimer(&sleepy_stop_requested, ZTIMER_MSEC,
                                   sleepy_interval_ms) == 0) {
            break;
        }
        if (!sleepy_run) {
            break;
        }

        if (sleepy_wake_rx_retry() < 0) {
            ztimer_sleep(ZTIMER_MSEC, SLEEPY_OFF_RETRY_DELAY_MS);
            continue;
        }

        sleepy_poll_once();
        /* If the poll triggers an indirect frame, data_indication schedules the
         * response and the response confirm releases us to sleep. */
        sleepy_wait_data_indication(SLEEPY_DATA_INDICATION_WAIT_MS);
        if (!sleepy_run) {
            break;
        }
    }

    if (sleepy_restore_rx_on_exit) {
        (void)sleepy_wake_rx_retry();
    }
    else {
        (void)sleepy_set_off_retry();
    }
    sleepy_pid = KERNEL_PID_UNDEF;
    return NULL;
}

static int duty_cmd(int argc, char **argv)
{
    if (!require_mac_ready()) {
        return 1;
    }

    if ((argc == 2) && (strcmp(argv[1], "status") == 0)) {
        printf("sleepy: status run=%u pid=%" PRIkernel_pid " interval=%lu polls=%lu "
               "last_poll_ms=%lu last_poll_res=%d awake_until_ms=%lu trace=%u "
               "now_ms=%lu\n",
               sleepy_run ? 1U : 0U, sleepy_pid,
               (unsigned long)sleepy_interval_ms,
               (unsigned long)sleepy_poll_count,
               (unsigned long)sleepy_last_poll_ms,
               sleepy_last_poll_res,
               (unsigned long)sleepy_awake_until_ms,
               sleepy_trace ? 1U : 0U,
               (unsigned long)ztimer_now(ZTIMER_MSEC));
        return 0;
    }

    if ((argc == 3) && (strcmp(argv[1], "trace") == 0)) {
        if (strcmp(argv[2], "on") == 0) {
            sleepy_trace = true;
            puts("duty trace on");
            return 0;
        }
        if (strcmp(argv[2], "off") == 0) {
            sleepy_trace = false;
            puts("duty trace off");
            return 0;
        }
        puts("Usage: duty trace <on|off>");
        return 1;
    }

    if ((argc == 2) && (strcmp(argv[1], "stop") == 0)) {
        sleepy_request_stop(true);
        sleepy_wait_stopped();
        int res = sleepy_wake_rx_retry();
        if (res < 0) {
            printf("duty: stop failed to set rx: %d\n", res);
            return 1;
        }
        puts("duty stop");
        return 0;
    }

    if ((argc == 2) && (strcmp(argv[1], "off") == 0)) {
        sleepy_request_stop(false);
        sleepy_wait_stopped();
        int res = sleepy_set_off_retry();
        if (res < 0) {
            printf("duty: off failed: %d\n", res);
            return 1;
        }
        printf("RADIO STATE    = %lu\n", NRF_RADIO->STATE);
        printf("HFCLKSTAT      = 0x%08lx\n", NRF_CLOCK->HFCLKSTAT);
        printf("UARTE0 ENABLE  = %lu\n", NRF_UARTE0->ENABLE);
        printf("RNG VALUE?     = 0x%08lx\n", NRF_RNG->VALUE);

        puts("duty off");
        return 0;
    }

    if (argc != 2) {
        puts("Usage: duty <interval_ms> | duty stop | duty off | duty status | duty trace <on|off>");
        return 1;
    }

    char *end = NULL;
    unsigned long interval = strtoul(argv[1], &end, 10);
    if ((end == argv[1]) || (*end != '\0')) {
        puts("Usage: duty <interval_ms> | duty stop | duty off | duty status | duty trace <on|off>");
        return 1;
    }

    if (interval == 0) {
        sleepy_request_stop(true);
        sleepy_wait_stopped();
        int res = sleepy_wake_rx_retry();
        if (res < 0) {
            printf("duty: failed to set rx: %d\n", res);
            return 1;
        }
        puts("duty 0");
        return 0;
    }

    if (sleepy_start((uint32_t)interval) < 0) {
        return 1;
    }

    printf("duty %lu\n", interval);
    return 0;
}

static int set_panid_cmd(int argc, char **argv)
{
    if (!require_mac_ready()) {
        return 1;
    }

    if (argc != 2) {
        puts("Usage: set_panid <0xNNNN>\n");
        return 1;
    }
    uint16_t panid = (uint16_t)strtoul(argv[1], NULL, 0);
    ieee802154_pib_value_t pib_value;
    pib_value.type = IEEE802154_PIB_TYPE_U16;
    pib_value.v.u16 = panid;
    ieee802154_mac_mlme_set_request(&mac, IEEE802154_PIB_PAN_ID, &pib_value);
    printf("panid set to 0x%04x\n", panid);
    return 0;
}

static int set_coord_cmd(int argc, char **argv)
{
    if (!require_mac_ready()) {
        return 1;
    }

    if (argc != 2) {
        puts("Usage: set_coord <xx:.. (8 bytes)>\n");
        return 1;
    }
    ieee802154_ext_addr_t ext;
    if (!l2util_addr_from_str(argv[1], ext.uint8)) {
        puts("invalid long addr\n");
        return 1;
    }
    ieee802154_pib_value_t pib_value;
    pib_value.type = IEEE802154_PIB_TYPE_EUI64;
    pib_value.v.ext_addr = ext;
    ieee802154_mac_mlme_set_request(&mac, IEEE802154_PIB_COORD_EXTENDED_ADDRESS, &pib_value);
    printf("coord ext addr set to %s\n", argv[1]);
    return 0;
}

static int set_coord_short_cmd(int argc, char **argv)
{
    if (!require_mac_ready()) {
        return 1;
    }

    if (argc != 2) {
        puts("Usage: set_coord_short <0xNNNN>\n");
        return 1;
    }
    uint16_t short_addr = (uint16_t)strtoul(argv[1], NULL, 0);
    ieee802154_pib_value_t pib_value;
    pib_value.type = IEEE802154_PIB_TYPE_NUI16;
    pib_value.v.short_addr = byteorder_htons(short_addr);
    ieee802154_mac_mlme_set_request(&mac, IEEE802154_PIB_COORD_SHORT_ADDRESS, &pib_value);
    printf("coord short addr set to 0x%04x\n", short_addr);
    return 0;
}
static int print_addr(int argc, char **argv)
{
    if (!require_mac_ready()) {
        return 1;
    }

    (void)argc;
    (void)argv;
    char long_addr_str[IEEE802154_LONG_ADDRESS_LEN_STR_MAX];
    char short_addr_str[IEEE802154_SHORT_ADDRESS_LEN * 3];
    ieee802154_pib_value_t short_addr;
    ieee802154_pib_value_t long_addr;
    ieee802154_mac_mlme_get_request(&mac, IEEE802154_PIB_SHORT_ADDR, &short_addr);
    ieee802154_mac_mlme_get_request(&mac, IEEE802154_PIB_EXTENDED_ADDRESS, &long_addr);
    printf("short %s\n", l2util_addr_to_str(
               short_addr.v.short_addr.u8, IEEE802154_SHORT_ADDRESS_LEN, short_addr_str));
    printf("extended %s\n", l2util_addr_to_str(
               long_addr.v.ext_addr.uint8, IEEE802154_LONG_ADDRESS_LEN, long_addr_str));
    return 0;
}

static int scan(int argc, char **argv)
{
    if (!require_mac_ready()) {
        return 1;
    }

    if (argc < 3) {
        puts("Usage: scan <duration_us> <ch1> [ch2 ...]\n");
        return 1;
    }

    uint32_t duration = (uint32_t)atoi(argv[1]);
    int channel_count = argc - 2;
    if (channel_count > (int)(sizeof(scan_channels) / sizeof(scan_channels[0]))) {
        puts("Error: too many channels\n");
        return 1;
    }

    for (int i = 0; i < channel_count; i++) {
        scan_channels[i] = (uint16_t)atoi(argv[i + 2]);
    }

    scan_results_used = 0;
    scan_req.channels = scan_channels;
    scan_req.channel_count = (uint8_t)channel_count;
    scan_req.results = scan_results;
    scan_req.results_len = sizeof(scan_results) / sizeof(scan_results[0]);
    scan_req.results_used = &scan_results_used;
    scan_req.duration = duration;

    int res = ieee802154_mac_mlme_scan_request(&mac, IEEE802154_SCAN_ACTIVE,
                                               &scan_req);
    if (res < 0) {
        printf("scan request failed: %d (%s)\n", res, strerror(-res));
        return 1;
    }
    return 0;
}

static int assoc_req_cmd(int argc, char **argv)
{
    if (!require_mac_ready()) {
        return 1;
    }

    if (argc != 5) {
        puts("Usage: assoc_req <short|long> <addr> <panid> <channel>\n");
        return 1;
    }

    sleepy_request_stop(true);
    sleepy_wait_stopped();
    int res = sleepy_wake_rx_retry();
    if (res < 0) {
        printf("assoc_req: failed to wake radio: %d\n", res);
        return 1;
    }

    ieee802154_addr_mode_t mode;
    uint16_t panid = (uint16_t)strtoul(argv[3], NULL, 0);
    uint16_t channel = (uint16_t)strtoul(argv[4], NULL, 0);

    if (strcmp(argv[1], "short") == 0) {
        mode = IEEE802154_ADDR_MODE_SHORT;
        uint16_t short_addr_host = (uint16_t)strtoul(argv[2], NULL, 0);
        network_uint16_t short_addr = byteorder_htons(short_addr_host);
        ieee802154_addr_t addr = { .type = mode, .v.short_addr = short_addr };
        ieee802154_pib_value_t pib_short = {
            .type = IEEE802154_PIB_TYPE_NUI16,
            .v.short_addr = short_addr
        };
        ieee802154_mac_mlme_set_request(&mac, IEEE802154_PIB_COORD_SHORT_ADDRESS, &pib_short);
        return ieee802154_mac_mlme_associate_request(&mac, &addr, channel, panid,
                                                     _assoc_cap_fixed);
    }
    else if (strcmp(argv[1], "long") == 0) {
        mode = IEEE802154_ADDR_MODE_EXTENDED;
        ieee802154_ext_addr_t ext;
        if (!l2util_addr_from_str(argv[2], ext.uint8)) {
            puts("invalid long addr\n");
            return 1;
        }
        ieee802154_addr_t addr = { .type = mode, .v.ext_addr = ext };
        ieee802154_pib_value_t pib_ext = {
            .type = IEEE802154_PIB_TYPE_EUI64,
            .v.ext_addr = ext
        };
        ieee802154_mac_mlme_set_request(&mac, IEEE802154_PIB_COORD_EXTENDED_ADDRESS, &pib_ext);
        return ieee802154_mac_mlme_associate_request(&mac, &addr, channel, panid,
                                                     _assoc_cap_fixed);
    }

    puts("Usage: assoc_req <short|long> <addr> <panid> <channel>\n");
    return 1;
}

static int assoc_rsp_cmd(int argc, char **argv)
{
    if (!require_mac_ready()) {
        return 1;
    }

    if (argc != 5) {
        puts("Usage: assoc_rsp <short|long> <addr> <status> <short_addr>\n");
        return 1;
    }

    ieee802154_addr_mode_t mode;
    ieee802154_assoc_status_t status =
        (ieee802154_assoc_status_t)strtoul(argv[3], NULL, 0);
    uint16_t short_addr = (uint16_t)strtoul(argv[4], NULL, 0);

    if (strcmp(argv[1], "short") == 0) {
        mode = IEEE802154_ADDR_MODE_SHORT;
        uint16_t dst_short_host = (uint16_t)strtoul(argv[2], NULL, 0);
        network_uint16_t dst_short = byteorder_htons(dst_short_host);
        ieee802154_addr_t addr = { .type = mode, .v.short_addr = dst_short };
        return ieee802154_mac_mlme_associate_response(&mac, &addr, status,
                                                      short_addr);
    }
    else if (strcmp(argv[1], "long") == 0) {
        mode = IEEE802154_ADDR_MODE_EXTENDED;
        ieee802154_ext_addr_t ext;
        if (!l2util_addr_from_str(argv[2], ext.uint8)) {
            puts("invalid long addr\n");
            return 1;
        }
        ieee802154_addr_t addr = { .type = mode, .v.ext_addr = ext };
        return ieee802154_mac_mlme_associate_response(&mac, &addr, status,
                                                      short_addr);
    }

    puts("Usage: assoc_rsp <short|long> <addr> <status> <short_addr>\n");
    return 1;
}

static int assoc_auto_cmd(int argc, char **argv)
{
    if (!require_mac_ready()) {
        return 1;
    }

    if (argc == 1) {
        printf("assoc_auto %s\n", assoc_auto ? "on" : "off");
        return 0;
    }
    if (argc == 2) {
        if (strcmp(argv[1], "on") == 0) {
            assoc_auto = true;
            puts("assoc_auto on\n");
            return 0;
        }
        if (strcmp(argv[1], "off") == 0) {
            assoc_auto = false;
            puts("assoc_auto off\n");
            return 0;
        }
    }
    puts("Usage: assoc_auto [on|off]\n");
    return 1;
}

static int send(uint8_t *dst,
                void *data, size_t len, bool indirect)
{
    iolist_t *msdu = _allocate(NULL, 0);
    if (!msdu) {
        puts("no TX buffer available\n");
        return -ENOBUFS;
    }
    msdu->iol_base = data;
    msdu->iol_len = len;
    msdu->iol_next = NULL;
    mac_buf_t *msdu_buf = container_of(msdu, mac_buf_t, iolist);
    uint8_t handle = (uint8_t)(msdu_buf - buf_pool);
    tx_start_us[handle] = ztimer_now(ZTIMER_USEC);
    tx_start_valid[handle] = true;
    ieee802154_pib_value_t panid;
    ieee802154_mac_mlme_get_request(&mac, IEEE802154_PIB_PAN_ID, &panid);
    int res = ieee802154_mcps_data_request(&mac,
                                           IEEE802154_ADDR_MODE_EXTENDED,
                                           IEEE802154_ADDR_MODE_EXTENDED,
                                           panid.v.u16,
                                           dst,
                                           msdu,
                                           handle,
                                           true,
                                           indirect);
    if (res < 0) {
        tx_start_valid[handle] = false;
        printf("error in request\n");
        _mac_buf_free(&mac, msdu_buf);
        return res;
    }

    return 0;
}

static int send_short(network_uint16_t dst_short,
                      void *data, size_t len, bool indirect)
{
    iolist_t *msdu = _allocate(NULL, 0);
    if (!msdu) {
        puts("no TX buffer available\n");
        return -ENOBUFS;
    }
    msdu->iol_base = data;
    msdu->iol_len = len;
    msdu->iol_next = NULL;
    mac_buf_t *msdu_buf = container_of(msdu, mac_buf_t, iolist);
    uint8_t handle = (uint8_t)(msdu_buf - buf_pool);
    tx_start_us[handle] = ztimer_now(ZTIMER_USEC);
    tx_start_valid[handle] = true;
    ieee802154_pib_value_t panid;
    ieee802154_mac_mlme_get_request(&mac, IEEE802154_PIB_PAN_ID, &panid);
    int res = ieee802154_mcps_data_request(&mac,
                                           IEEE802154_ADDR_MODE_SHORT,
                                           IEEE802154_ADDR_MODE_SHORT,
                                           panid.v.u16,
                                           &dst_short,
                                           msdu,
                                           handle,
                                           true,
                                           indirect);
    if (res < 0) {
        tx_start_valid[handle] = false;
        printf("error in request\n");
        _mac_buf_free(&mac, msdu_buf);
        return res;
    }

    return 0;
}

static uint32_t _exp_delay_ms(uint32_t mean_ms)
{
    if (mean_ms == 0) {
        return 0;
    }

    double u = ((double)random_uint32() + 1.0) / ((double)UINT32_MAX + 2.0);
    double sample_ms = -(double)mean_ms * log(u);

    if (sample_ms >= (double)UINT32_MAX) {
        return UINT32_MAX;
    }

    return (uint32_t)sample_ms;
}

static void _sleep_ms_jitter(uint32_t mean_ms)
{
    uint32_t delay_ms = _exp_delay_ms(mean_ms);

    if (delay_ms > 0) {
        ztimer_sleep(ZTIMER_MSEC, delay_ms);
    }
}

static int send_response(uint32_t msg_id, uint32_t request_start_us)
{
    iolist_t *msdu = _allocate(NULL, 0);
    if (!msdu) {
        if (sleepy_trace) {
            _log_printf("sleepy: response_send msg=%" PRIu32 " res=%d",
                        msg_id, -ENOBUFS);
        }
        return -ENOBUFS;
    }

    mac_buf_t *msdu_buf = container_of(msdu, mac_buf_t, iolist);
    uint8_t handle = (uint8_t)(msdu_buf - buf_pool);
    int payload_len = snprintf((char *)msdu_buf->buf, sizeof(msdu_buf->buf),
                               "r:m=%" PRIu32 ":t=%" PRIu32,
                               msg_id, request_start_us);
    if ((payload_len < 0) || ((size_t)payload_len >= sizeof(msdu_buf->buf))) {
        _mac_buf_free(&mac, msdu_buf);
        if (sleepy_trace) {
            _log_printf("sleepy: response_send msg=%" PRIu32 " res=%d",
                        msg_id, -EMSGSIZE);
        }
        return -EMSGSIZE;
    }

    msdu->iol_base = msdu_buf->buf;
    msdu->iol_len = (size_t)payload_len;
    msdu->iol_next = NULL;

    ieee802154_pib_value_t panid;
    ieee802154_pib_value_t coord_short;
    ieee802154_mac_mlme_get_request(&mac, IEEE802154_PIB_PAN_ID, &panid);
    ieee802154_mac_mlme_get_request(&mac, IEEE802154_PIB_COORD_SHORT_ADDRESS,
                                    &coord_short);

    tx_start_us[handle] = ztimer_now(ZTIMER_USEC);
    tx_start_valid[handle] = true;
    response_handle[handle] = true;
    sleepy_last_response_msg = msg_id;
    sleepy_last_response_valid = true;
    int res = ieee802154_mcps_data_request(&mac,
                                           IEEE802154_ADDR_MODE_SHORT,
                                           IEEE802154_ADDR_MODE_SHORT,
                                           panid.v.u16,
                                           &coord_short.v.short_addr,
                                           msdu,
                                           handle,
                                           true,
                                           false);
    if (res < 0) {
        tx_start_valid[handle] = false;
        response_handle[handle] = false;
        sleepy_last_response_valid = false;
        _mac_buf_free(&mac, msdu_buf);
    }
    if (sleepy_trace) {
        _log_printf("sleepy: response_send msg=%" PRIu32 " handle=%u res=%d",
                    msg_id, handle, res);
    }
    return res;
}

static int send_short_payload(uint16_t dst_short_host, unsigned seq,
                              size_t len, bool indirect)
{
    if (len > IEEE802154_FRAME_LEN_MAX) {
        return -EMSGSIZE;
    }

    iolist_t *msdu = _allocate(NULL, 0);
    if (!msdu) {
        _log_printf("macq: no TX buffer available");
        return -ENOBUFS;
    }

    mac_buf_t *msdu_buf = container_of(msdu, mac_buf_t, iolist);
    uint8_t handle = (uint8_t)(msdu_buf - buf_pool);
    uint32_t request_start_us = ztimer_now(ZTIMER_USEC);
    int payload_len = snprintf((char *)msdu_buf->buf, sizeof(msdu_buf->buf),
                               "q:m=%u:t=%" PRIu32, seq, request_start_us);
    if ((payload_len < 0) || ((size_t)payload_len > len)) {
        _mac_buf_free(&mac, msdu_buf);
        return -EMSGSIZE;
    }

    size_t used_len = (size_t)payload_len;
    msdu->iol_base = msdu_buf->buf;
    msdu->iol_len = used_len;
    msdu->iol_next = NULL;

    network_uint16_t dst_short = byteorder_htons(dst_short_host);
    ieee802154_pib_value_t panid;
    ieee802154_mac_mlme_get_request(&mac, IEEE802154_PIB_PAN_ID, &panid);
    tx_start_us[handle] = request_start_us;
    tx_start_valid[handle] = true;
    tx_seq[handle] = seq;
    tx_seq_valid[handle] = true;
    int res = ieee802154_mcps_data_request(&mac,
                                           IEEE802154_ADDR_MODE_SHORT,
                                           IEEE802154_ADDR_MODE_SHORT,
                                           panid.v.u16,
                                           &dst_short,
                                           msdu,
                                           handle,
                                           true,
                                           indirect);
    if (res < 0) {
        tx_start_valid[handle] = false;
        tx_seq_valid[handle] = false;
        _mac_buf_free(&mac, msdu_buf);
    }

    _log_printf("macq: enqueue dst=0x%04x seq=%u handle=%u len=%u indirect=%u res=%d",
                dst_short_host, seq, handle, (unsigned)used_len,
                indirect ? 1U : 0U, res);
    return res;
}

static int txtsnd(int argc, char **argv)
{
    if (!require_mac_ready()) {
        return 1;
    }

    uint8_t long_addr[IEEE802154_LONG_ADDRESS_LEN];
    uint16_t short_addr_host;
    network_uint16_t short_addr;
    size_t len;
    size_t res;
    bool indirect = false;

    if (argc != 4) {
        puts("Usage: txtsnd <addr> <len> <indirect (true/false)>\n"
             "  addr: short xx:yy or 0xNNNN / decimal, long xx:.. (8 bytes)\n>");
        return 1;
    }

    if (!((strcmp(argv[3], "true") == 0 ) || (strcmp(argv[3], "false") == 0)) ) {
        puts("Usage: txtsnd <addr> <len> <indirect (true/false)>\n"
             "  addr: short xx:yy or 0xNNNN / decimal, long xx:.. (8 bytes)\n");
        return 1;
    }

    if ((strcmp(argv[3], "true")) == 0) {
        indirect = true;
    }

    len = (size_t)atoi(argv[2]);

    if (strchr(argv[1], ':') != NULL) {
        res = l2util_addr_from_str(argv[1], long_addr);
        if (res == IEEE802154_LONG_ADDRESS_LEN) {
            return send(long_addr, (void *)payload, len, indirect);
        }
        if (res == IEEE802154_SHORT_ADDRESS_LEN) {
            short_addr.u8[0] = long_addr[0];
            short_addr.u8[1] = long_addr[1];
            return send_short(short_addr, (void *)payload, len, indirect);
        }
        puts("Usage: txtsnd <addr> <len> <indirect (true/false)>\n"
             "  addr: short xx:yy or 0xNNNN / decimal, long xx:.. (8 bytes)\n");
        return 1;
    }

    char *endptr = NULL;
    unsigned long parsed = strtoul(argv[1], &endptr, 0);
    if ((endptr == argv[1]) || (*endptr != '\0') || (parsed > 0xFFFFU)) {
        puts("Usage: txtsnd <addr> <len> <indirect (true/false)>\n"
             "  addr: short xx:yy or 0xNNNN / decimal, long xx:.. (8 bytes)\n");
        return 1;
    }

    short_addr_host = (uint16_t)parsed;
    short_addr = byteorder_htons(short_addr_host);
    return send_short(short_addr, (void *)payload, len, indirect);
}

static int qpoisson(int argc, char **argv)
{
    if (!require_mac_ready()) {
        return 1;
    }

    if ((argc < 6) || (argc > 8)) {
        puts("Usage: qpoisson <first_short> <nodes> <count> <len> <mean_ms> [rr|random]\n"
             "       qpoisson <first_short> <nodes> <count> <len> <duty_ms> <load_factor> [rr|random]");
        return 1;
    }

    char *endptr = NULL;
    unsigned long first = strtoul(argv[1], &endptr, 0);
    if ((endptr == argv[1]) || (*endptr != '\0') || (first > 0xFFFFU)) {
        puts("Usage: qpoisson <first_short> <nodes> <count> <len> <mean_ms> [rr|random]\n"
             "       qpoisson <first_short> <nodes> <count> <len> <duty_ms> <load_factor> [rr|random]");
        return 1;
    }

    unsigned nodes = (unsigned)strtoul(argv[2], NULL, 0);
    unsigned count = (unsigned)strtoul(argv[3], NULL, 0);
    size_t len = (size_t)strtoul(argv[4], NULL, 0);
    uint32_t mean_ms = (uint32_t)strtoul(argv[5], NULL, 0);
    double load_factor = 0.0;
    bool has_load_factor = false;
    bool random_dest = false;
    int mode_arg = -1;

    if (argc >= 7) {
        char *load_end = NULL;
        load_factor = strtod(argv[6], &load_end);
        if ((load_end != argv[6]) && (*load_end == '\0') && (load_factor > 0.0)) {
            double scaled_mean = (double)mean_ms / load_factor;
            mean_ms = scaled_mean < 1.0 ? 1U : (uint32_t)(scaled_mean + 0.5);
            has_load_factor = true;
            mode_arg = (argc == 8) ? 7 : -1;
        }
        else {
            mode_arg = 6;
        }
    }

    if ((argc == 8) && !has_load_factor) {
        puts("Usage: qpoisson <first_short> <nodes> <count> <len> <mean_ms> [rr|random]\n"
             "       qpoisson <first_short> <nodes> <count> <len> <duty_ms> <load_factor> [rr|random]");
        return 1;
    }

    if (mode_arg > 0) {
        if (strcmp(argv[mode_arg], "random") == 0) {
            random_dest = true;
        }
        else if (strcmp(argv[mode_arg], "rr") != 0) {
            puts("Usage: qpoisson <first_short> <nodes> <count> <len> <mean_ms> [rr|random]\n"
                 "       qpoisson <first_short> <nodes> <count> <len> <duty_ms> <load_factor> [rr|random]");
            return 1;
        }
    }

    if ((nodes == 0) || (count == 0) || (len == 0)) {
        puts("Usage: qpoisson <first_short> <nodes> <count> <len> <mean_ms> [rr|random]\n"
             "       qpoisson <first_short> <nodes> <count> <len> <duty_ms> <load_factor> [rr|random]");
        return 1;
    }

    bool indirect = has_load_factor;

    mutex_lock(&print_lock);
    printf("macq: qpoisson first=0x%04lx nodes=%u count=%u len=%u mean_ms=%lu mode=%s indirect=%u",
           first, nodes, count, (unsigned)len, (unsigned long)mean_ms,
           random_dest ? "random" : "rr", indirect ? 1U : 0U);
    if (has_load_factor) {
        printf(" duty_ms=%s load_factor=%s", argv[5], argv[6]);
    }
    puts("");
    mutex_unlock(&print_lock);

    unsigned enqueued = 0;
    unsigned failed = 0;
    while (sema_try_wait(&qpoisson_data_confirmed) == 0) {}
    while (sema_try_wait(&qpoisson_response_received) == 0) {}
    memset(qpoisson_response_seen, 0, sizeof(qpoisson_response_seen));
    qpoisson_response_max_msg_id = count;
    qpoisson_response_wait_active = true;
    for (unsigned seq = 1; seq <= count; seq++) {
        unsigned dst_index = random_dest ? (random_uint32() % nodes)
                                         : ((seq - 1) % nodes);
        uint16_t dst = (uint16_t)(first + dst_index);
        int res = send_short_payload(dst, seq, len, indirect);
        if (res == 0) {
            enqueued++;
        }
        else {
            failed++;
        }
        if (seq < count) {
            _sleep_ms_jitter(mean_ms);
        }
    }

    uint32_t wait_timeout_ms = _qpoisson_wait_timeout_ms();
    unsigned responses = 0;
    uint32_t response_wait_started_ms = ztimer_now(ZTIMER_MSEC);
    while (responses < enqueued) {
        uint32_t elapsed_ms = ztimer_now(ZTIMER_MSEC) - response_wait_started_ms;
        if (elapsed_ms >= wait_timeout_ms) {
            break;
        }
        uint32_t remaining_ms = wait_timeout_ms - elapsed_ms;
        if (sema_wait_timed_ztimer(&qpoisson_response_received, ZTIMER_MSEC,
                                   remaining_ms) != 0) {
            break;
        }
        responses++;
    }

    unsigned confirmed = 0;
    uint32_t wait_started_ms = ztimer_now(ZTIMER_MSEC);
    while (confirmed < enqueued) {
        uint32_t elapsed_ms = ztimer_now(ZTIMER_MSEC) - wait_started_ms;
        if (elapsed_ms >= wait_timeout_ms) {
            break;
        }
        uint32_t remaining_ms = wait_timeout_ms - elapsed_ms;
        if (sema_wait_timed_ztimer(&qpoisson_data_confirmed, ZTIMER_MSEC,
                                   remaining_ms) != 0) {
            break;
        }
        confirmed++;
    }

    while (sema_try_wait(&qpoisson_response_received) == 0) {
        responses++;
    }
    qpoisson_response_wait_active = false;

    if (confirmed < enqueued) {
        _log_printf("macq: qpoisson timeout requested=%u enqueued=%u failed=%u "
                    "confirmed=%u responses=%u timeout_ms=%" PRIu32,
                    count, enqueued, failed, confirmed, responses,
                    wait_timeout_ms);
        return 1;
    }

    _log_printf("macq: qpoisson done requested=%u enqueued=%u failed=%u "
                "confirmed=%u responses=%u timeout_ms=%" PRIu32,
                count, enqueued, failed, confirmed, responses, wait_timeout_ms);
    return failed ? 1 : 0;
}

static int qserial(int argc, char **argv)
{
    if (!require_mac_ready()) {
        return 1;
    }

    if ((argc < 6) || (argc > 8)) {
        puts("Usage: qserial <first_short> <nodes> <count> <len> <mean_ms> [rr|random]\n"
             "       qserial <first_short> <nodes> <count> <len> <duty_ms> <load_factor> [rr|random]");
        return 1;
    }

    char *endptr = NULL;
    unsigned long first = strtoul(argv[1], &endptr, 0);
    if ((endptr == argv[1]) || (*endptr != '\0') || (first > 0xFFFFU)) {
        puts("Usage: qserial <first_short> <nodes> <count> <len> <mean_ms> [rr|random]\n"
             "       qserial <first_short> <nodes> <count> <len> <duty_ms> <load_factor> [rr|random]");
        return 1;
    }

    unsigned nodes = (unsigned)strtoul(argv[2], NULL, 0);
    unsigned count = (unsigned)strtoul(argv[3], NULL, 0);
    size_t len = (size_t)strtoul(argv[4], NULL, 0);
    uint32_t mean_ms = (uint32_t)strtoul(argv[5], NULL, 0);
    double load_factor = 0.0;
    bool has_load_factor = false;
    bool random_dest = false;
    int mode_arg = -1;

    if (argc >= 7) {
        char *load_end = NULL;
        load_factor = strtod(argv[6], &load_end);
        if ((load_end != argv[6]) && (*load_end == '\0') && (load_factor > 0.0)) {
            double scaled_mean = (double)mean_ms / load_factor;
            mean_ms = scaled_mean < 1.0 ? 1U : (uint32_t)(scaled_mean + 0.5);
            has_load_factor = true;
            mode_arg = (argc == 8) ? 7 : -1;
        }
        else {
            mode_arg = 6;
        }
    }

    if ((argc == 8) && !has_load_factor) {
        puts("Usage: qserial <first_short> <nodes> <count> <len> <mean_ms> [rr|random]\n"
             "       qserial <first_short> <nodes> <count> <len> <duty_ms> <load_factor> [rr|random]");
        return 1;
    }

    if (mode_arg > 0) {
        if (strcmp(argv[mode_arg], "random") == 0) {
            random_dest = true;
        }
        else if (strcmp(argv[mode_arg], "rr") != 0) {
            puts("Usage: qserial <first_short> <nodes> <count> <len> <mean_ms> [rr|random]\n"
                 "       qserial <first_short> <nodes> <count> <len> <duty_ms> <load_factor> [rr|random]");
            return 1;
        }
    }

    if ((nodes == 0) || (count == 0) || (len == 0)) {
        puts("Usage: qserial <first_short> <nodes> <count> <len> <mean_ms> [rr|random]\n"
             "       qserial <first_short> <nodes> <count> <len> <duty_ms> <load_factor> [rr|random]");
        return 1;
    }

    bool indirect = has_load_factor;

    mutex_lock(&print_lock);
    printf("macq: qserial first=0x%04lx nodes=%u count=%u len=%u mean_ms=%lu mode=%s indirect=%u",
           first, nodes, count, (unsigned)len, (unsigned long)mean_ms,
           random_dest ? "random" : "rr", indirect ? 1U : 0U);
    if (has_load_factor) {
        printf(" duty_ms=%s load_factor=%s", argv[5], argv[6]);
    }
    puts("");
    mutex_unlock(&print_lock);

    unsigned enqueued = 0;
    unsigned failed = 0;
    unsigned confirmed = 0;
    unsigned responses = 0;
    uint32_t wait_timeout_ms = _qpoisson_wait_timeout_ms();
    while (sema_try_wait(&qpoisson_data_confirmed) == 0) {}
    while (sema_try_wait(&qpoisson_response_received) == 0) {}
    memset(qpoisson_response_seen, 0, sizeof(qpoisson_response_seen));
    qpoisson_response_max_msg_id = count;
    qpoisson_response_wait_active = true;

    for (unsigned seq = 1; seq <= count; seq++) {
        unsigned dst_index = random_dest ? (random_uint32() % nodes)
                                         : ((seq - 1) % nodes);
        uint16_t dst = (uint16_t)(first + dst_index);
        int res = send_short_payload(dst, seq, len, indirect);
        if (res != 0) {
            failed++;
            if (seq < count) {
                _sleep_ms_jitter(mean_ms);
            }
            continue;
        }

        enqueued++;
        bool response_seen = false;
        uint32_t wait_started_ms = ztimer_now(ZTIMER_MSEC);
        while (!response_seen) {
            while (sema_try_wait(&qpoisson_data_confirmed) == 0) {
                confirmed++;
            }
            if ((seq < QPOISSON_RESPONSE_SEEN_MAX) && qpoisson_response_seen[seq]) {
                response_seen = true;
                break;
            }

            uint32_t elapsed_ms = ztimer_now(ZTIMER_MSEC) - wait_started_ms;
            if (elapsed_ms >= wait_timeout_ms) {
                break;
            }

            uint32_t remaining_ms = wait_timeout_ms - elapsed_ms;
            uint32_t wait_ms = remaining_ms < 50U ? remaining_ms : 50U;
            if (sema_wait_timed_ztimer(&qpoisson_response_received, ZTIMER_MSEC,
                                       wait_ms) == 0) {
                if (seq >= QPOISSON_RESPONSE_SEEN_MAX) {
                    response_seen = true;
                }
            }
        }

        while (sema_try_wait(&qpoisson_data_confirmed) == 0) {
            confirmed++;
        }
        if (response_seen) {
            responses++;
        }

        if (seq < count) {
            _sleep_ms_jitter(mean_ms);
        }
    }

    while (sema_try_wait(&qpoisson_data_confirmed) == 0) {
        confirmed++;
    }
    qpoisson_response_wait_active = false;

    _log_printf("macq: qserial done requested=%u enqueued=%u failed=%u "
                "confirmed=%u responses=%u timeout_ms=%" PRIu32,
                count, enqueued, failed, confirmed, responses, wait_timeout_ms);
    return (failed || (responses < enqueued)) ? 1 : 0;
}

static void measure_prepare_radio_off(void)
{
    if (!mac_ready) {
        return;
    }

    sleepy_request_stop(false);
    sleepy_wait_stopped();
    int res = sleepy_set_off_retry();
    if (res < 0) {
        _log_printf("measure: radio off failed: %d", res);
    }
}

static void measure_busy_ms(uint32_t duration_ms)
{
    uint32_t start = ztimer_now(ZTIMER_MSEC);

    while ((ztimer_now(ZTIMER_MSEC) - start) < duration_ms) {
        __asm__ volatile ("" ::: "memory");
    }
}

static uint32_t measure_parse_duration(int argc, char **argv, uint32_t fallback_ms)
{
    if (argc < 3) {
        return fallback_ms;
    }

    char *end = NULL;
    unsigned long value = strtoul(argv[2], &end, 10);
    if ((end == argv[2]) || (*end != '\0') || (value > UINT32_MAX)) {
        return fallback_ms;
    }
    return (uint32_t)value;
}

static int measure_cmd(int argc, char **argv)
{
    if (argc < 2) {
        puts("Usage: measure idle|active|cycle [phase_ms|duration_ms]");
        return 1;
    }

    measure_prepare_radio_off();

    if (strcmp(argv[1], "idle") == 0) {
        uint32_t duration_ms = measure_parse_duration(argc, argv, 0U);
        puts("measure idle");
        if (duration_ms == 0) {
            thread_sleep();
        }
        else {
            ztimer_sleep(ZTIMER_MSEC, duration_ms);
        }
        return 0;
    }

    if (strcmp(argv[1], "active") == 0) {
        uint32_t duration_ms = measure_parse_duration(argc, argv, 1000U);
        puts("measure active");
        if (duration_ms == 0) {
            while (1) {
                measure_busy_ms(1000U);
            }
        }
        measure_busy_ms(duration_ms);
        return 0;
    }

    if (strcmp(argv[1], "cycle") == 0) {
        uint32_t phase_ms = measure_parse_duration(argc, argv, 1000U);
        if (phase_ms == 0) {
            phase_ms = 1000U;
        }
        printf("measure cycle %lu\n", (unsigned long)phase_ms);
        while (1) {
            ztimer_sleep(ZTIMER_MSEC, phase_ms);
            measure_busy_ms(phase_ms);
        }
    }

    puts("Usage: measure idle|active|cycle [phase_ms|duration_ms]");
    return 1;
}

static int _init(void)
{
    mutex_init(&buf_lock);
    mutex_init(&assoc_lock);
    mutex_init(&print_lock);
    sema_create(&sleepy_request_received, 0);
    sema_create(&sleepy_response_confirmed, 0);
    sema_create(&sleepy_stop_requested, 0);
    sema_create(&qpoisson_data_confirmed, 0);
    sema_create(&qpoisson_response_received, 0);
    memset(buf_pool, 0, sizeof(mac_buf_t) * IEEE802154_MAC_TEST_BUF_SIZE);
    ieee802154_mac_cbs_t cbs = {
        .data_confirm = my_confirm,
        .data_indication = my_ind,
        .mlme_scan_confirm = my_scan_confirm,
        .mlme_associate_indication = my_associate_indication,
        .mlme_associate_confirm = my_associate_confirm,
        .scan_timer_request = my_scan_timer,
        .tick_request = my_tick,
        .bh_request = my_bh_cb,
        .radio_cb_request = my_radio_cb,
        .ack_timeout = my_timeout,
        .allocate_request = my_alloc,
        .dealloc_request = my_dealloc,
        .rx_request = my_rx
    };
    ieee802154_dev_type_t dev_type = IEEE802154_DEV_TYPE_INVALID;
    if (ieee802154_mac_test_init_devs(&mac.submac.dev, &dev_type) < 0) {
        mac_ready = false;
        return -ENODEV;
    }
    ieee802154_mac_init_with_devtype(&mac, &cbs, dev_type);

    ieee802154_pib_value_t pib_value;
    eui64_t long_addr;

    luid_base(&long_addr, sizeof(long_addr));
    eui64_set_local(&long_addr);
    eui64_clear_group(&long_addr);

    pib_value.type = IEEE802154_PIB_TYPE_EUI64;
    pib_value.v.ext_addr = long_addr;
    ieee802154_mac_mlme_set_request(&mac, IEEE802154_PIB_EXTENDED_ADDRESS, &pib_value);
    mac_ready = true;
    return 0;
}

int main(void)
{
    int res = _init();
    if (res < 0) {
        printf("Initialization failed: IEEE 802.15.4 MAC radio unavailable (%d)\n", res);
    }


    char line_buf[SHELL_DEFAULT_BUFSIZE];

    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;

}
