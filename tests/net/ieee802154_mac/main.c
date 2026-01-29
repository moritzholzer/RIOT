#include <ctype.h>
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
#include "shell.h"

#define IEEE802154_MAC_TEST_BUF_SIZE (16U)
#define IEEE802154_LONG_ADDRESS_LEN_STR_MAX \
        (sizeof("00:00:00:00:00:00:00:00"))

//static void _ev_data_confirm_handler(event_t *event);                        /**< TX Done event handler */                        /**< RX Done event handler */
static void _ev_radio_handler(event_t *event);                      /**< CRC Error event handler */
static void _ev_bh_request_handler(event_t *event);                 /**< BH Request event handler */
static void _ev_ack_timeout_handler(event_t *event);                /**< ACK Timeout event handler */
static void _ev_tick_handler(event_t *event);
static void _ev_scan_timer_handler(event_t *event);
static void _ev_alloc_handler(event_t *event);                       /**< Set RX event handler */
static void _ev_rx_handler(event_t *event);
static void _ev_assoc_indication_handler(event_t *event);

//static event_t ev_data_confirm = { .handler = _ev_data_confirm_handler };         /**< TX Done descriptor */         /**< RX Done descriptor */
static event_t ev_bh_request = { .handler = _ev_bh_request_handler };   /**< BH Request descriptor */
static event_t ev_ack_timeout = { .handler = _ev_ack_timeout_handler }; /**< ACK TO descriptor */
static event_t ev_tick = { .handler = _ev_tick_handler };
static event_t ev_scan_timer = { .handler = _ev_scan_timer_handler };
static event_t ev_alloc = { .handler = _ev_alloc_handler };               /**< Set RX descriptor */
static event_t ev_radio = { .handler = _ev_radio_handler };
static event_t ev_rx = { .handler = _ev_rx_handler };
static event_t ev_assoc_indication = { .handler = _ev_assoc_indication_handler };

typedef struct {
    bool in_use;
    uint8_t buf[IEEE802154_FRAME_LEN_MAX];
    iolist_t iolist;
} mac_buf_t;

ieee802154_mac_t mac;
mutex_t buf_lock;
mac_buf_t buf_pool[IEEE802154_MAC_TEST_BUF_SIZE];
static uint16_t scan_channels[16];
static ieee802154_scan_result_t scan_results[16];
static size_t scan_results_used;
static ieee802154_mlme_scan_req_t scan_req;
static mutex_t assoc_lock;
static uint16_t assoc_short_addr_next = 0x0100;
static struct {
    bool pending;
    uint8_t addr[IEEE802154_LONG_ADDRESS_LEN];
    uint8_t addr_len;
    ieee802154_addr_mode_t addr_mode;
    ieee802154_assoc_capability_t cap;
} assoc_req;

static const uint8_t payload[] =
    "Lorem ipsum dolor sit amet, consectetur adipiscing elit. Etiam ornare" \
    "lacinia mi elementum interdum ligula.";


static int start(int argc, char **argv);
static int poll(int argc, char **argv);
static int print_addr(int argc, char **argv);
static int print_short(int argc, char **argv);
static int scan(int argc, char **argv);
static int txtsnd(int argc, char **argv);
static int txtsnd_short(int argc, char **argv);
static int alloc_cmd(int argc, char **argv);
static int assoc_req_cmd(int argc, char **argv);
static int assoc_rsp_cmd(int argc, char **argv);
static int assoc_auto_cmd(int argc, char **argv);
static const shell_command_t shell_commands[] = {
    { "print_addr", "Print IEEE802.15.4 addresses", print_addr },
    { "print_short", "Print IEEE802.15.4 short address", print_short },
    { "txtsnd", "Send IEEE 802.15.4 packet", txtsnd },
    { "txtsnd_short", "Send IEEE 802.15.4 packet to short addr", txtsnd_short },
    { "poll", "Send IEEE 802.15.4 data request packet", poll },
    { "scan", "Active scan: scan <duration_symbols> <ch1> [ch2 ...]", scan },
    { "start", "Start as IEEE 802.15.4 coordinator (always RX)", start },
    { "alloc", "Allocate/free RX buffer: alloc [free]", alloc_cmd },
    { "assoc_req", "MLME-ASSOC.req: assoc_req <short|long> <addr> <panid>", assoc_req_cmd },
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

static iolist_t *_last_alloc;
static const ieee802154_assoc_capability_t _assoc_cap_fixed = {
    .bits = {
        .device_type = 0,
        .power_source = 1,
        .rx_on_when_idle = 0,
        .allocate_address = 1,
    }
};
static bool assoc_auto = true;


iolist_t * _allocate(void)
{
    return _mac_buf_alloc();
}

static void my_confirm(void *arg, uint8_t handle, int status)
{
    (void)arg; (void)handle;
    printf("DATA confirm res=%d (%s) with handle: %d\n", status, strerror(-status), handle);
    if (handle < IEEE802154_MAC_TEST_BUF_SIZE) {
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
    (void)info;

    size_t mhr_len = ieee802154_get_frame_hdr_len(psdu->iol_base);
    if (mhr_len == 0) {
        puts("RX: get_frame_hdr_len failed");
        return;
    }
    if (mhr_len > psdu->iol_len) {
        puts("RX: bad header length");
        return;
    }

    const uint8_t *payload = psdu->iol_base + mhr_len;
    size_t plen = psdu->iol_len - mhr_len;

    printf("RX payload (as string): ");
    for (size_t i = 0; i < plen; i++) {
        unsigned char c = payload[i];
        putchar(isprint(c) ? (char)c : '.');
    }
    putchar('\n');
    mac_buf_t *buf = container_of(psdu, mac_buf_t, iolist);
    _mac_buf_free(&mac, buf);
}

static void my_scan_confirm(void *arg, int status,
                            ieee802154_mlme_scan_req_t *req)
{
    (void)arg;
    printf("SCAN confirm res=%d (%s), results=%u\n",
           status, strerror(-status), *req->results_used);
    for (size_t i = 0; i < *req->results_used; i++) {
        char addr_str[IEEE802154_LONG_ADDRESS_LEN_STR_MAX];
        const ieee802154_scan_result_t *res = &req->results[i];
        if (res->coord_addr.type == IEEE802154_ADDR_MODE_EXTENDED) {
            printf("[%u] ch=%u pan=0x%04x addr=%s lqi=%u rssi=%u\n",
                   (unsigned)i, res->channel, res->pan_id,
                   l2util_addr_to_str(res->coord_addr.v.ext_addr.uint8,
                                      IEEE802154_LONG_ADDRESS_LEN, addr_str),
                   res->lqi, res->rssi);
        }
        else if (res->coord_addr.type == IEEE802154_ADDR_MODE_SHORT) {
            printf("[%u] ch=%u pan=0x%04x addr=0x%04x lqi=%u rssi=%u\n",
                   (unsigned)i, res->channel, res->pan_id,
                   res->coord_addr.v.short_addr.u16, res->lqi, res->rssi);
        }
        else {
            printf("[%u] ch=%u pan=0x%04x addr=none lqi=%u rssi=%u\n",
                   (unsigned)i, res->channel, res->pan_id,
                   res->lqi, res->rssi);
        }
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

    event_post(EVENT_PRIO_HIGHEST, &ev_assoc_indication);
}

static void my_associate_confirm(void *arg, int status, uint16_t short_addr)
{
    (void)arg;
    printf("ASSOC confirm status=%d short_addr=0x%04x\n", status, short_addr);
}

static void _ev_tick_handler(event_t *event)
{
    (void)event;
    ieee802154_mac_tick(&mac);
}

static void my_alloc(void *mac)
{
    (void)mac;
    event_post(EVENT_PRIO_HIGHEST, &ev_alloc);
}

static void my_dealloc(void *mac, iolist_t *io)
{
    mac_buf_t *buf = container_of(io, mac_buf_t, iolist);

    _mac_buf_free((ieee802154_mac_t *)&mac, buf);
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
    iolist_t *buf = _allocate();
    if (!buf) {
        puts("no RX buffer available\n");
        return;
    }
    ieee802154_mac_rx_process(&mac, buf);
}

static void _ev_rx_handler(event_t *event)
{
    (void)event;
    if (ieee802154_set_rx(&mac.submac) < 0) {
        printf("error switching back to rx\n");
    }
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
        puts("ASSOC indication: auto response disabled\n");
        return;
    }

    int res;
    if ((mode == IEEE802154_ADDR_MODE_SHORT) && (addr_len >= 2)) {
        network_uint16_t dst_short = { .u8 = { addr[0], addr[1] } };
        res = ieee802154_mac_mlme_associate_response(&mac, mode, &dst_short,
                                                     IEEE802154_ASSOC_STATUS_SUCCESS,
                                                     assoc_short_addr_next++);
    }
    else {
        res = ieee802154_mac_mlme_associate_response(&mac, mode, addr,
                                                     IEEE802154_ASSOC_STATUS_SUCCESS,
                                                     assoc_short_addr_next++);
    }
    if (res < 0) {
        printf("ASSOC response failed: %d (%s)\n", res, strerror(-res));
    }
}


static int start(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    int res = ieee802154_mlme_start_request(&mac, CONFIG_IEEE802154_DEFAULT_CHANNEL);
    if (res < 0) {
        puts("Error starting coordinator\n");
    }
    return 0;
}


static int poll(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    uint8_t addr[IEEE802154_LONG_ADDRESS_LEN];
    int res;

    res = l2util_addr_from_str(argv[1], addr);
    if (res == 0) {
        puts("Usage: poll <long_addr>\n");
        return 1;
    }

    ieee802154_mac_mlme_poll(&mac, IEEE802154_ADDR_MODE_EXTENDED, CONFIG_IEEE802154_DEFAULT_PANID,
                             addr);
    return 0;
}

static int print_addr(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    char addr_str[IEEE802154_LONG_ADDRESS_LEN_STR_MAX];
    ieee802154_pib_value_t long_addr;
    ieee802154_mac_mlme_get_request(&mac, IEEE802154_PIB_EXTENDED_ADDRESS, &long_addr);
    printf("%s\n", l2util_addr_to_str(
               long_addr.v.ext_addr.uint8, IEEE802154_LONG_ADDRESS_LEN, addr_str));
    return 0;
}

static int print_short(int argc, char **argv)
{
    (void)argc;
    (void)argv;
    ieee802154_pib_value_t short_addr;
    ieee802154_mac_mlme_get_request(&mac, IEEE802154_PIB_SHORT_ADDR, &short_addr);
    printf("0x%04x\n", byteorder_ntohs(short_addr.v.short_addr));
    return 0;
}

static int scan(int argc, char **argv)
{
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

static int alloc_cmd(int argc, char **argv)
{
    if (argc > 1 && strcmp(argv[1], "free") == 0) {
        if (!_last_alloc) {
            puts("no buffer allocated\n");
            return 1;
        }
        mac_buf_t *buf = container_of(_last_alloc, mac_buf_t, iolist);
        _mac_buf_free(&mac, buf);
        _last_alloc = NULL;
        puts("buffer freed\n");
        return 0;
    }

    iolist_t *buf = _mac_buf_alloc();
    if (!buf) {
        puts("no RX buffer available\n");
        return 1;
    }
    _last_alloc = buf;
    mac_buf_t *p = container_of(buf, mac_buf_t, iolist);
    printf("buffer allocated (slot=%u)\n",
           (unsigned)(p - buf_pool));
    return 0;
}

static int assoc_req_cmd(int argc, char **argv)
{
    if (argc != 4) {
        puts("Usage: assoc_req <short|long> <addr> <panid>\n");
        return 1;
    }

    ieee802154_addr_mode_t mode;
    uint16_t panid = (uint16_t)strtoul(argv[3], NULL, 0);

    if (strcmp(argv[1], "short") == 0) {
        mode = IEEE802154_ADDR_MODE_SHORT;
        uint16_t short_addr_host = (uint16_t)strtoul(argv[2], NULL, 0);
        network_uint16_t short_addr = byteorder_htons(short_addr_host);
        return ieee802154_mac_mlme_associate_request(&mac, mode, panid,
                                                     &short_addr, _assoc_cap_fixed);
    }
    else if (strcmp(argv[1], "long") == 0) {
        mode = IEEE802154_ADDR_MODE_EXTENDED;
        ieee802154_ext_addr_t ext;
        if (!l2util_addr_from_str(argv[2], ext.uint8)) {
            puts("invalid long addr\n");
            return 1;
        }
        return ieee802154_mac_mlme_associate_request(&mac, mode, panid,
                                                     &ext, _assoc_cap_fixed);
    }

    puts("Usage: assoc_req <short|long> <addr> <panid>\n");
    return 1;
}

static int assoc_rsp_cmd(int argc, char **argv)
{
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
        return ieee802154_mac_mlme_associate_response(&mac, mode, &dst_short,
                                                      status, short_addr);
    }
    else if (strcmp(argv[1], "long") == 0) {
        mode = IEEE802154_ADDR_MODE_EXTENDED;
        ieee802154_ext_addr_t ext;
        if (!l2util_addr_from_str(argv[2], ext.uint8)) {
            puts("invalid long addr\n");
            return 1;
        }
        return ieee802154_mac_mlme_associate_response(&mac, mode, &ext,
                                                      status, short_addr);
    }

    puts("Usage: assoc_rsp <short|long> <addr> <status> <short_addr>\n");
    return 1;
}

static int assoc_auto_cmd(int argc, char **argv)
{
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
    iolist_t *msdu = _allocate();
    if (!msdu) {
        puts("no TX buffer available\n");
        return -ENOBUFS;
    }
    msdu->iol_base = data;
    msdu->iol_len = len;
    msdu->iol_next = NULL;
    mac_buf_t *msdu_buf = container_of(msdu, mac_buf_t, iolist);
    uint8_t handle = (uint8_t)(msdu_buf - buf_pool);
    int res = ieee802154_mcps_data_request(&mac,
                                           IEEE802154_ADDR_MODE_EXTENDED,
                                           IEEE802154_ADDR_MODE_EXTENDED,
                                           CONFIG_IEEE802154_DEFAULT_PANID,
                                           dst,
                                           msdu,
                                           handle,
                                           true,
                                           indirect);
    if (res < 0) {
        printf("error in request\n");
        _mac_buf_free(&mac, msdu_buf);
        return res;
    }

    return 0;
}

static int send_short(network_uint16_t dst_short,
                      void *data, size_t len, bool indirect)
{
    iolist_t *msdu = _allocate();
    if (!msdu) {
        puts("no TX buffer available\n");
        return -ENOBUFS;
    }
    msdu->iol_base = data;
    msdu->iol_len = len;
    msdu->iol_next = NULL;
    mac_buf_t *msdu_buf = container_of(msdu, mac_buf_t, iolist);
    uint8_t handle = (uint8_t)(msdu_buf - buf_pool);
    int res = ieee802154_mcps_data_request(&mac,
                                           IEEE802154_ADDR_MODE_SHORT,
                                           IEEE802154_ADDR_MODE_SHORT,
                                           CONFIG_IEEE802154_DEFAULT_PANID,
                                           &dst_short,
                                           msdu,
                                           handle,
                                           true,
                                           indirect);
    if (res < 0) {
        printf("error in request\n");
        _mac_buf_free(&mac, msdu_buf);
        return res;
    }

    return 0;
}

static int txtsnd(int argc, char **argv)
{
    uint8_t addr[IEEE802154_LONG_ADDRESS_LEN];
    size_t len;
    size_t res;
    bool indirect = false;

    if (argc != 4) {
        puts("Usage: txtsnd <long_addr> <len> <indirect (true/false)>\n>");
        return 1;
    }

    if (!((strcmp(argv[3], "true") == 0 ) || (strcmp(argv[3], "false") == 0)) ) {
        puts("Usage: txtsnd <long_addr> <len> <indirect (true/false)\n");
        return 1;
    }

    if ((strcmp(argv[3], "true")) == 0) {
        indirect = true;
    }

    res = l2util_addr_from_str(argv[1], addr);
    if (res == 0) {
        puts("Usage: txtsnd <long_addr> <len> <indirect (true/false)\n");
        return 1;
    }
    len = atoi(argv[2]);

    return send(addr, (void * )payload, len, indirect);
}

static int txtsnd_short(int argc, char **argv)
{
    uint16_t addr_host;
    network_uint16_t addr;
    size_t len;
    bool indirect = false;

    if (argc != 4) {
        puts("Usage: txtsnd_short <short_addr> <len> <indirect (true/false)>\n>");
        return 1;
    }

    if (!((strcmp(argv[3], "true") == 0 ) || (strcmp(argv[3], "false") == 0)) ) {
        puts("Usage: txtsnd_short <short_addr> <len> <indirect (true/false)>\n");
        return 1;
    }

    if ((strcmp(argv[3], "true")) == 0) {
        indirect = true;
    }

    addr_host = (uint16_t)strtoul(argv[1], NULL, 0);
    addr = byteorder_htons(addr_host);
    len = (size_t)atoi(argv[2]);

    return send_short(addr, (void * )payload, len, indirect);
}

static int _init(void)
{
    mutex_init(&buf_lock);
    mutex_init(&assoc_lock);
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
    ieee802154_mac_init(&mac, &cbs);

    ieee802154_pib_value_t pib_value;
    eui64_t long_addr;
    
    luid_base(&long_addr, sizeof(long_addr));
    eui64_set_local(&long_addr);
    eui64_clear_group(&long_addr);
    
    pib_value.type = IEEE802154_PIB_TYPE_EUI64;
    pib_value.v.ext_addr = long_addr;
    ieee802154_mac_mlme_set_request(&mac, IEEE802154_PIB_EXTENDED_ADDRESS, &pib_value);
    return 0;
}

int main(void)
{
    _init();

    char line_buf[SHELL_DEFAULT_BUFSIZE];

    shell_run(shell_commands, line_buf, SHELL_DEFAULT_BUFSIZE);

    return 0;
}
