#include "net/eui_provider.h"
#include "net/ieee802154.h"
#include "net/ieee802154/mac.h"
#include "net/ieee802154/radio.h"
#include "luid.h"
#include <stdio.h>
#include <ctype.h>
#include "event.h"
#include "event/thread.h"

ieee802154_mac_t mac;

#define IEEE802154_MAC_TEST_BUF_SIZE (8U)

//static void _ev_data_confirm_handler(event_t *event);                        /**< TX Done event handler */                        /**< RX Done event handler */
static void _ev_radio_handler(event_t *event);                      /**< CRC Error event handler */
static void _ev_bh_request_handler(event_t *event);                     /**< BH Request event handler */
static void _ev_ack_timeout_handler(event_t *event);                    /**< ACK Timeout event handler */
static void _ev_tick_handler(event_t *event);
static void _ev_send_handler(event_t *event);                         /**< Set RX event handler */
static void _ev_rx_handler(event_t *event);  

//static event_t ev_data_confirm = { .handler = _ev_data_confirm_handler };         /**< TX Done descriptor */         /**< RX Done descriptor */
static event_t ev_bh_request = { .handler = _ev_bh_request_handler };   /**< BH Request descriptor */
static event_t ev_ack_timeout = { .handler = _ev_ack_timeout_handler }; /**< ACK TO descriptor */
static event_t ev_tick = { .handler = _ev_tick_handler };
static event_t ev_send = { .handler = _ev_send_handler };           /**< Set RX descriptor */
static event_t ev_radio = {.handler = _ev_radio_handler };
static event_t ev_rx    = {.handler = _ev_rx_handler};

mutex_t lock;
mutex_t buf_lock;

typedef struct {
    bool in_use;
    uint8_t buf[IEEE802154_FRAME_LEN_MAX];
    iolist_t iolist;
} mac_buf_t;

mac_buf_t buf_pool[IEEE802154_MAC_TEST_BUF_SIZE];
static inline iolist_t *_mac_buf_alloc(void)
{
    mutex_lock(&buf_lock);
    for (uint8_t i = 0; i < IEEE802154_MAC_TEST_BUF_SIZE; i++) {
        mac_buf_t *p = &buf_pool[i];
        if (!p->in_use)
        {
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


iolist_t * _allocate(void)
{
    puts("allocate\n");
    return _mac_buf_alloc();
}

static void my_confirm(void *arg, uint8_t handle, int status) {
    (void)arg; (void)handle;
    printf("DATA confirm res=%d (%s)\n", status, strerror(-status));
}

static void my_rx(void *mac)
{
    (void) mac;
    event_post(EVENT_PRIO_HIGHEST,&ev_rx);
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

static void _ev_tick_handler(event_t *event){
    (void) event;
    puts("ACK TIMEOUT TIMER\n");
    ieee802154_mac_tick(&mac);
}

static void my_send(void *mac)
{
    (void) mac;
    event_post(EVENT_PRIO_HIGHEST, &ev_send);
}

static void my_tick(void *mac){
    (void) mac;
    event_post(EVENT_PRIO_HIGHEST, &ev_tick);
}

static void my_timeout(void *mac){
    (void) mac;
    puts("ACK TIMEOUT TIMER\n");
    event_post(EVENT_PRIO_HIGHEST, &ev_ack_timeout);
}

static void my_bh_cb(void *mac){
    (void) mac;
    event_post(EVENT_PRIO_HIGHEST, &ev_bh_request);
}
ieee802154_dev_t *_dev_radio_cb;
ieee802154_trx_ev_t _st_radio_cb;
static void my_radio_cb(ieee802154_dev_t *dev, ieee802154_trx_ev_t st){
    _dev_radio_cb = dev;
    _st_radio_cb = st;
    event_post(EVENT_PRIO_HIGHEST, &ev_radio);
}

static void _ev_radio_handler(event_t *event){
    (void) event;
    mutex_lock(&lock);
    ieee802154_mac_handle_radio(_dev_radio_cb, _st_radio_cb);
    mutex_unlock(&lock);
}
static void _ev_bh_request_handler(event_t *event){
    (void) event;
    mutex_lock(&lock);
    ieee802154_mac_bh_process(&mac);
    mutex_unlock(&lock);
}
static void _ev_ack_timeout_handler(event_t *event){
    (void) event;
    mutex_lock(&lock);
    puts("ACK Timeout\n");
    ieee802154_mac_ack_timeout_fired(&mac);
    mutex_unlock(&lock);
}
static void _ev_send_handler(event_t *event){
    (void) event;
    mutex_lock(&lock);
    iolist_t *buf = _allocate();
    ieee802154_mac_send_process(&mac, buf);
    mutex_unlock(&lock);
}

static void _ev_rx_handler(event_t *event){
    (void) event;
    mutex_lock(&lock);
    if (ieee802154_set_rx(&mac.submac) <0 ){
        printf("error switching back to rx\n");
    }
    printf("state: %d \n", ieee802154_submac_state_is_rx(&mac.submac));
    mutex_unlock(&lock);
}

int main(void){
    mutex_init(&lock);
    memset(buf_pool, 0, sizeof(mac_buf_t) * IEEE802154_MAC_TEST_BUF_SIZE);
    ieee802154_mac_cbs_t cbs = {
        .data_confirm = my_confirm,
        .data_indication = my_ind,
        .tick_request = my_tick,
        .bh_request = my_bh_cb,
        .radio_cb_request = my_radio_cb,
        .ack_timeout = my_timeout,
        .allocate_request = my_send,
        .rx_request = my_rx
    };
    ieee802154_mac_init(&mac, &cbs);

    ieee802154_pib_value_t pib_value;
    eui64_t long_addr;
    network_uint16_t short_addr;

    luid_base(&long_addr, sizeof(long_addr));
    eui64_set_local(&long_addr);
    eui64_clear_group(&long_addr);
    eui_short_from_eui64(&long_addr, &short_addr);
    pib_value.type = IEEE802154_PIB_TYPE_EUI64;
    pib_value.v.ext_addr = long_addr;
    ieee802154_mac_mlme_set_request(&mac, IEEE802154_PIB_EXTENDED_ADDRESS, &pib_value);
    pib_value.type = IEEE802154_PIB_TYPE_NUI16;
    pib_value.v.short_addr = short_addr;
    //printf("short addr: %02X%02X\n", short_addr.u8[0], short_addr.u8[1]);
    ieee802154_mac_mlme_set_request(&mac, IEEE802154_PIB_SHORT_ADDR, &pib_value);
    //ieee802154_pib_value_t value;
    //ieee802154_mac_mlme_get_request(&mac, IEEE802154_PIB_DSN, &value);
    //printf("%u\n", value.v.u8);
    // if (res != 0) {
    //     printf("set failed: %d\n", res);
    //     return 1;
    // }

    printf("SRC EUI64 = ");
    for (unsigned i = 0; i < 8; i++)
    {
        printf("%02x", long_addr.uint8[i]);
    }
    puts("\n");
    // res = ieee802154_mac_start(&mac);
    // if (res != 0) {
    //     printf("set failed: %d\n", res);
    //     return 1;
    // }

    int res = ieee802154_mlme_start_request(&mac, CONFIG_IEEE802154_DEFAULT_CHANNEL);
    if (res < 0)
    {
        puts("Error in start\n");
    }
    ieee802154_ext_addr_t dst = { .uint8 = { 0xde, 0xe2, 0x51, 0xe6, 0x0d, 0x67, 0x87, 0x83 }};

    char *data = "hello world";
    iolist_t msdu;
    msdu.iol_base = data;
    msdu.iol_len = strlen(data);
    msdu.iol_next = NULL;
    mutex_lock(&lock);
    res = ieee802154_mcps_data_request(&mac,
                                  IEEE802154_ADDR_MODE_EXTENDED,
                                  IEEE802154_ADDR_MODE_EXTENDED,
                                  CONFIG_IEEE802154_DEFAULT_PANID,
                                  &dst,
                                  &msdu,
                                  1,
                                  true,
                                  true);
    if (res < 0){
        printf("error in request\n");
    }
    mutex_unlock(&lock);
    // mutex_lock(&lock);
    // ieee802154_ext_addr_t dst = { .uint8 = { 0xba, 0x0c, 0xb7, 0xed, 0x21, 0xb2, 0xd9, 0x9e }};
    // ieee802154_mac_mlme_poll(&mac, IEEE802154_ADDR_MODE_EXTENDED, CONFIG_IEEE802154_DEFAULT_PANID, &dst);
    // mutex_unlock(&lock);
    // // if (res != 0) {
    //     printf("get failed: %d\n", res);
    //     return 1;
    // }
    return 0;
}
