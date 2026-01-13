/*
 * SPDX-FileCopyrightText: 2026 HAW Hamburg
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @{
 *
 * @file
 * @author Moritz Holzer <moritz.holzer@haw-hamburg.de>
 */

#include <string.h>

#include "container.h"
#include "bhp/event.h"
#include "isrpipe/read_timeout.h"
#include "ztimer.h"
#include "msg.h"

#include "net/ieee802154/mac_internal.h"
#include "net/ieee802154/mac.h"
#include "net/ieee802154/mac_pib.h"


#define ENABLE_DEBUG 1
#include "debug.h"

#include "event/thread.h"
extern void auto_init_event_thread(void);

#ifdef MODULE_CC2538_RF
#  include "cc2538_rf.h"
#endif

#ifdef MODULE_ESP_IEEE802154
#  include "esp_ieee802154_hal.h"
#endif

#ifdef MODULE_NRF802154
#  include "nrf802154.h"
#endif

#ifdef MODULE_SOCKET_ZEP
#  include "socket_zep.h"
#  include "socket_zep_params.h"
#else
#  define SOCKET_ZEP_MAX  0
#endif

#define RADIOS_NUM IS_USED(MODULE_CC2538_RF) + \
                     IS_USED(MODULE_NRF802154) + \
                     SOCKET_ZEP_MAX + \
                     IS_USED(MODULE_MRF24J40) + \
                     IS_USED(MODULE_KW2XRF) + \
                     IS_USED(MODULE_ESP_IEEE802154)


#ifdef MODULE_KW2XRF
#  include "kw2xrf.h"
#  include "kw2xrf_params.h"
#  define KW2XRF_NUM   ARRAY_SIZE(kw2xrf_params)
static kw2xrf_t kw2xrf_dev[KW2XRF_NUM];
static bhp_event_t kw2xrf_bhp[KW2XRF_NUM];
#endif

#ifdef MODULE_MRF24J40
#include "mrf24j40.h"
#include "mrf24j40_params.h"
#define MRF24J40_NUM    ARRAY_SIZE(mrf24j40_params)
static mrf24j40_t mrf24j40_dev[MRF24J40_NUM];
static bhp_event_t mrf24j40_bhp[MRF24J40_NUM];
#endif

static void _hal_init_dev(ieee802154_mac_t *mac, ieee802154_dev_type_t dev_type)
{
    if (IS_USED(MODULE_EVENT_THREAD)) {
        auto_init_event_thread();
    }

    ieee802154_dev_t *radio = NULL;
    bool ok = false;

    (void)radio;

    if (RADIOS_NUM == 0) {
        puts("Radio is either not supported or not present");
        assert(false);
    }

    switch (dev_type) {

        case IEEE802154_DEV_TYPE_CC2538_RF:
#if IS_USED(MODULE_CC2538_RF)
            if ((radio = cb(IEEE802154_DEV_TYPE_CC2538_RF, opaque))) {
                cc2538_rf_hal_setup(radio);
                cc2538_init();
                ok = true;
            }
#else
            puts("CC2538_RF selected but MODULE_CC2538_RF not compiled in");
#endif
            break;

        case IEEE802154_DEV_TYPE_ESP_IEEE802154:
#if IS_USED(MODULE_ESP_IEEE802154)
            if ((radio = cb(IEEE802154_DEV_TYPE_ESP_IEEE802154, opaque))) {
                esp_ieee802154_setup(radio);
                esp_ieee802154_init();
                ok = true;
            }
#else
            puts("ESP_IEEE802154 selected but MODULE_ESP_IEEE802154 not compiled in");
#endif
            break;

        case IEEE802154_DEV_TYPE_NRF802154:
#if IS_USED(MODULE_NRF802154)
            if ((radio = &mac->submac.dev)) {
                nrf802154_hal_setup(radio);
                nrf802154_init();
                ok = true;
            }
#else
            puts("NRF802154 selected but MODULE_NRF802154 not compiled in");
#endif
            break;

        case IEEE802154_DEV_TYPE_KW2XRF:
#if IS_USED(MODULE_KW2XRF)
            if ((radio = &mac->submac.dev)) {
                for (unsigned i = 0; i < KW2XRF_NUM; i++) {
                    const kw2xrf_params_t *p = &kw2xrf_params[i];
                    bhp_event_init(&kw2xrf_bhp[i], EVENT_PRIO_HIGHEST,
                                   &kw2xrf_radio_hal_irq_handler, radio);
                    kw2xrf_init(&kw2xrf_dev[i], p, radio, bhp_event_isr_cb, &kw2xrf_bhp[i]);
                    break; /* init one */
                }
                ok = true;
            }
#else
            puts("KW2XRF selected but MODULE_KW2XRF not compiled in");
#endif
            break;

        case IEEE802154_DEV_TYPE_SOCKET_ZEP:
#if IS_USED(MODULE_SOCKET_ZEP)
        {
            static socket_zep_t _socket_zeps[SOCKET_ZEP_MAX];

            if ((radio = &mac->submac.dev)) {
                socket_zep_hal_setup(&_socket_zeps[0], radio);
                socket_zep_setup(&_socket_zeps[0], &socket_zep_params[0]);
                ok = true;
            }
        }
#else
            puts("SOCKET_ZEP selected but MODULE_SOCKET_ZEP not compiled in");
#endif
            break;

        case IEEE802154_DEV_TYPE_MRF24J40:
#if IS_USED(MODULE_MRF24J40)
            if ((radio = cb(IEEE802154_DEV_TYPE_MRF24J40, opaque))) {
                for (unsigned i = 0; i < MRF24J40_NUM; i++) {
                    const mrf24j40_params_t *p = &mrf24j40_params[i];
                    bhp_event_init(&mrf24j40_bhp[i], EVENT_PRIO_HIGHEST,
                                   &mrf24j40_radio_irq_handler, radio);
                    mrf24j40_init(&mrf24j40_dev[i], p, radio, bhp_event_isr_cb, &mrf24j40_bhp[i]);
                    break; /* init one */
                }
                ok = true;
            }
#else
            puts("MRF24J40 selected but MODULE_MRF24J40 not compiled in");
#endif
            break;

        default:
            puts("Unknown/invalid radio type");
            break;
    }

    if (!ok) {
        puts("Requested radio type not supported/compiled-in or not present");
        assert(false);
    }
}


void ieee802154_init_mac_thread(ieee802154_mac_t *mac, const ieee802154_mac_cbs_t *cbs){
    memset(mac, 0, sizeof(*mac));
    mac->cbs = *cbs;
    ieee802154_mac_pib_init(mac);
    _hal_init_dev(mac, IEEE802154_DEV_TYPE_KW2XRF);
}

void ieee802154_mac_post_event(ieee802154_mac_t *mac, ieee802154_mac_ev_t ev)
{
    isrpipe_write_one(&mac->evpipe, (uint8_t)ev);
}

static void _radio_cb(ieee802154_dev_t *dev, ieee802154_trx_ev_t st)
{
    ieee802154_submac_t *submac = container_of(dev, ieee802154_submac_t, dev);
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);

    ieee802154_mac_ev_t ev;
    switch (st) {
    case IEEE802154_RADIO_CONFIRM_TX_DONE:
        ev = IEEE802154_MAC_EV_RADIO_TX_DONE;
        break;
    case IEEE802154_RADIO_INDICATION_RX_DONE:
        ev = IEEE802154_MAC_EV_RADIO_RX_DONE;
        break;
    case IEEE802154_RADIO_INDICATION_CRC_ERROR:
        ev = IEEE802154_MAC_EV_RADIO_CRC_ERR;
        break;
    default:
        return;
    }

    ieee802154_mac_post_event(mac, ev);
}

void ieee802154_mac_radio_attach(ieee802154_mac_t *mac)
{
    mac->submac.dev.cb     = _radio_cb;
}

/* ACK timer callback */
static void _ack_timer_cb(void *arg){
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;
    ieee802154_mac_post_event(mac, IEEE802154_MAC_EV_ACK_TIMEOUT);
}

/* ===== Required SubMAC extern hooks ===== */
void ieee802154_submac_bh_request(ieee802154_submac_t *submac){
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);
    ieee802154_mac_post_event(mac, IEEE802154_MAC_EV_SUBMAC_BH);
}

void ieee802154_submac_ack_timer_set(ieee802154_submac_t *submac)
{
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);
    mac->ack_timer.callback = _ack_timer_cb;
    mac->ack_timer.arg = mac;

    ztimer_set(ZTIMER_USEC, &mac->ack_timer, (uint32_t)submac->ack_timeout_us);
}


void ieee802154_submac_ack_timer_cancel(ieee802154_submac_t *submac){
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);
    ztimer_remove(ZTIMER_USEC, &mac->ack_timer);
}

/* ===== SubMAC callbacks ===== */
static void _submac_rx_done(ieee802154_submac_t *submac){
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);
    int len = ieee802154_get_frame_length(submac);
    if (len <= 0 || len > (int)sizeof(mac->rx_buf)) {
        (void)ieee802154_read_frame(submac, NULL, 0, NULL);
        return;
    }

    ieee802154_rx_info_t info;
    int r = ieee802154_read_frame(submac, mac->rx_buf, sizeof(mac->rx_buf), &info);
    if (r > 0 && mac->cbs.data_indication) {
        mac->cbs.data_indication(mac->cbs.arg, mac->rx_buf, (size_t)r, &info);
    }
}

static void _submac_tx_done(ieee802154_submac_t *submac, int status, ieee802154_tx_info_t *info){
    (void)info;
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);

    int res;
    switch (status) {
    case TX_STATUS_SUCCESS:
    case TX_STATUS_FRAME_PENDING:
        res = 0;
        break;
    case TX_STATUS_NO_ACK:
        res = -ETIMEDOUT;
        break;
    case TX_STATUS_MEDIUM_BUSY:
        res = -EBUSY;
        break;
    default:
        res = -EIO;
        break;
    }

    ieee802154_mac_tx_finish_current(mac, res);

    /* start next if queued */
    ieee802154_mac_post_event(mac, IEEE802154_MAC_EV_TX);
}

static const ieee802154_submac_cb_t _submac_cbs = {
    .rx_done = _submac_rx_done,
    .tx_done = _submac_tx_done,
};

void ieee802154_mac_submac_attach(ieee802154_mac_t *mac){
    mac->submac.cb = &_submac_cbs;
}

void ieee802154_mac_tx_finish_current(ieee802154_mac_t *mac, int status)
{
    if (ieee802154_mac_tx_empty(mac)) {
        mac->tx_ring.busy = false;
        return;
    }

    ieee802154_mac_tx_desc_t *d = ieee802154_mac_tx_peek(mac);

    if (mac->cbs.data_confirm) {
        mac->cbs.data_confirm(mac->cbs.arg, d->handle, status);
    }

    d->in_use = false;
    ieee802154_mac_tx_pop(mac);
    mac->tx_ring.busy = false;
}

static void _tx_kick(ieee802154_mac_t *mac)
{
    if (mac->tx_ring.busy || ieee802154_mac_tx_empty(mac)) {
        return;
    }

    ieee802154_mac_tx_desc_t *d = ieee802154_mac_tx_peek(mac);
    if (!d || !d->payload) {
        return;
    }

    d->iol_msdu.iol_base = (void *)d->payload->buf;
    d->iol_msdu.iol_len  = d->payload->len;
    d->iol_msdu.iol_next = NULL;

    d->iol_mhr.iol_base  = d->mhr;
    d->iol_mhr.iol_len   = d->mhr_len;
    d->iol_mhr.iol_next  = &d->iol_msdu;

    int r = ieee802154_send(&mac->submac, &d->iol_mhr);
    if (r == 0) {
        mac->tx_ring.busy = true;
    }
    else {
        ieee802154_mac_tx_finish_current(mac, r);
        _tx_kick(mac);
    }
}

static int _enqueue_tx_req_into_txq(ieee802154_mac_t *mac,
                                   const ieee802154_mac_req_t *r)
{

    if (ieee802154_mac_tx_full(mac)) {
        return -ENOBUFS;
    }

    ieee802154_mac_tx_desc_t *d = ieee802154_mac_tx_reserve(mac);
    if (!d) {
        return -ENOBUFS;
    }

    d->handle = r->handle;

    /* src addr selection */
    const void *src = NULL;
    uint8_t src_len = ieee80214_addr_len_from_mode(r->u.tx.src_mode);
    if (r->u.tx.src_mode == IEEE802154_ADDR_MODE_SHORT) {
        src = &mac->submac.short_addr;
    }
    else if (r->u.tx.src_mode == IEEE802154_ADDR_MODE_EXTENDED) {
        src = &mac->submac.ext_addr;
    }

    le_uint16_t src_pan = byteorder_btols(byteorder_htons(mac->submac.panid));
    le_uint16_t dst_pan = byteorder_btols(byteorder_htons(r->u.tx.dst_panid));

    uint8_t flags = IEEE802154_FCF_TYPE_DATA;
    if (r->u.tx.ack_req) {
        flags |= IEEE802154_FCF_ACK_REQ;
    }

    ieee802154_pib_value_t dsn;
    int res = ieee802154_mac_mlme_get(mac, IEEE802154_PIB_DSN, &dsn);
    if (res < 0) {
        d->in_use = false;
        return res;
    }

    size_t mhr_len = ieee802154_set_frame_hdr(d->mhr,
                                           src, src_len,
                                           r->u.tx.dst_len ? r->u.tx.dst_addr : NULL, r->u.tx.dst_len,
                                           src_pan, dst_pan,
                                           flags,
                                           dsn.v.u8);
    if (mhr_len == 0 || mhr_len > (int)sizeof(d->mhr)) {
        d->in_use = false;
        return -EINVAL;
    }
    d->mhr_len = mhr_len;

    /* DSN++ */
    ieee802154_pib_value_t dsn_new = {
        .type = IEEE802154_PIB_TYPE_U8,
        .v.u8 = dsn.v.u8 + 1,
    };
    (void)ieee802154_mac_mlme_set(mac, IEEE802154_PIB_DSN, &dsn_new);

    d->payload = r->u.tx.pl;

    ieee802154_mac_tx_commit(mac);
    return 0;
}

static int _mac_mlme_start(ieee802154_mac_t *mac, uint16_t channel){
    int res = ieee802154_set_channel_number(&mac->submac, channel);
    ieee802154_pib_value_t value;
    ieee802154_mac_mlme_get(mac, IEEE802154_PIB_PAN_ID, &value);
    res |=  ieee802154_set_panid(&mac->submac, &value.v.u16 );
    return res;
}

static void _drain_requests(ieee802154_mac_t *mac)
{
    ieee802154_mac_req_t r;
    bool kick = false;

    while (ieee80214_mac_req_ring_pop(mac, &r)) {
        switch (r.type) {
        case IEEE802154_MAC_REQ_TX: {
            int st = _enqueue_tx_req_into_txq(mac, &r);
            if (st < 0) {
                ieee802154_mac_payload_free(mac, r.u.tx.pl);
                if (mac->cbs.data_confirm) {
                    mac->cbs.data_confirm(mac->cbs.arg, r.handle, st);
                }
            }
            else {
                kick = true;
            }
            break;
        }

        case IEEE802154_MAC_REQ_MLME_SET: {
            int st = ieee802154_mac_mlme_set(mac, r.u.set.attr, &r.u.set.value);
            if (mac->cbs.mlme_set_confirm) {
                mac->cbs.mlme_set_confirm(mac->cbs.arg, r.handle, st, r.u.set.attr);
            }
            break;
        }

        case IEEE802154_MAC_REQ_MLME_GET: {
            ieee802154_pib_value_t v;
            int st = ieee802154_mac_mlme_get(mac, r.u.get.attr, &v);
            if (mac->cbs.mlme_get_confirm) {
                mac->cbs.mlme_get_confirm(mac->cbs.arg, r.handle, st, r.u.get.attr, v);
            }
            break;
        }

        case IEEE802154_MAC_REQ_MLME_START: {
            int st = _mac_mlme_start(mac, r.u.start.channel);
            if (mac->cbs.mlme_start_confirm) {
                mac->cbs.mlme_start_confirm(mac->cbs.arg, r.handle, st);
            }
            break;
        }
        }
    }

    if (kick) {
        ieee802154_mac_post_event(mac, IEEE802154_MAC_EV_TX);
    }
}

static void _process_event(ieee802154_mac_t *mac, uint8_t ev)
{
    switch ((ieee802154_mac_ev_t)ev) {
    case IEEE802154_MAC_EV_REQ:
        DEBUG("IEEE802154 MAC: IEEE802154_MAC_EV_REQ\n");
        _drain_requests(mac);
        break;
    case IEEE802154_MAC_EV_RADIO_TX_DONE:
        DEBUG("IEEE802154 MAC: processing event IEEE802154_MAC_EV_RADIO_TX_DONE\n");
        ieee802154_submac_tx_done_cb(&mac->submac);
        break;
    case IEEE802154_MAC_EV_RADIO_RX_DONE:
        DEBUG("IEEE802154 MAC: processing event IEEE802154_MAC_EV_RADIO_RX_DONE\n");
        ieee802154_submac_rx_done_cb(&mac->submac);
        break;

    case IEEE802154_MAC_EV_RADIO_CRC_ERR:
        DEBUG("IEEE802154 MAC: processing event IEEE802154_MAC_EV_RADIO_CRC_ERR\n");
        ieee802154_submac_crc_error_cb(&mac->submac);
        break;

    case IEEE802154_MAC_EV_SUBMAC_BH:
        DEBUG("IEEE802154 MAC: processing event IEEE802154_MAC_EV_SUBMAC_BH\n");
        ieee802154_submac_bh_process(&mac->submac);
        break;

    case IEEE802154_MAC_EV_ACK_TIMEOUT:
        DEBUG("IEEE802154 MAC: processing event IEEE802154_MAC_EV_ACK_TIMEOUT\n");
        /* Must be thread context (submac.h note) */
        ieee802154_submac_ack_timeout_fired(&mac->submac);
        break;

    case IEEE802154_MAC_EV_TX:
        DEBUG("IEEE802154 MAC: processing event IEEE802154_MAC_EV_TX_KICK\n");
        _tx_kick(mac);
        break;

    default:
        break;
    }
}

void *ieee802154_mac_thread(void *arg)
{
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;

    /* init handshake */
    msg_t m;
    msg_receive(&m);

    if (m.type == IEEE802154_MAC_EV_INIT) {
        DEBUG("IEEE802154 MAC: processing event IEEE802154_MAC_EV_INIT\n");
        ieee802154_pib_value_t short_addr_value;
        ieee802154_pib_value_t ext_addr_value;
        int res = ieee802154_mac_mlme_get(mac, IEEE802154_PIB_SHORT_ADDR, &short_addr_value);
        if (res != 0){
            DEBUG("IEEE802154 MAC: ERROR getting short address\n");
        }
        res = ieee802154_mac_mlme_get(mac, IEEE802154_PIB_EXTENDED_ADDRESS, &ext_addr_value);
        if (res != 0){
            DEBUG("IEEE802154 MAC: ERROR err getting extended address\n");
        }
        ieee802154_submac_init(&mac->submac, &short_addr_value.v.short_addr, &ext_addr_value.v.ext_addr);
        msg_t reply = { .type = IEEE802154_MAC_EV_INIT };
        reply.content.value = (uint32_t)res;
        msg_reply(&m, &reply);
    }
    else {
        msg_t reply = { .type = IEEE802154_MAC_EV_INIT };
        reply.content.value = (uint32_t)(-EINVAL);
        msg_reply(&m, &reply);
    }

    /* main loop */
    while (1) {
        uint8_t ev;

        /* block if nothing to do */
        int n = isrpipe_read(&mac->evpipe, &ev, 1);
        if (n == 1) {
            _process_event(mac, ev);
        }
        /* read remaining elements in queue */
        while (isrpipe_read_timeout(&mac->evpipe, &ev, 1, 0) == 1) {
            _process_event(mac, ev);
        }
    }

    return NULL;
}
