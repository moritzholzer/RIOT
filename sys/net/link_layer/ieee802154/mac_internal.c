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
#include "ztimer.h"

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

void ieee802154_mac_tx(ieee802154_mac_t *mac, const ieee802154_ext_addr_t *dst_addr)
{
    int slot = ieee802154_mac_indirectq_search_slot(&mac->indirect_q, dst_addr);
    printf("slot sending: %d \n", slot);
    if (slot < 0) {
        if (mac->is_coordinator)
        {
            mac->cbs.rx_request(mac);
        }
        return;
    }
    ieee802154_mac_txq_t *txq = &mac->indirect_q.q[slot];
    if (ieee802154_mac_tx_empty(txq) || mac->indirect_q.busy) {
        ieee802154_mac_handle_indirectq_auto_free(mac, &mac->indirect_q, slot);
        return;
    }

    ieee802154_mac_tx_desc_t *d = ieee802154_mac_tx_peek(txq);
    mac->indirect_q.current_slot = slot;
    mac->indirect_q.current_txq = txq;
    int r = ieee802154_send(&mac->submac, &d->iol_mhr);
    if (r == 0)
    {
        mac->indirect_q.busy = true;
    }
    else {
        ieee802154_mac_tx_finish_current(mac, r);
    }
}

static void _process_event(ieee802154_mac_t *mac, uint8_t ev)
{
    switch ((ieee802154_mac_ev_t)ev) {
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

    default:
        break;
    }
}

void ieee802154_mac_handle_radio(ieee802154_dev_t *dev, ieee802154_trx_ev_t st)
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

    _process_event(mac, ev);
}

/* ACK timer callback */
static void _ack_timer_cb(void *arg){
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;
    mac->cbs.ack_timeout(mac);
}

void ieee802154_mac_ack_timeout_fired(ieee802154_mac_t *mac){
    ieee802154_submac_ack_timeout_fired(&mac->submac);
}

void ieee802154_mac_bh_process(ieee802154_mac_t *mac){
    ieee802154_submac_bh_process(&mac->submac);
}

/* ===== Required SubMAC extern hooks ===== */
void ieee802154_submac_bh_request(ieee802154_submac_t *submac){
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);
    puts("bh request\n");
    mac->cbs.bh_request(mac);
}

void ieee802154_submac_ack_timer_set(ieee802154_submac_t *submac)
{
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);
    puts("ACK TIMEOUT SET\n");
    ztimer_set(ZTIMER_USEC, &mac->ack_timer, (uint32_t)submac->ack_timeout_us);
}


void ieee802154_submac_ack_timer_cancel(ieee802154_submac_t *submac){
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);
    ztimer_remove(ZTIMER_USEC, &mac->ack_timer);
}

/* ===== SubMAC callbacks ===== */
static void _submac_rx_done(ieee802154_submac_t *submac){
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);
    mac->cbs.allocate_request(mac);
    }

void ieee802154_mac_send_process(ieee802154_mac_t *mac, iolist_t *buf)
{
    puts("here\n");
    eui64_t src_addr;
    uint8_t src[IEEE802154_LONG_ADDRESS_LEN];//, dst[IEEE802154_LONG_ADDRESS_LEN];
    uint8_t cmd_type, frame_type;
    size_t mhr_len, src_len;
    le_uint16_t src_pan;
    int len = ieee802154_get_frame_length(&mac->submac);
    if (len <= 0) {
        (void)ieee802154_read_frame(&mac->submac, NULL, 0, NULL);
        return;
    }
    // TODO: switch back to rx? or let upper layer do it??
    ieee802154_rx_info_t info;
    buf->iol_len = len;
    (void)ieee802154_read_frame(&mac->submac, buf->iol_base, buf->iol_len, &info);
    mhr_len = ieee802154_get_frame_hdr_len(buf->iol_base);
    frame_type =((const uint8_t *)buf->iol_base)[0] & IEEE802154_FCF_TYPE_MASK;
    //dst_len = ieee802154_get_dst(buf->iol_base, dst, &dst_pan);
    src_len = ieee802154_get_src(buf->iol_base, src, &src_pan);
    memcpy(&src_addr, src, src_len);
    printf("frame type: %d\n", frame_type);
    switch(frame_type)
    {
    case IEEE802154_FCF_TYPE_DATA:
        if (mac->cbs.data_indication) {
            mac->cbs.data_indication(mac->cbs.mac, buf, &info);
        }
        break;
    case IEEE802154_FCF_TYPE_MACCMD:
        cmd_type = ((const uint8_t *)buf->iol_base)[mhr_len];
        if (cmd_type == IEEE802154_CMD_DATA_REQ)
        {
            puts("data request \n");
            ieee802154_mac_tx(mac, &src_addr);
        }
        break;
    default:
        return;
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
}

static const ieee802154_submac_cb_t _submac_cbs = {
    .rx_done = _submac_rx_done,
    .tx_done = _submac_tx_done,
};

static void _tx_finish(ieee802154_mac_t *mac, ieee802154_mac_indirect_q_t *indirect_q, int slot, int status)
{
    if (ieee802154_mac_tx_empty(&indirect_q->q[slot])) {
        mac->indirect_q.busy= false;
        return;
    }

    ieee802154_mac_tx_desc_t *d = ieee802154_mac_tx_peek(&indirect_q->q[slot]);
    if (mac->cbs.data_confirm) {
       mac->cbs.data_confirm(mac->cbs.mac, d->handle, status);
    }
    if (mac->is_coordinator ||  ((status == 0) && (d->handle == 0xFF)))
    {
        puts("rx_request\n");
        mac->cbs.rx_request(mac);
    }
    d->in_use = false;
    ieee802154_mac_tx_pop(&indirect_q->q[slot]);
    ieee802154_mac_handle_indirectq_auto_free(mac, indirect_q, slot);
    mac->indirect_q.busy = false;
}

void ieee802154_mac_tick(ieee802154_mac_t *mac){
    mac->indirect_q.tick++;
    puts("tick\n");
    for (unsigned i = 0; i< IEEE802154_MAC_TX_INDIRECTQ_SIZE; i++)
    {
        if (ieee802154_mac_frame_is_expired(mac->indirect_q.tick, *mac->indirect_q.q[i].deadline_tick))
        {
            _tx_finish(mac, &mac->indirect_q, i, -ETIMEDOUT);
        }
    }
    ztimer_set(ZTIMER_USEC, &mac->tick, (uint32_t)IEEE802154_MAC_TICK_INTERVAL_US);
}

void ieee802154_mac_tx_finish_current(ieee802154_mac_t *mac, int status)
{
    _tx_finish(mac, &mac->indirect_q, mac->indirect_q.current_slot, status);
}

void _init_tx_q(ieee802154_mac_t *mac){
    /* 1 means free with this the count of 1 is == IEEE802154_MAC_TX_INDIRECTQ_SIZE */
    mac->indirect_q.free_mask = (1U << IEEE802154_MAC_TX_INDIRECTQ_SIZE)-1;
    mutex_init(&mac->indirect_q.lock);
    memset(&mac->indirect_q.q, 0, sizeof(ieee802154_mac_tx_desc_t) * IEEE802154_MAC_TX_INDIRECTQ_SIZE);
}

void ieee802154_init_mac_internal(ieee802154_mac_t *mac)
{
    memset(mac->cmd_buf, 0, IEEE802154_FRAME_LEN_MAX);
    mac->cmd.iol_base = mac->cmd_buf;
    mac->cmd.iol_len = IEEE802154_FRAME_LEN_MAX;
    mac->cmd.iol_next = NULL;
    _hal_init_dev(mac, IEEE802154_DEV_TYPE_KW2XRF);
    ieee802154_pib_value_t short_addr_value;
    ieee802154_pib_value_t ext_addr_value;
    ieee802154_mac_mlme_get(mac, IEEE802154_PIB_SHORT_ADDR, &short_addr_value);
    ieee802154_mac_mlme_get(mac, IEEE802154_PIB_EXTENDED_ADDRESS, &ext_addr_value);
    uint16_t sym_us;
    ieee802154_phy_mode_t phy_mode = ieee802154_get_phy_mode(&mac->submac);
    switch (phy_mode) {
    case IEEE802154_PHY_OQPSK:
        sym_us = IEEE802154_SYMBOL_TIME_US;
        break;
    case IEEE802154_PHY_MR_FSK:
        sym_us = IEEE802154_MR_FSK_SYMBOL_TIME_US;
        break;
    case IEEE802154_PHY_MR_OFDM:
        sym_us = IEEE802154_MR_OFDM_SYMBOL_TIME_US;
        break;
    default:
        /* TODO: check for correct symbol times */
        // MR-OQPSK / ASK / BPSK etc
        sym_us = IEEE802154_SYMBOL_TIME_US; /* fallback rn */
        break;
    }
    mac->sym_us = sym_us;

    _init_tx_q(mac);
    mutex_init(&mac->submac_lock);
    mutex_lock(&mac->submac_lock);
    ieee802154_submac_init(&mac->submac, &short_addr_value.v.short_addr, &ext_addr_value.v.ext_addr);
    mac->submac.cb = &_submac_cbs;
    mac->submac.dev.cb = mac->cbs.radio_cb_request;
    mac->tick.callback = mac->cbs.tick_request;
    mac->tick.arg = mac;
    mac->ack_timer.callback = _ack_timer_cb;
    mac->ack_timer.arg = mac;
    mutex_unlock(&mac->submac_lock);
}
