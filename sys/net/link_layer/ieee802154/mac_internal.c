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
#include "mutex.h"

#include "mac_internal_priv.h"
#include "net/ieee802154/submac.h"
#include "mac_pib.h"

#define ENABLE_DEBUG 0
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

static void _hal_init_dev(ieee802154_mac_t *mac, ieee802154_dev_type_t dev_type);
static void _ack_timer_cb(void *arg);
static void _submac_rx_done(ieee802154_submac_t *submac);
static void _submac_tx_done(ieee802154_submac_t *submac, int status, ieee802154_tx_info_t *info);
static void _init_tx_q(ieee802154_mac_t *mac);

void ieee802154_init_mac_internal(ieee802154_mac_t *mac);

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
                break;     /* init one */
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
                break;     /* init one */
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

/* ACK timer callback */
static void _ack_timer_cb(void *arg)
{
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;

    mac->cbs.ack_timeout(mac);
}

/* ===== SubMAC callbacks ===== */
static void _submac_rx_done(ieee802154_submac_t *submac)
{
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);

    int len = ieee802154_get_frame_length(submac);
    if (len <= 0) {
        return;
    }
    mac->cbs.allocate_request(mac, (size_t)len);
}

static void _submac_tx_done(ieee802154_submac_t *submac, int status, ieee802154_tx_info_t *info)
{
    (void)info;
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);
    ieee802154_mac_tx_finish_current(mac, status);
}

static const ieee802154_submac_cb_t _submac_cbs = {
    .rx_done = _submac_rx_done,
    .tx_done = _submac_tx_done,
};

static void _init_tx_q(ieee802154_mac_t *mac)
{
    /* 1 means free with this the count of 1 is == IEEE802154_MAC_TX_INDIRECTQ_SIZE */
    mac->indirect_q.free_mask = (1U << IEEE802154_MAC_TX_INDIRECTQ_SIZE) - 1;
    mutex_init(&mac->indirect_q.lock);
    memset(&mac->indirect_q.q, 0, sizeof(mac->indirect_q.q));
}

void ieee802154_init_mac_internal(ieee802154_mac_t *mac)
{
    DEBUG("IEEE802154 MAC: init\n");
    memset(mac->cmd_buf, 0, IEEE802154_FRAME_LEN_MAX);
    mac->cmd.iol_base = mac->cmd_buf;
    mac->cmd.iol_len = IEEE802154_FRAME_LEN_MAX;
    mac->cmd.iol_next = NULL;
    mac->state = IEEE802154_MAC_STATE_IDLE;
    mac->state_history = IEEE802154_MAC_STATE_IDLE;
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
    DEBUG("IEEE802154 MAC: init submac\n");
    ieee802154_submac_init(&mac->submac, &short_addr_value.v.short_addr,
                           &ext_addr_value.v.ext_addr);
    mac->submac.cb = &_submac_cbs;
    mac->submac.dev.cb = mac->cbs.radio_cb_request;
    mac->poll_rx_active = false;
    mac->poll_rx_deadline = 0;
    mac->scan_idx = 0;
    mac->scan_timer_pending = false;
    mac->assoc_pending = false;
    mac->assoc_deadline_tick = 0;
    mac->tick.callback = mac->cbs.tick_request;
    mac->tick.arg = mac;
    mac->ack_timer.callback = _ack_timer_cb;
    mac->ack_timer.arg = mac;
    mac->scan_timer.callback = mac->cbs.scan_timer_request;
    mac->scan_timer.arg = mac;
    ztimer_set(ZTIMER_MSEC, &mac->tick, (uint32_t)IEEE802154_MAC_TICK_INTERVAL_MS);
    mutex_unlock(&mac->submac_lock);
}

/** @} */
