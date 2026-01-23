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

typedef struct {
    iolist_t *buf;
    const ieee802154_rx_info_t *info;
    eui64_t src_addr;
    uint8_t src[IEEE802154_LONG_ADDRESS_LEN];
    le_uint16_t src_pan;
    int src_len;
    uint8_t frame_type;
    uint8_t cmd_type;
    const ieee802154_ext_addr_t *dst_addr;
    const void *data_dst_addr;
    iolist_t *msdu;
    uint8_t msdu_handle;
    ieee802154_addr_mode_t src_mode;
    ieee802154_addr_mode_t dst_mode;
    uint16_t dst_panid;
    bool ack_req;
    bool indirect;
    int *result;
} ieee802154_mac_fsm_ctx_t;

static int _mac_tx_request(ieee802154_mac_t *mac, const ieee802154_ext_addr_t *dst_addr);
static int _mac_data_request(ieee802154_mac_t *mac, const ieee802154_mac_fsm_ctx_t *ctx);

static uint8_t ieee80214_addr_len_from_mode(ieee802154_addr_mode_t mode)
{
    switch (mode) {
    case IEEE802154_ADDR_MODE_NONE:
        return 0;
    case IEEE802154_ADDR_MODE_SHORT:
        return IEEE802154_SHORT_ADDRESS_LEN;
    case IEEE802154_ADDR_MODE_EXTENDED:
        return IEEE802154_LONG_ADDRESS_LEN;
    default:
        return 0;
    }
}

static int _mac_data_request(ieee802154_mac_t *mac, const ieee802154_mac_fsm_ctx_t *ctx)
{
    if (!ctx || !ctx->result || !ctx->data_dst_addr) {
        return -EINVAL;
    }

    int res = ieee802154_mac_map_push(mac, IEEE802154_FCF_TYPE_DATA,
                                      ctx->src_mode, ctx->dst_mode,
                                      &ctx->dst_panid, ctx->data_dst_addr,
                                      ctx->msdu, &ctx->msdu_handle,
                                      ctx->ack_req, ctx->indirect);
    if (res < 0) {
        *ctx->result = res;
        return res;
    }
    if (!ctx->indirect) {
        res = _mac_tx_request(mac, ctx->data_dst_addr);
        *ctx->result = res;
        return res;
    }
    *ctx->result = 0;
    return 0;
}

static const char *const _mac_fsm_ev_str[] = {
    [IEEE802154_MAC_FSM_EV_SCAN_START] = "SCAN_START",
    [IEEE802154_MAC_FSM_EV_SCAN_DONE] = "SCAN_DONE",
    [IEEE802154_MAC_FSM_EV_ASSOC_REQ_RX] = "ASSOC_REQ_RX",
    [IEEE802154_MAC_FSM_EV_ASSOC_RES_RX] = "ASSOC_RES_RX",
    [IEEE802154_MAC_FSM_EV_DISASSOC_RX] = "DISASSOC_RX",
    [IEEE802154_MAC_FSM_EV_COORD_START] = "COORD_START",
    [IEEE802154_MAC_FSM_EV_TX_REQUEST] = "TX_REQUEST",
    [IEEE802154_MAC_FSM_EV_SLEEP] = "SLEEP",
    [IEEE802154_MAC_FSM_EV_WAKE] = "WAKE",
    [IEEE802154_MAC_FSM_EV_RX_BEACON] = "RX_BEACON",
    [IEEE802154_MAC_FSM_EV_RX_DATA] = "RX_DATA",
    [IEEE802154_MAC_FSM_EV_RX_CMD_DATA_REQ] = "RX_CMD_DATA_REQ",
    [IEEE802154_MAC_FSM_EV_RX_CMD_BEACON_REQ] = "RX_CMD_BEACON_REQ",
    [IEEE802154_MAC_FSM_EV_RX_CMD_ASSOC_REQ] = "RX_CMD_ASSOC_REQ",
    [IEEE802154_MAC_FSM_EV_RX_CMD_ASSOC_RES] = "RX_CMD_ASSOC_RES",
    [IEEE802154_MAC_FSM_EV_RX_CMD_DISASSOC] = "RX_CMD_DISASSOC",
    [IEEE802154_MAC_FSM_EV_MCPS_DATA_REQ] = "MCPS_DATA_REQ",
};

static const char *const _mac_fsm_state_str[] = {
    [IEEE802154_MAC_STATE_IDLE] = "IDLE",
    [IEEE802154_MAC_STATE_SCAN_ACTIVE] = "SCAN_ACTIVE",
    [IEEE802154_MAC_STATE_ASSOCIATING] = "ASSOCIATING",
    [IEEE802154_MAC_STATE_COORDINATOR] = "COORDINATOR",
    [IEEE802154_MAC_STATE_DEVICE] = "DEVICE",
    [IEEE802154_MAC_STATE_SLEEP] = "SLEEP",
    [IEEE802154_MAC_STATE_INVALID] = "INVALID",
};

static void _process_event(ieee802154_mac_t *mac, uint8_t ev);
static int _mac_fsm_process_ev(ieee802154_mac_t *mac, ieee802154_mac_fsm_ev_t ev,
                               const ieee802154_mac_fsm_ctx_t *ctx);
static int _mac_enqueue_beacon(ieee802154_mac_t *mac);

static ieee802154_mac_state_t _mac_fsm_state_idle(ieee802154_mac_t *mac,
                                                  ieee802154_mac_fsm_ev_t ev,
                                                  const ieee802154_mac_fsm_ctx_t *ctx)
{
    switch (ev) {
    case IEEE802154_MAC_FSM_EV_SCAN_START:
        if (mac->scan_req == NULL)
        {
            return IEEE802154_MAC_STATE_INVALID;
        }
        mac->state_before_scan = mac->state;
        mac->scan_idx = 0;
        return IEEE802154_MAC_STATE_SCAN_ACTIVE;
    case IEEE802154_MAC_FSM_EV_COORD_START:
    case IEEE802154_MAC_FSM_EV_ASSOC_REQ_RX:
    case IEEE802154_MAC_FSM_EV_RX_CMD_ASSOC_REQ:
        return IEEE802154_MAC_STATE_COORDINATOR;
    case IEEE802154_MAC_FSM_EV_ASSOC_RES_RX:
    case IEEE802154_MAC_FSM_EV_RX_CMD_ASSOC_RES:
        return IEEE802154_MAC_STATE_DEVICE;
    case IEEE802154_MAC_FSM_EV_TX_REQUEST:
        if (ctx && ctx->dst_addr && ctx->result) {
            *ctx->result = _mac_tx_request(mac, ctx->dst_addr);
        }
        return IEEE802154_MAC_STATE_IDLE;
    case IEEE802154_MAC_FSM_EV_SLEEP:
        return IEEE802154_MAC_STATE_SLEEP;
    case IEEE802154_MAC_FSM_EV_RX_DATA:
        if (ctx && mac->cbs.data_indication) {
            mac->cbs.data_indication(mac->cbs.mac, ctx->buf, ctx->info);
        }
        return IEEE802154_MAC_STATE_IDLE;
    case IEEE802154_MAC_FSM_EV_RX_CMD_DATA_REQ:
        if (ctx && (_mac_tx_request(mac, &ctx->src_addr) > 0)) {
            mac->cbs.dealloc_request(mac, ctx->buf);
        }
        return IEEE802154_MAC_STATE_IDLE;
    case IEEE802154_MAC_FSM_EV_RX_CMD_BEACON_REQ:
        if (ctx) {
            _mac_enqueue_beacon(mac);
            (void)_mac_tx_request(mac, &ctx->src_addr);
        }
        return IEEE802154_MAC_STATE_IDLE;
    case IEEE802154_MAC_FSM_EV_MCPS_DATA_REQ:
        if (ctx) {
            (void)_mac_data_request(mac, ctx);
        }
        return IEEE802154_MAC_STATE_IDLE;
    default:
        return IEEE802154_MAC_STATE_INVALID;
    }
}

static ieee802154_mac_state_t _mac_fsm_state_scan_active(ieee802154_mac_t *mac,
                                                         ieee802154_mac_fsm_ev_t ev,
                                                         const ieee802154_mac_fsm_ctx_t *ctx)
{
    uint8_t idx;
    int res;
    ieee802154_ext_addr_t dst_addr = {.uint8 = IEEE802154_ADDR_BCAST};

    switch (ev) {
    case IEEE802154_MAC_FSM_EV_SCAN_DONE:
    {
        ieee802154_mlme_scan_req_t *req = mac->scan_req;
        ieee802154_radio_set_frame_filter_mode(&mac->submac.dev, IEEE802154_FILTER_ACCEPT);
        mac->scan_active = false;
        mac->scan_timer_pending = false;
        mac->scan_req = NULL;
        mac->scan_idx = 0;
        if (req != NULL) {
            mac->cbs.mlme_scan_confirm(mac, 0, req);
        }
        return mac->state_before_scan;
    }
    case IEEE802154_MAC_FSM_EV_SCAN_TIMER:
        idx = mac->scan_idx;
        if (idx >= mac->scan_req->channel_count) {
            return _mac_fsm_process_ev(mac, IEEE802154_MAC_FSM_EV_SCAN_DONE, NULL);
        }
        res = ieee802154_set_channel_number(&mac->submac, mac->scan_req->channels[idx]);
        res |= ieee802154_mac_enqueue_beacon_request(mac);
        if (res < 0)
        {
            DEBUG("IEEE802154 MAC: failed to scan channel %u\n", mac->scan_req->channels[idx]);
        }
        res = _mac_tx_request(mac, &dst_addr);
        if (res > 0)
        {
            DEBUG("IEEE802154 MAC: failed to send beacon request none enqueud\n");
        } else if ( res < 0)
        {
            DEBUG("IEEE802154 MAC: failed to send beacon request %u\n", res);
        }
        mac->scan_idx++;
        mac->scan_timer_pending = true;
        return IEEE802154_MAC_STATE_SCAN_ACTIVE;
    case IEEE802154_MAC_FSM_EV_RX_BEACON:
        if (ctx && mac->scan_active && (mac->scan_req != NULL) &&
            (mac->scan_req->results != NULL) &&
            (mac->scan_req->results_used != NULL) &&
            (mac->scan_req->results_len > 0)) {
            size_t idx_res = *mac->scan_req->results_used;
            if (idx_res < mac->scan_req->results_len) {
                ieee802154_scan_result_t *scan_res = &mac->scan_req->results[idx_res];
                scan_res->channel = mac->submac.channel_num;
                scan_res->pan_id = ctx->src_pan.u16;
                scan_res->lqi = ctx->info->lqi;
                scan_res->rssi = ctx->info->rssi;
                if (ctx->src_len == IEEE802154_SHORT_ADDRESS_LEN) {
                    scan_res->coord_addr.type = IEEE802154_ADDR_MODE_SHORT;
                    memcpy(&scan_res->coord_addr.v.short_addr, ctx->src,
                           IEEE802154_SHORT_ADDRESS_LEN);
                }
                else if (ctx->src_len == IEEE802154_LONG_ADDRESS_LEN) {
                    scan_res->coord_addr.type = IEEE802154_ADDR_MODE_EXTENDED;
                    memcpy(&scan_res->coord_addr.v.ext_addr, ctx->src,
                           IEEE802154_LONG_ADDRESS_LEN);
                }
                else {
                    scan_res->coord_addr.type = IEEE802154_ADDR_MODE_NONE;
                }
                (*mac->scan_req->results_used)++;
            }
        }
        return IEEE802154_MAC_STATE_SCAN_ACTIVE;
    case IEEE802154_MAC_FSM_EV_RX_DATA:
        if (ctx && mac->cbs.data_indication) {
            mac->cbs.data_indication(mac->cbs.mac, ctx->buf, ctx->info);
        }
        return IEEE802154_MAC_STATE_SCAN_ACTIVE;
    case IEEE802154_MAC_FSM_EV_RX_CMD_DATA_REQ:
        if (ctx && (_mac_tx_request(mac, &ctx->src_addr) > 0)) {
            mac->cbs.dealloc_request(mac, ctx->buf);
        }
        return IEEE802154_MAC_STATE_SCAN_ACTIVE;
    case IEEE802154_MAC_FSM_EV_RX_CMD_BEACON_REQ:
    case IEEE802154_MAC_FSM_EV_TX_REQUEST:
    case IEEE802154_MAC_FSM_EV_MCPS_DATA_REQ:
        return IEEE802154_MAC_STATE_SCAN_ACTIVE;
    case IEEE802154_MAC_FSM_EV_SLEEP:
        return IEEE802154_MAC_STATE_INVALID;
    default:
        return IEEE802154_MAC_STATE_INVALID;
    }
}

static ieee802154_mac_state_t _mac_fsm_state_coordinator(ieee802154_mac_t *mac,
                                                         ieee802154_mac_fsm_ev_t ev,
                                                         const ieee802154_mac_fsm_ctx_t *ctx)
{
    switch (ev) {
    case IEEE802154_MAC_FSM_EV_SCAN_START:
        if (mac->scan_req == NULL) {
            return IEEE802154_MAC_STATE_INVALID;
        }
        mac->state_before_scan = mac->state;
        mac->scan_idx = 0;
        mac->scan_timer_pending = false;
        return IEEE802154_MAC_STATE_SCAN_ACTIVE;
    case IEEE802154_MAC_FSM_EV_DISASSOC_RX:
    case IEEE802154_MAC_FSM_EV_RX_CMD_DISASSOC:
        return IEEE802154_MAC_STATE_COORDINATOR;
    case IEEE802154_MAC_FSM_EV_RX_DATA:
        if (ctx && mac->cbs.data_indication) {
            mac->cbs.data_indication(mac->cbs.mac, ctx->buf, ctx->info);
        }
        return IEEE802154_MAC_STATE_COORDINATOR;
    case IEEE802154_MAC_FSM_EV_RX_CMD_DATA_REQ:
        if (ctx && (_mac_tx_request(mac, &ctx->src_addr) > 0)) {
            mac->cbs.dealloc_request(mac, ctx->buf);
        }
        return IEEE802154_MAC_STATE_COORDINATOR;
    case IEEE802154_MAC_FSM_EV_RX_CMD_BEACON_REQ:
        if (ctx) {
            DEBUG("SENDING BEACON\n");
            _mac_enqueue_beacon(mac);
            const ieee802154_ext_addr_t *dst =
                (ctx->src_len > 0) ? &ctx->src_addr : NULL;
            if (_mac_tx_request(mac, dst) < 0)
            {
                DEBUG("ERROR SENDING BEACON\n");
            }
        }
        return IEEE802154_MAC_STATE_COORDINATOR;
    case IEEE802154_MAC_FSM_EV_TX_REQUEST:
        if (ctx && ctx->dst_addr && ctx->result) {
            *ctx->result = _mac_tx_request(mac, ctx->dst_addr);
        }
        return IEEE802154_MAC_STATE_COORDINATOR;
    case IEEE802154_MAC_FSM_EV_MCPS_DATA_REQ:
        if (ctx) {
            (void)_mac_data_request(mac, ctx);
        }
        return IEEE802154_MAC_STATE_COORDINATOR;
    case IEEE802154_MAC_FSM_EV_SLEEP:
        return IEEE802154_MAC_STATE_SLEEP;
    default:
        return IEEE802154_MAC_STATE_INVALID;
    }
}

static ieee802154_mac_state_t _mac_fsm_state_device(ieee802154_mac_t *mac,
                                                    ieee802154_mac_fsm_ev_t ev,
                                                    const ieee802154_mac_fsm_ctx_t *ctx)
{
    switch (ev) {
    case IEEE802154_MAC_FSM_EV_DISASSOC_RX:
    case IEEE802154_MAC_FSM_EV_RX_CMD_DISASSOC:
        return IEEE802154_MAC_STATE_IDLE;
    case IEEE802154_MAC_FSM_EV_RX_DATA:
        if (ctx && mac->cbs.data_indication) {
            mac->cbs.data_indication(mac->cbs.mac, ctx->buf, ctx->info);
        }
        return IEEE802154_MAC_STATE_DEVICE;
    case IEEE802154_MAC_FSM_EV_RX_CMD_DATA_REQ:
        if (ctx && (_mac_tx_request(mac, &ctx->src_addr) > 0)) {
            mac->cbs.dealloc_request(mac, ctx->buf);
        }
        return IEEE802154_MAC_STATE_DEVICE;
    case IEEE802154_MAC_FSM_EV_RX_CMD_BEACON_REQ:
        if (ctx) {
            _mac_enqueue_beacon(mac);
            (void)_mac_tx_request(mac, &ctx->src_addr);
        }
        return IEEE802154_MAC_STATE_DEVICE;
    case IEEE802154_MAC_FSM_EV_TX_REQUEST:
        if (ctx && ctx->dst_addr && ctx->result) {
            *ctx->result = _mac_tx_request(mac, ctx->dst_addr);
        }
        return IEEE802154_MAC_STATE_DEVICE;
    case IEEE802154_MAC_FSM_EV_MCPS_DATA_REQ:
        if (ctx) {
            (void)_mac_data_request(mac, ctx);
        }
        return IEEE802154_MAC_STATE_DEVICE;
    case IEEE802154_MAC_FSM_EV_SLEEP:
        return IEEE802154_MAC_STATE_SLEEP;
    default:
        return IEEE802154_MAC_STATE_INVALID;
    }
}

static ieee802154_mac_state_t _mac_fsm_state_associating(ieee802154_mac_t *mac,
                                                         ieee802154_mac_fsm_ev_t ev,
                                                         const ieee802154_mac_fsm_ctx_t *ctx)
{
    switch (ev) {
    case IEEE802154_MAC_FSM_EV_ASSOC_RES_RX:
    case IEEE802154_MAC_FSM_EV_RX_CMD_ASSOC_RES:
        return IEEE802154_MAC_STATE_DEVICE;
    case IEEE802154_MAC_FSM_EV_DISASSOC_RX:
    case IEEE802154_MAC_FSM_EV_RX_CMD_DISASSOC:
        return IEEE802154_MAC_STATE_IDLE;
    case IEEE802154_MAC_FSM_EV_RX_DATA:
        if (ctx && mac->cbs.data_indication) {
            mac->cbs.data_indication(mac->cbs.mac, ctx->buf, ctx->info);
        }
        return IEEE802154_MAC_STATE_ASSOCIATING;
    case IEEE802154_MAC_FSM_EV_RX_CMD_DATA_REQ:
        if (ctx && (_mac_tx_request(mac, &ctx->src_addr) > 0)) {
            mac->cbs.dealloc_request(mac, ctx->buf);
        }
        return IEEE802154_MAC_STATE_ASSOCIATING;
    case IEEE802154_MAC_FSM_EV_RX_CMD_BEACON_REQ:
        if (ctx) {
            _mac_enqueue_beacon(mac);
            (void)_mac_tx_request(mac, &ctx->src_addr);
        }
        return IEEE802154_MAC_STATE_ASSOCIATING;
    case IEEE802154_MAC_FSM_EV_TX_REQUEST:
        if (ctx && ctx->dst_addr && ctx->result) {
            *ctx->result = _mac_tx_request(mac, ctx->dst_addr);
        }
        return IEEE802154_MAC_STATE_ASSOCIATING;
    case IEEE802154_MAC_FSM_EV_MCPS_DATA_REQ:
        if (ctx) {
            (void)_mac_data_request(mac, ctx);
        }
        return IEEE802154_MAC_STATE_ASSOCIATING;
    default:
        return IEEE802154_MAC_STATE_INVALID;
    }
}

static ieee802154_mac_state_t _mac_fsm_state_sleep(ieee802154_mac_t *mac,
                                                   ieee802154_mac_fsm_ev_t ev,
                                                   const ieee802154_mac_fsm_ctx_t *ctx)
{
    (void)mac;
    (void) ctx;
    switch (ev) {
    case IEEE802154_MAC_FSM_EV_WAKE:
        return IEEE802154_MAC_STATE_IDLE;
    case IEEE802154_MAC_FSM_EV_RX_DATA:
    case IEEE802154_MAC_FSM_EV_RX_CMD_DATA_REQ:
    case IEEE802154_MAC_FSM_EV_RX_CMD_BEACON_REQ:
        return IEEE802154_MAC_STATE_SLEEP;
    case IEEE802154_MAC_FSM_EV_TX_REQUEST:
        if (ctx && ctx->result) {
            *ctx->result = -EBUSY;
        }
        return IEEE802154_MAC_STATE_SLEEP;
    case IEEE802154_MAC_FSM_EV_MCPS_DATA_REQ:
        if (ctx && ctx->result) {
            *ctx->result = -EBUSY;
        }
        return IEEE802154_MAC_STATE_SLEEP;
    default:
        return IEEE802154_MAC_STATE_INVALID;
    }
}

static int _mac_fsm_process_ev(ieee802154_mac_t *mac, ieee802154_mac_fsm_ev_t ev,
                               const ieee802154_mac_fsm_ctx_t *ctx)
{
    ieee802154_mac_state_t new_state;

    if (ev == IEEE802154_MAC_FSM_EV_RX_CMD_ASSOC_RES) {
        mac->is_coordinator = false;
    }

    switch (mac->state) {
    case IEEE802154_MAC_STATE_IDLE:
        new_state = _mac_fsm_state_idle(mac, ev, ctx);
        break;
    case IEEE802154_MAC_STATE_SCAN_ACTIVE:
        new_state = _mac_fsm_state_scan_active(mac, ev, ctx);
        break;
    case IEEE802154_MAC_STATE_ASSOCIATING:
        new_state = _mac_fsm_state_associating(mac, ev, ctx);
        break;
    case IEEE802154_MAC_STATE_COORDINATOR:
        new_state = _mac_fsm_state_coordinator(mac, ev, ctx);
        break;
    case IEEE802154_MAC_STATE_DEVICE:
        new_state = _mac_fsm_state_device(mac, ev, ctx);
        break;
    case IEEE802154_MAC_STATE_SLEEP:
        new_state = _mac_fsm_state_sleep(mac, ev, ctx);
        break;
    default:
        new_state = IEEE802154_MAC_STATE_INVALID;
        break;
    }

    if (new_state == IEEE802154_MAC_STATE_INVALID) {
        const char *ev_str = (ev < (sizeof(_mac_fsm_ev_str) / sizeof(_mac_fsm_ev_str[0])))
                             ? _mac_fsm_ev_str[ev]
                             : "UNKNOWN";
        const char *st_str = (mac->state < (sizeof(_mac_fsm_state_str) /
                             sizeof(_mac_fsm_state_str[0])))
                             ? _mac_fsm_state_str[mac->state]
                             : "UNKNOWN";
        if (ev_str == NULL) {
            ev_str = "UNKNOWN";
        }
        if (st_str == NULL) {
            st_str = "UNKNOWN";
        }
        DEBUG("IEEE802154 MAC: invalid FSM event %s in state %s\n", ev_str, st_str);
        return -EINVAL;
    }

    if (new_state != mac->state) {
        const char *ev_str = (ev < (sizeof(_mac_fsm_ev_str) / sizeof(_mac_fsm_ev_str[0])))
                             ? _mac_fsm_ev_str[ev]
                             : "UNKNOWN";
        const char *old_str = (mac->state < (sizeof(_mac_fsm_state_str) /
                             sizeof(_mac_fsm_state_str[0])))
                             ? _mac_fsm_state_str[mac->state]
                             : "UNKNOWN";
        const char *new_str = (new_state < (sizeof(_mac_fsm_state_str) /
                             sizeof(_mac_fsm_state_str[0])))
                             ? _mac_fsm_state_str[new_state]
                             : "UNKNOWN";
        if (ev_str == NULL) {
            ev_str = "UNKNOWN";
        }
        if (old_str == NULL) {
            old_str = "UNKNOWN";
        }
        if (new_str == NULL) {
            new_str = "UNKNOWN";
        }
        DEBUG("IEEE802154 MAC: FSM %s -> %s on %s\n", old_str, new_str, ev_str);
        mac->state = new_state;
    }

    if ((ev == IEEE802154_MAC_FSM_EV_SCAN_START) &&
        (mac->state == IEEE802154_MAC_STATE_SCAN_ACTIVE)) {
        int res = ieee802154_radio_set_frame_filter_mode(&mac->submac.dev, IEEE802154_FILTER_PROMISC);
        if (res < 0)
        {
            return res;
        }
        mac->scan_active = true;
        return _mac_fsm_process_ev(mac, IEEE802154_MAC_FSM_EV_SCAN_TIMER, NULL);
    }

    // TODO: implement in radio hal
    if (ev  == IEEE802154_MAC_FSM_EV_COORD_START)
    {
        bool coord = true;
        int res = ieee802154_radio_config_addr_filter(&mac->submac.dev,IEEE802154_AF_PAN_COORD, (void*) &coord);
        if (res == -ENOTSUP)
        {
            DEBUG("IEEE802154 MAC: starting coordinator in SoftMode bc PAN_COORD is not supported in hardware\n");
            res = ieee802154_radio_set_frame_filter_mode(&mac->submac.dev, IEEE802154_FILTER_PROMISC);
            if (res < 0)
            {
                return res;
            }
        }
        mac->is_coordinator = true;
    }

    return 0;
}

int ieee802154_mac_fsm_process_ev(ieee802154_mac_t *mac, ieee802154_mac_fsm_ev_t ev)
{
    int res;

    if (!mac) {
        return -EINVAL;
    }

    mutex_lock(&mac->submac_lock);
    res = _mac_fsm_process_ev(mac, ev, NULL);
    mutex_unlock(&mac->submac_lock);
    return res;
}

bool ieee802154_mac_tx_full(const ieee802154_mac_txq_t *txq)
{
    return txq->cnt >= IEEE802154_MAC_TXQ_LEN;
}

bool ieee802154_mac_tx_empty(const ieee802154_mac_txq_t *txq)
{
    return (txq->cnt == 0);
}

ieee802154_mac_tx_desc_t *ieee802154_mac_tx_reserve(ieee802154_mac_txq_t *txq)
{
    if (!txq || ieee802154_mac_tx_full(txq)) {
        return NULL;
    }

    ieee802154_mac_tx_desc_t *d = &txq->q[txq->tail];
    memset(d, 0, sizeof(*d));
    d->in_use = true;
    return d;
}

void ieee802154_mac_tx_commit(ieee802154_mac_txq_t *txq)
{
    txq->tail = (uint8_t)((txq->tail + 1) % IEEE802154_MAC_TXQ_LEN);
    txq->cnt++;
}

ieee802154_mac_tx_desc_t *ieee802154_mac_tx_peek(ieee802154_mac_txq_t *txq)
{
    if (!txq || ieee802154_mac_tx_empty(txq)) {
        return NULL;
    }

    ieee802154_mac_tx_desc_t *d = &txq->q[txq->head];

    if (!d->in_use) {
        return NULL;
    }

    return d;
}

void ieee802154_mac_tx_pop(ieee802154_mac_txq_t *txq)
{
    if (!txq || ieee802154_mac_tx_empty(txq)) {
        return;
    }

    ieee802154_mac_tx_desc_t *d = &txq->q[txq->head];
    memset(d, 0, sizeof(*d));

    txq->head = (uint8_t)((txq->head + 1) % IEEE802154_MAC_TXQ_LEN);
    txq->cnt--;
}

int ieee802154_indirectq_alloc_slot(ieee802154_mac_indirect_q_t *indirect_q)
{
    if (indirect_q->free_mask == 0) {
        return -1;
    }

    /* first free slot */
    uint8_t slot = __builtin_ctz(indirect_q->free_mask);
    /* 0 means used */
    indirect_q->free_mask &= ~(1U << slot);
    return slot;
}

void ieee802154_indirectq_free_slot(ieee802154_mac_indirect_q_t *indirect_q, uint8_t slot)
{
    memset(&indirect_q->q[slot], 0, sizeof(ieee802154_mac_txq_t));
    indirect_q->free_mask |= (1U << slot);
}

bool ieee802154_indirectq_empty(const ieee802154_mac_indirect_q_t *indirect_q)
{
    /* all slots free */
    return indirect_q->free_mask == ((1U << IEEE802154_MAC_TX_INDIRECTQ_SIZE) - 1U);
}


uint16_t ieee802154_indirect_get_deadline(ieee802154_mac_t *mac)
{
    uint16_t unit_period_us = IEEE802154_MAC_FRAME_TIMEOUT * mac->sym_us;
    /* round up to handle too early timeouts */
    uint16_t unit_period_ticks =
        (unit_period_us + IEEE802154_MAC_TICK_INTERVAL_US - 1U) / IEEE802154_MAC_TICK_INTERVAL_US;
    return (mac->indirect_q.tick + (unit_period_ticks * IEEE802154_MAC_FRAME_TIMEOUT));
}

bool ieee802154_mac_frame_is_expired(uint16_t now_tick, uint16_t deadline_tick)
{
    return (bool)((now_tick - deadline_tick) >= 0);
}

void ieee802154_mac_indirect_fp_update(ieee802154_mac_t *mac,
                                       const ieee802154_ext_addr_t *dst_addr,
                                       bool pending)
{
#ifdef IEEE802154_MAC_INDIRECT_ENABLE
    ieee802154_dev_t *dev = &mac->submac.dev;
#  ifdef IEEE802154_MAC_HAS_SRC_ADDR_MATCH
    ieee802154_radio_config_src_address_match(dev,
                                              pending ? IEEE802154_SRC_MATCH_EXT_ADD
                                                      : IEEE802154_SRC_MATCH_EXT_CLEAR,
                                              dst_addr);
#  else
    (void)dst_addr;
    bool any_pending = pending;
    if (!pending) {
        any_pending = !ieee802154_indirectq_empty(&mac->indirect_q);
    }
    ieee802154_radio_config_src_address_match(dev, IEEE802154_SRC_MATCH_EN, &any_pending);
#  endif
#else
    (void)mac;
    (void)dst_addr;
    (void)pending;
#endif
}

void ieee802154_mac_handle_indirectq_auto_free(ieee802154_mac_t *mac,
                                               ieee802154_mac_indirect_q_t *indirect_q,
                                               uint8_t slot)
{
    ieee802154_mac_txq_t *txq = &indirect_q->q[slot];

    if (ieee802154_mac_tx_empty(txq)) {
        ieee802154_ext_addr_t dst_addr = txq->dst_addr;
        ieee802154_indirectq_free_slot(indirect_q, slot);
        ieee802154_mac_indirect_fp_update(mac, &dst_addr, false);
    }
    else {
        ieee802154_mac_tx_desc_t *d = ieee802154_mac_tx_peek(txq);
        if (d) {
            txq->deadline_tick = &d->deadline_tick;
        }
    }
}

static int _enqueue_data_tx(ieee802154_mac_t *mac,
                            uint8_t frame_type,
                            ieee802154_mac_txq_t *txq,
                            ieee802154_addr_mode_t src_mode,
                            ieee802154_addr_mode_t dst_mode,
                            const uint16_t *dst_panid,
                            const void *dst_addr,
                            iolist_t *msdu,
                            const uint8_t *msdu_handle,
                            bool ack_req,
                            bool indirect)
{
    ieee802154_mac_tx_desc_t *dsc = ieee802154_mac_tx_reserve(txq);
    if (!dsc) {
        return -ENOBUFS;
    }
    dsc->handle = *msdu_handle;
    dsc->type = frame_type;
    dsc->ack = ack_req;
    dsc->indirect = indirect;
    dsc->tx_state = IEEE802154_TX_STATE_QUEUED;
    DEBUG("IEEE802154 MAC: TX state QUEUED (handle=%u)\n", dsc->handle);

    /* src addr selection */
    const void *src = NULL;
    ieee802154_pib_value_t src_v;
    if (src_mode == IEEE802154_ADDR_MODE_SHORT) {
        ieee802154_mac_mlme_get(mac, IEEE802154_PIB_SHORT_ADDR, &src_v);
        src = &src_v.v.short_addr;
    }
    else if (src_mode == IEEE802154_ADDR_MODE_EXTENDED) {
        ieee802154_mac_mlme_get(mac, IEEE802154_PIB_EXTENDED_ADDRESS, &src_v);
        src = &src_v.v.ext_addr;
    }

    uint8_t src_len = ieee80214_addr_len_from_mode(src_mode);
    uint8_t dst_len = ieee80214_addr_len_from_mode(dst_mode);
    ieee802154_pib_value_t src_panid;
    ieee802154_mac_mlme_get(mac, IEEE802154_PIB_PAN_ID, &src_panid);
    le_uint16_t src_pan = byteorder_btols(byteorder_htons(src_panid.v.u16));
    le_uint16_t dst_pan = {0};
    if (dst_panid) {
        dst_pan = byteorder_btols(byteorder_htons(*dst_panid));
    }

    ieee802154_pib_value_t dsn;
    ieee802154_mac_mlme_get(mac, IEEE802154_PIB_DSN, &dsn);

    uint8_t flags = frame_type;
    if ((frame_type != IEEE802154_FCF_TYPE_BEACON) && ack_req) {
        flags |= IEEE802154_FCF_ACK_REQ;
    }

    bool was_empty = ieee802154_mac_tx_empty(txq);
    size_t mhr_len = ieee802154_set_frame_hdr(dsc->mhr,
                                              src, (size_t)src_len,
                                              dst_len ? dst_addr : NULL, (size_t)dst_len,
                                              src_pan, dst_pan,
                                              flags,
                                              dsn.v.u8);
    if (mhr_len == 0 || mhr_len > (int)sizeof(dsc->mhr)) {
        dsc->in_use = false;
        return -EINVAL;
    }

    dsc->iol_msdu = msdu;
    dsc->iol_mhr.iol_base = &dsc->mhr;
    dsc->iol_mhr.iol_len = mhr_len;
    dsc->iol_mhr.iol_next = dsc->iol_msdu;
    if (msdu && (msdu->iol_len == 0)) {
        /* Avoid zero-length iolist entries with NULL base. */
        dsc->iol_mhr.iol_next = NULL;
    }

    /* DSN++ */
    ieee802154_pib_value_t dsn_new = {
        .type = IEEE802154_PIB_TYPE_U8,
        .v.u8 = dsn.v.u8 + 1,
    };
    uint16_t deadline = ieee802154_indirect_get_deadline(mac);
    dsc->deadline_tick = deadline;
    if (was_empty) {
        txq->deadline_tick = &dsc->deadline_tick;
    }
    ieee802154_mac_tx_commit(txq);
    if (indirect && (dst_mode == IEEE802154_ADDR_MODE_EXTENDED)) {
        ieee802154_mac_indirect_fp_update(mac, (const ieee802154_ext_addr_t *)dst_addr, true);
    }
    ieee802154_mac_mlme_set(mac, IEEE802154_PIB_DSN, &dsn_new);
    return 0;
}

int ieee802154_mac_indirectq_search_slot(ieee802154_mac_indirect_q_t *indirect_q,
                                         const ieee802154_ext_addr_t *dst_addr)
{
    if (!dst_addr) {
        for (int i = 0; i < IEEE802154_MAC_TX_INDIRECTQ_SIZE; i++) {
            if (!indirect_q->q[i].has_dst_addr) {
                return i;
            }
        }
        return -1;
    }
    for (int i = 0; i < IEEE802154_MAC_TX_INDIRECTQ_SIZE; i++) {
        if (!indirect_q->q[i].has_dst_addr) {
            continue;
        }
        if (memcmp(indirect_q->q[i].dst_addr.uint8,
                   dst_addr->uint8,
                   IEEE802154_LONG_ADDRESS_LEN) == 0) {
            return i;
        }
    }
    return -1;
}

int ieee802154_mac_indirectq_get_slot(ieee802154_mac_indirect_q_t *indirect_q,
                                      const ieee802154_ext_addr_t *dst_addr)
{
    int slot = ieee802154_mac_indirectq_search_slot(indirect_q, dst_addr);

    if (slot >= 0) {
        return slot;
    }
    slot = ieee802154_indirectq_alloc_slot(indirect_q);
    if (slot < 0) {
        return slot;
    }
    if (dst_addr) {
        indirect_q->q[slot].dst_addr = *dst_addr;
        indirect_q->q[slot].has_dst_addr = true;
    }
    else {
        indirect_q->q[slot].has_dst_addr = false;
    }
    return slot;
}

int ieee802154_mac_map_push(ieee802154_mac_t *mac,
                            uint8_t frame_type,
                            ieee802154_addr_mode_t src_mode,
                            ieee802154_addr_mode_t dst_mode,
                            const uint16_t *dst_panid,
                            const void *dst_addr,
                            iolist_t *msdu,
                            const uint8_t *msdu_handle,
                            bool ack_req,
                            bool indirect)
{
    // TODO: mapping short to extended
    int slot = ieee802154_mac_indirectq_get_slot(&mac->indirect_q, dst_addr);
    if (slot < 0) {
        return -ENOBUFS;
    }
    int res = _enqueue_data_tx(mac, frame_type, &mac->indirect_q.q[slot], src_mode,
                               dst_mode, dst_panid, dst_addr, msdu,
                               msdu_handle, ack_req, indirect);
    if (res < 0) {
        DEBUG("Enqueue Data failed: %d (%s)\n", res, strerror(-res));
        return res;
    }
    DEBUG("Frame enqueued \n");
    return 0;
}

int ieee802154_mac_enqueue_data_request(ieee802154_mac_t *mac,
                                        ieee802154_addr_mode_t dst_mode,
                                        uint16_t *dst_panid,
                                        const void *dst_addr)
{
    *(uint8_t *)mac->cmd.iol_base = IEEE802154_CMD_DATA_REQ;
    mac->cmd.iol_len = 1;
    mac->cmd.iol_next = NULL;
    // TODO: check for src addressing mode
    uint8_t handle = 0xFFU;
    ieee802154_mac_map_push(mac, IEEE802154_FCF_TYPE_MACCMD, dst_mode, dst_mode,
                            dst_panid, dst_addr, &mac->cmd, &handle, true, false);
    return 0;
}

int ieee802154_mac_enqueue_beacon_request(ieee802154_mac_t *mac)
{
    *(uint8_t *)mac->cmd.iol_base = IEEE802154_CMD_BEACON_REQ;
    mac->cmd.iol_len = 1;
    mac->cmd.iol_next = NULL;
    uint8_t handle = 0xFFU;
    uint8_t panid_bytes[2] = IEEE802154_PANID_BCAST;
    uint16_t panid = ((uint16_t)panid_bytes[1] << 8) | (uint16_t)panid_bytes[0];
    ieee802154_ext_addr_t dst_addr = {.uint8 = IEEE802154_ADDR_BCAST};
    ieee802154_mac_map_push(mac, IEEE802154_FCF_TYPE_MACCMD, IEEE802154_ADDR_MODE_NONE, IEEE802154_ADDR_MODE_SHORT, &panid, &dst_addr, &mac->cmd, &handle, false, false);
    return 0;
}

int _mac_enqueue_beacon(ieee802154_mac_t *mac)
{
    ieee802154_pib_value_t value;
    ieee802154_mac_mlme_get(mac, IEEE802154_PIB_BEACON_PAYLOAD, &value);
    mac->cmd.iol_base = (void *)value.v.bytes.ptr;
    mac->cmd.iol_len = value.v.bytes.len;
    mac->cmd.iol_next = NULL;
    uint8_t handle = 0xFFU;
    ieee802154_mac_mlme_get(mac, IEEE802154_PIB_EXTENDED_ADDRESS, &value);

    ieee802154_mac_map_push(mac, IEEE802154_FCF_TYPE_BEACON, IEEE802154_ADDR_MODE_EXTENDED,
        IEEE802154_ADDR_MODE_NONE, 0, NULL, &mac->cmd, &handle, false, false);
    return 0;
}



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

static int _mac_tx_request(ieee802154_mac_t *mac, const ieee802154_ext_addr_t *dst_addr)
{
    int slot = ieee802154_mac_indirectq_search_slot(&mac->indirect_q, dst_addr);

    if (slot < 0) {
        if (mac->is_coordinator) {
            mac->cbs.rx_request(mac);
        }
        return 1;
    }
    ieee802154_mac_txq_t *txq = &mac->indirect_q.q[slot];
    if (ieee802154_mac_tx_empty(txq) || mac->indirect_q.busy) {
        ieee802154_mac_handle_indirectq_auto_free(mac, &mac->indirect_q, slot);
        return -ENOBUFS;
    }

    ieee802154_mac_tx_desc_t *d = ieee802154_mac_tx_peek(txq);
    mac->indirect_q.current_slot = slot;
    mac->indirect_q.current_txq = txq;
    d->tx_state = IEEE802154_TX_STATE_IN_PROGRESS;
    DEBUG("IEEE802154 MAC: TX state IN_PROGRESS (handle=%u)\n", d->handle);
    int r = ieee802154_send(&mac->submac, &d->iol_mhr);
    if (r == 0) {
        mac->indirect_q.busy = true;
        return 0;
    }
    else {
        ieee802154_mac_tx_finish_current(mac, r);
        return -EIO;
    }
}

int ieee802154_mac_tx(ieee802154_mac_t *mac, const ieee802154_ext_addr_t *dst_addr)
{
    int res = -EINVAL;
    ieee802154_mac_fsm_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.dst_addr = dst_addr;
    ctx.result = &res;

    /* Caller holds submac_lock. */
    if (_mac_fsm_process_ev(mac, IEEE802154_MAC_FSM_EV_TX_REQUEST, &ctx) < 0) {
        return -EBUSY;
    }

    return res;
}

int ieee802154_mac_data_request_fsm(ieee802154_mac_t *mac,
                                    ieee802154_addr_mode_t src_mode,
                                    ieee802154_addr_mode_t dst_mode,
                                    uint16_t dst_panid,
                                    const void *dst_addr,
                                    iolist_t *msdu,
                                    uint8_t msdu_handle,
                                    bool ack_req,
                                    bool indirect)
{
    int res = -EINVAL;
    ieee802154_mac_fsm_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.data_dst_addr = dst_addr;
    ctx.msdu = msdu;
    ctx.msdu_handle = msdu_handle;
    ctx.src_mode = src_mode;
    ctx.dst_mode = dst_mode;
    ctx.dst_panid = dst_panid;
    ctx.ack_req = ack_req;
    ctx.indirect = indirect;
    ctx.result = &res;

    if (!mac) {
        return -EINVAL;
    }

    mutex_lock(&mac->submac_lock);
    (void)_mac_fsm_process_ev(mac, IEEE802154_MAC_FSM_EV_MCPS_DATA_REQ, &ctx);
    mutex_unlock(&mac->submac_lock);

    return res;
}

static void _process_event(ieee802154_mac_t *mac, uint8_t ev)
{
    switch ((ieee802154_mac_ev_t)ev) {
    case IEEE802154_MAC_EV_RADIO_TX_DONE:
        DEBUG("IEEE802154 MAC: processing event IEEE802154_MAC_EV_RADIO_TX_DONE (submac_state=%u)\n",
              mac->submac.fsm_state);
        ieee802154_submac_tx_done_cb(&mac->submac);
        if (mac->scan_active && mac->scan_timer_pending && (mac->scan_req != NULL)) {
            uint32_t duration_us = mac->scan_req->duration * mac->sym_us;
            mac->scan_timer_pending = false;
            ztimer_set(ZTIMER_USEC, &mac->scan_timer, duration_us);
        }
        break;
    case IEEE802154_MAC_EV_RADIO_RX_DONE:
        DEBUG("IEEE802154 MAC: processing event IEEE802154_MAC_EV_RADIO_RX_DONE (submac_state=%u)\n",
              mac->submac.fsm_state);
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

    mutex_lock(&mac->submac_lock);
    _process_event(mac, ev);
    mutex_unlock(&mac->submac_lock);
}

/* ACK timer callback */
static void _ack_timer_cb(void *arg)
{
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;

    mac->cbs.ack_timeout(mac);
}

void ieee802154_mac_ack_timeout_fired(ieee802154_mac_t *mac)
{
    mutex_lock(&mac->submac_lock);
    ieee802154_submac_ack_timeout_fired(&mac->submac);
    mutex_unlock(&mac->submac_lock);
}

void ieee802154_mac_bh_process(ieee802154_mac_t *mac)
{
    mutex_lock(&mac->submac_lock);
    ieee802154_submac_bh_process(&mac->submac);
    mutex_unlock(&mac->submac_lock);
}

/* ===== Required SubMAC extern hooks ===== */
void ieee802154_submac_bh_request(ieee802154_submac_t *submac)
{
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);

    mac->cbs.bh_request(mac);
}

void ieee802154_submac_ack_timer_set(ieee802154_submac_t *submac)
{
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);

    ztimer_set(ZTIMER_USEC, &mac->ack_timer, (uint32_t)submac->ack_timeout_us);
}


void ieee802154_submac_ack_timer_cancel(ieee802154_submac_t *submac)
{
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);

    ztimer_remove(ZTIMER_USEC, &mac->ack_timer);
}

void ieee802154_mac_scan_timer_process(ieee802154_mac_t *mac)
{
    if (!mac) {
        return;
    }

    ieee802154_mac_fsm_process_ev(mac, IEEE802154_MAC_FSM_EV_SCAN_TIMER);
}

/* ===== SubMAC callbacks ===== */
static void _submac_rx_done(ieee802154_submac_t *submac)
{
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);

    mac->cbs.allocate_request(mac);
}

void ieee802154_mac_rx_process(ieee802154_mac_t *mac, iolist_t *buf)
{
    eui64_t src_addr;
    uint8_t src[IEEE802154_LONG_ADDRESS_LEN];//, dst[IEEE802154_LONG_ADDRESS_LEN];
    uint8_t cmd_type, frame_type;
    int mhr_len, src_len;
    le_uint16_t src_pan;
    ieee802154_mac_fsm_ev_t ev;
    bool do_fsm = true;
    ieee802154_mac_fsm_ctx_t ctx;
    mutex_lock(&mac->submac_lock);
    int len = ieee802154_get_frame_length(&mac->submac);
    if (len <= 0) {
        DEBUG("IEEE802154 MAC: RX length %d (scan_active=%d)\n", len, mac->scan_active);
        (void)ieee802154_read_frame(&mac->submac, NULL, 0, NULL);
        mutex_unlock(&mac->submac_lock);
        return;
    }
    ieee802154_rx_info_t info;
    buf->iol_len = len;
    (void)ieee802154_read_frame(&mac->submac, buf->iol_base, buf->iol_len, &info);
    mhr_len = ieee802154_get_frame_hdr_len(buf->iol_base);
    frame_type = ((const uint8_t *)buf->iol_base)[0] & IEEE802154_FCF_TYPE_MASK;
    //dst_len = ieee802154_get_dst(buf->iol_base, dst, &dst_pan);
    src_len = ieee802154_get_src(buf->iol_base, src, &src_pan);
    if (src_len < 0 || (size_t)src_len > sizeof(src_addr)) {
        mutex_unlock(&mac->submac_lock);
        return;
    }
    if (mac->poll_rx_active) {
        mac->poll_rx_active = false;
    }
    memcpy(&src_addr, src, src_len);
    memset(&ctx, 0, sizeof(ctx));
    ctx.buf = buf;
    ctx.info = &info;
    ctx.src_addr = src_addr;
    ctx.src_pan = src_pan;
    ctx.src_len = src_len;
    ctx.frame_type = frame_type;
    if (src_len > 0) {
        memcpy(ctx.src, src, (size_t)src_len);
    }
    switch (frame_type) {
    case IEEE802154_FCF_TYPE_BEACON:
        if (mac->scan_active) {
            ev = IEEE802154_MAC_FSM_EV_RX_BEACON;
        }
        else {
            do_fsm = false;
        }
        break;
    case IEEE802154_FCF_TYPE_DATA:
        ev = IEEE802154_MAC_FSM_EV_RX_DATA;
        break;
    case IEEE802154_FCF_TYPE_MACCMD:
        cmd_type = ((const uint8_t *)buf->iol_base)[mhr_len];
        ctx.cmd_type = cmd_type;
        switch(cmd_type)
        {
        case IEEE802154_CMD_DATA_REQ:
            DEBUG("IEEE802154 MAC: IEEE802154_CMD_DATA_REQ\n");
            ev = IEEE802154_MAC_FSM_EV_RX_CMD_DATA_REQ;
            break;
        case IEEE802154_CMD_BEACON_REQ:
            DEBUG("IEEE802154 MAC: IEEE802154_CMD_BEACON_REQ\n");
            ev = IEEE802154_MAC_FSM_EV_RX_CMD_BEACON_REQ;
            break;
        case IEEE802154_CMD_ASSOCIATION_REQ:
            DEBUG("IEEE802154 MAC: IEEE802154_CMD_ASSOCIATION_REQ\n");
            ev = IEEE802154_MAC_FSM_EV_RX_CMD_ASSOC_REQ;
            break;
        case IEEE802154_CMD_ASSOCIATION_RES:
            DEBUG("IEEE802154 MAC: IEEE802154_CMD_ASSOCIATION_RES\n");
            ev = IEEE802154_MAC_FSM_EV_RX_CMD_ASSOC_RES;
            break;
        case IEEE802154_CMD_DISASSOCIATION:
            DEBUG("IEEE802154 MAC: IEEE802154_CMD_DISASSOCIATION\n");
            ev = IEEE802154_MAC_FSM_EV_RX_CMD_DISASSOC;
            break;
        default:
            DEBUG("IEEE802154 MAC: unknown command id\n");
            do_fsm = false;
            break;
        }
        break;
    default:
        DEBUG("IEEE802154 MAC: unknown FCF_TYPE: %d\n", frame_type);
        mutex_unlock(&mac->submac_lock);
        return;
    }
    if (do_fsm) {
        (void)_mac_fsm_process_ev(mac, ev, &ctx);
    }
    if (mac->scan_active)
    {
        mac->cbs.rx_request(mac);
    }
    mutex_unlock(&mac->submac_lock);
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

static void _tx_finish(ieee802154_mac_t *mac, ieee802154_mac_indirect_q_t *indirect_q, int slot,
                       int status)
{
    if (ieee802154_mac_tx_empty(&indirect_q->q[slot])) {
        mac->indirect_q.busy = false;
        return;
    }

    ieee802154_mac_tx_desc_t *d = ieee802154_mac_tx_peek(&indirect_q->q[slot]);
    d->tx_state = IEEE802154_TX_STATE_DONE;
    DEBUG("IEEE802154 MAC: TX state DONE (handle=%u, status=%d)\n", d->handle, status);
    if ((d->type == IEEE802154_FCF_TYPE_DATA) && mac->cbs.data_confirm) {
        mac->cbs.data_confirm(mac->cbs.mac, d->handle, status);
    }
    /* TODO: implement timer for not receiving frame after frame pending to go back to radio off */
    if (!mac->is_coordinator && (status == TX_STATUS_FRAME_PENDING) &&
        !mac->scan_active) {
        mac->poll_rx_active = true;
        mac->poll_rx_deadline = ieee802154_indirect_get_deadline(mac);
    }
    if (mac->is_coordinator || (status == TX_STATUS_FRAME_PENDING) || mac->scan_active) {
        mac->cbs.rx_request(mac);
    }
    d->in_use = false;
    ieee802154_mac_tx_pop(&indirect_q->q[slot]);
    ieee802154_mac_handle_indirectq_auto_free(mac, indirect_q, slot);
    mac->indirect_q.busy = false;
}

void ieee802154_mac_tick(ieee802154_mac_t *mac)
{
    mutex_lock(&mac->submac_lock);
    mac->indirect_q.tick++;
    if (mac->poll_rx_active &&
        ieee802154_mac_frame_is_expired(mac->indirect_q.tick, mac->poll_rx_deadline) &&
        !mac->is_coordinator && !mac->scan_active) {
        mac->poll_rx_active = false;
        (void)ieee802154_set_idle(&mac->submac);
    }
    for (unsigned i = 0; i < IEEE802154_MAC_TX_INDIRECTQ_SIZE; i++) {
        ieee802154_mac_txq_t *txq = &mac->indirect_q.q[i];
        if (ieee802154_mac_tx_empty(txq) || (txq->deadline_tick == NULL)) {
            continue;
        }
        if (ieee802154_mac_frame_is_expired(mac->indirect_q.tick, *txq->deadline_tick)) {
            _tx_finish(mac, &mac->indirect_q, i, -ETIMEDOUT);
        }
    }
    ztimer_set(ZTIMER_USEC, &mac->tick, (uint32_t)IEEE802154_MAC_TICK_INTERVAL_US);
    mutex_unlock(&mac->submac_lock);
}

void ieee802154_mac_tx_finish_current(ieee802154_mac_t *mac, int status)
{
    _tx_finish(mac, &mac->indirect_q, mac->indirect_q.current_slot, status);
}

void _init_tx_q(ieee802154_mac_t *mac)
{
    /* 1 means free with this the count of 1 is == IEEE802154_MAC_TX_INDIRECTQ_SIZE */
    mac->indirect_q.free_mask = (1U << IEEE802154_MAC_TX_INDIRECTQ_SIZE) - 1;
    mutex_init(&mac->indirect_q.lock);
    memset(&mac->indirect_q.q, 0, sizeof(mac->indirect_q.q));
}

void ieee802154_init_mac_internal(ieee802154_mac_t *mac)
{
    memset(mac->cmd_buf, 0, IEEE802154_FRAME_LEN_MAX);
    mac->cmd.iol_base = mac->cmd_buf;
    mac->cmd.iol_len = IEEE802154_FRAME_LEN_MAX;
    mac->cmd.iol_next = NULL;
    mac->state = IEEE802154_MAC_STATE_IDLE;
    mac->state_before_scan = IEEE802154_MAC_STATE_IDLE;
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
    ieee802154_submac_init(&mac->submac, &short_addr_value.v.short_addr,
                           &ext_addr_value.v.ext_addr);
    mac->submac.cb = &_submac_cbs;
    mac->submac.dev.cb = mac->cbs.radio_cb_request;
    mac->poll_rx_active = false;
    mac->poll_rx_deadline = 0;
    mac->scan_idx = 0;
    mac->tick.callback = mac->cbs.tick_request;
    mac->tick.arg = mac;
    mac->ack_timer.callback = _ack_timer_cb;
    mac->ack_timer.arg = mac;
    mac->scan_timer.callback = mac->cbs.scan_timer_request;
    mac->scan_timer.arg = mac;
    ztimer_set(ZTIMER_USEC, &mac->tick, (uint32_t)IEEE802154_MAC_TICK_INTERVAL_US);
    mutex_unlock(&mac->submac_lock);
}

/** @} */
