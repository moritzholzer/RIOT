/*
 * SPDX-FileCopyrightText: 2026 HAW Hamburg
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <string.h>

#include "mutex.h"

#include "mac_internal_priv.h"
#include "mac_pib.h"

#define ENABLE_DEBUG 1
#include "debug.h"

static int _mac_tx_request(ieee802154_mac_t *mac, ieee802154_addr_mode_t dst_mode,
                           const void *dst_addr);
static int _mac_enqueue_and_tx(ieee802154_mac_t *mac, const ieee802154_mac_fsm_ctx_t *ctx,
                               ieee802154_addr_mode_t src_mode, uint8_t frame_type,
                               iolist_t *msdu, const uint8_t *msdu_handle,
                               bool ack_req, bool indirect);
static int _mac_data_request(ieee802154_mac_t *mac, const ieee802154_mac_fsm_ctx_t *ctx);
static int _mac_assoc_request(ieee802154_mac_t *mac, const ieee802154_mac_fsm_ctx_t *ctx);
static int _mac_poll_request(ieee802154_mac_t *mac, const ieee802154_mac_fsm_ctx_t *ctx);
static int _mac_assoc_response(ieee802154_mac_t *mac, const ieee802154_mac_fsm_ctx_t *ctx);
static int _mac_enqueue_beacon(ieee802154_mac_t *mac);
static ieee802154_mac_state_t _mac_fsm_state_idle(ieee802154_mac_t *mac,
                                                  ieee802154_mac_fsm_ev_t ev,
                                                  const ieee802154_mac_fsm_ctx_t *ctx);
static ieee802154_mac_state_t _mac_fsm_state_scan_active(ieee802154_mac_t *mac,
                                                         ieee802154_mac_fsm_ev_t ev,
                                                         const ieee802154_mac_fsm_ctx_t *ctx);
static ieee802154_mac_state_t _mac_fsm_state_coordinator(ieee802154_mac_t *mac,
                                                         ieee802154_mac_fsm_ev_t ev,
                                                         const ieee802154_mac_fsm_ctx_t *ctx);
static ieee802154_mac_state_t _mac_fsm_state_device(ieee802154_mac_t *mac,
                                                    ieee802154_mac_fsm_ev_t ev,
                                                    const ieee802154_mac_fsm_ctx_t *ctx);
static ieee802154_mac_state_t _mac_fsm_state_associating(ieee802154_mac_t *mac,
                                                         ieee802154_mac_fsm_ev_t ev,
                                                         const ieee802154_mac_fsm_ctx_t *ctx);
static ieee802154_mac_state_t _mac_fsm_state_sleep(ieee802154_mac_t *mac,
                                                   ieee802154_mac_fsm_ev_t ev,
                                                   const ieee802154_mac_fsm_ctx_t *ctx);
static int _mac_fsm_process_ev(ieee802154_mac_t *mac, ieee802154_mac_fsm_ev_t ev,
                               const ieee802154_mac_fsm_ctx_t *ctx);

static const char *const _mac_fsm_ev_str[] = {
    [IEEE802154_MAC_FSM_EV_SCAN_START] = "SCAN_START",
    [IEEE802154_MAC_FSM_EV_SCAN_DONE] = "SCAN_DONE",
    [IEEE802154_MAC_FSM_EV_ASSOC_REQ_RX] = "ASSOC_REQ_RX",
    [IEEE802154_MAC_FSM_EV_ASSOC_RES_RX] = "ASSOC_RES_RX",
    [IEEE802154_MAC_FSM_EV_DISASSOC_RX] = "DISASSOC_RX",
    [IEEE802154_MAC_FSM_EV_COORD_START] = "COORD_START",
    [IEEE802154_MAC_FSM_EV_MLME_ASSOC_REQ] = "MLME_ASSOC_REQ",
    [IEEE802154_MAC_FSM_EV_MLME_POLL] = "MLME_POLL",
    [IEEE802154_MAC_FSM_EV_MLME_ASSOC_RES] = "MLME_ASSOC_RES",
    [IEEE802154_MAC_FSM_EV_ASSOC_TIMEOUT] = "ASSOC_TIMEOUT",
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

static int _mac_enqueue_and_tx(ieee802154_mac_t *mac, const ieee802154_mac_fsm_ctx_t *ctx,
                               ieee802154_addr_mode_t src_mode, uint8_t frame_type,
                               iolist_t *msdu, const uint8_t *msdu_handle,
                               bool ack_req, bool indirect)
{
    if (!ctx || !ctx->result || !ctx->data_dst_addr) {
        return -EINVAL;
    }

    int res = ieee802154_mac_map_push(mac, frame_type,
                                      src_mode, ctx->dst_mode,
                                      &ctx->dst_panid, ctx->data_dst_addr,
                                      msdu, msdu_handle,
                                      ack_req, indirect);
    if (res < 0) {
        *ctx->result = res;
        return res;
    }
    if (!indirect) {
        res = _mac_tx_request(mac, ctx->dst_mode, ctx->data_dst_addr);
        *ctx->result = res;
        return res;
    }
    *ctx->result = 0;
    return 0;
}

static int _mac_data_request(ieee802154_mac_t *mac, const ieee802154_mac_fsm_ctx_t *ctx)
{
    return _mac_enqueue_and_tx(mac, ctx, ctx->src_mode, IEEE802154_FCF_TYPE_DATA,
                               ctx->msdu, &ctx->msdu_handle, ctx->ack_req, ctx->indirect);
}

static int _mac_assoc_request(ieee802154_mac_t *mac, const ieee802154_mac_fsm_ctx_t *ctx)
{
    if (!ctx || !ctx->result) {
        return -EINVAL;
    }

    uint8_t *buf = (uint8_t *)mac->cmd.iol_base;
    buf[0] = IEEE802154_CMD_ASSOCIATION_REQ;
    buf[1] = ieee802154_assoc_capability_pack(ctx->capability);
    mac->cmd.iol_len = 2;
    mac->cmd.iol_next = NULL;
    uint8_t handle = 0xFFU;

    int res = _mac_enqueue_and_tx(mac, ctx, ctx->dst_mode, IEEE802154_FCF_TYPE_MACCMD,
                                  &mac->cmd, &handle, true, false);
    if (res < 0) {
        return res;
    }

    ieee802154_pib_value_t wait;
    ieee802154_mac_mlme_get(mac, IEEE802154_PIB_RESPONSE_WAIT_TIME, &wait);
    uint32_t duration_us = (uint32_t)wait.v.u8 * 60U * mac->sym_us;
    uint16_t ticks = (uint16_t)((duration_us + IEEE802154_MAC_TICK_INTERVAL_US - 1U) /
                                IEEE802154_MAC_TICK_INTERVAL_US);
    if (ticks == 0) {
        ticks = 1;
    }
    mac->assoc_pending = true;
    mac->assoc_deadline_tick = mac->indirect_q.tick + ticks;
    return res;
}

static int _mac_poll_request(ieee802154_mac_t *mac, const ieee802154_mac_fsm_ctx_t *ctx)
{
    uint8_t *buf = (uint8_t *)mac->cmd.iol_base;
    buf[0] = IEEE802154_CMD_DATA_REQ;
    mac->cmd.iol_len = 1;
    mac->cmd.iol_next = NULL;
    uint8_t handle = 0xFFU;

    return _mac_enqueue_and_tx(mac, ctx, ctx->dst_mode, IEEE802154_FCF_TYPE_MACCMD,
                               &mac->cmd, &handle, true, false);
}

static int _mac_assoc_response(ieee802154_mac_t *mac, const ieee802154_mac_fsm_ctx_t *ctx)
{
    if (!ctx || !ctx->result || !ctx->data_dst_addr) {
        return -EINVAL;
    }

    if ((ctx->assoc_status == IEEE802154_ASSOC_STATUS_SUCCESS) &&
        (ctx->dst_mode == IEEE802154_ADDR_MODE_EXTENDED)) {
        ieee802154_mac_addr_map_add(mac, ctx->assoc_short_addr,
                                    (const ieee802154_ext_addr_t *)ctx->data_dst_addr);
    }

    uint8_t *buf = (uint8_t *)mac->cmd.iol_base;
    buf[0] = IEEE802154_CMD_ASSOCIATION_RES;
    buf[1] = (uint8_t)(ctx->assoc_short_addr & 0xFFU);
    buf[2] = (uint8_t)((ctx->assoc_short_addr >> 8) & 0xFFU);
    buf[3] = ctx->assoc_status;
    mac->cmd.iol_len = 4;
    mac->cmd.iol_next = NULL;
    uint8_t handle = 0xFFU;

    return _mac_enqueue_and_tx(mac, ctx, ctx->dst_mode, IEEE802154_FCF_TYPE_MACCMD,
                               &mac->cmd, &handle, true, false);
}
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
        mac->state_history = mac->state;
        mac->scan_idx = 0;
        return IEEE802154_MAC_STATE_SCAN_ACTIVE;
    case IEEE802154_MAC_FSM_EV_COORD_START:
    case IEEE802154_MAC_FSM_EV_ASSOC_REQ_RX:
    case IEEE802154_MAC_FSM_EV_RX_CMD_ASSOC_REQ:
        return IEEE802154_MAC_STATE_COORDINATOR;
    case IEEE802154_MAC_FSM_EV_ASSOC_RES_RX:
    case IEEE802154_MAC_FSM_EV_RX_CMD_ASSOC_RES:
        return IEEE802154_MAC_STATE_DEVICE;
    case IEEE802154_MAC_FSM_EV_MLME_ASSOC_REQ:
        if (ctx) {
            (void)_mac_assoc_request(mac, ctx);
        }
        return IEEE802154_MAC_STATE_ASSOCIATING;
    case IEEE802154_MAC_FSM_EV_MLME_POLL:
        if (ctx) {
            (void)_mac_poll_request(mac, ctx);
        }
        return IEEE802154_MAC_STATE_DEVICE;
    case IEEE802154_MAC_FSM_EV_TX_REQUEST:
        if (ctx && ctx->dst_addr && ctx->result) {
            *ctx->result = _mac_tx_request(mac, ctx->dst_mode, ctx->dst_addr);
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
        if (ctx) {
            const void *src_addr = (ctx->src_mode == IEEE802154_ADDR_MODE_SHORT)
                                    ? (const void *)ctx->src
                                    : (const void *)&ctx->src_addr;
            if (_mac_tx_request(mac, ctx->src_mode, src_addr) > 0) {
                mac->cbs.dealloc_request(mac, ctx->buf);
            }
        }
        return IEEE802154_MAC_STATE_IDLE;
    case IEEE802154_MAC_FSM_EV_RX_CMD_BEACON_REQ:
        if (ctx) {
            _mac_enqueue_beacon(mac);
            const void *src_addr = (ctx->src_mode == IEEE802154_ADDR_MODE_SHORT)
                                    ? (const void *)ctx->src
                                    : (const void *)&ctx->src_addr;
            (void)_mac_tx_request(mac, ctx->src_mode, src_addr);
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
    uint16_t dst_addr = 0xFFFFU;

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
        return mac->state_history;
    }
    case IEEE802154_MAC_FSM_EV_SCAN_TIMER:
        idx = mac->scan_idx;
        if (idx >= mac->scan_req->channel_count) {
            return ieee802154_mac_fsm_process_ev_ctx(mac, IEEE802154_MAC_FSM_EV_SCAN_DONE, NULL);
        }
        res = ieee802154_set_channel_number(&mac->submac, mac->scan_req->channels[idx]);
        res |= ieee802154_mac_enqueue_beacon_request(mac);
        if (res < 0)
        {
            DEBUG("IEEE802154 MAC: failed to scan channel %u\n", mac->scan_req->channels[idx]);
        }
        res = _mac_tx_request(mac, IEEE802154_ADDR_MODE_SHORT, &dst_addr);
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
        if (ctx) {
            const void *src_addr = (ctx->src_mode == IEEE802154_ADDR_MODE_SHORT)
                                    ? (const void *)ctx->src
                                    : (const void *)&ctx->src_addr;
            if (_mac_tx_request(mac, ctx->src_mode, src_addr) > 0) {
                mac->cbs.dealloc_request(mac, ctx->buf);
            }
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
        mac->state_history = mac->state;
        mac->scan_idx = 0;
        mac->scan_timer_pending = false;
        return IEEE802154_MAC_STATE_SCAN_ACTIVE;
    case IEEE802154_MAC_FSM_EV_RX_CMD_ASSOC_REQ:
        if (ctx && mac->cbs.mlme_associate_indication) {
            mac->cbs.mlme_associate_indication(mac->cbs.mac, ctx->src,
                                               (uint8_t)ctx->src_len,
                                               ctx->src_mode, ctx->capability);
        }
        return IEEE802154_MAC_STATE_COORDINATOR;
    case IEEE802154_MAC_FSM_EV_DISASSOC_RX:
    case IEEE802154_MAC_FSM_EV_RX_CMD_DISASSOC:
        return IEEE802154_MAC_STATE_COORDINATOR;
    case IEEE802154_MAC_FSM_EV_RX_DATA:
        if (ctx && mac->cbs.data_indication) {
            mac->cbs.data_indication(mac->cbs.mac, ctx->buf, ctx->info);
        }
        return IEEE802154_MAC_STATE_COORDINATOR;
    case IEEE802154_MAC_FSM_EV_RX_CMD_DATA_REQ:
        if (ctx) {
            const void *src_addr = (ctx->src_mode == IEEE802154_ADDR_MODE_SHORT)
                                    ? (const void *)ctx->src
                                    : (const void *)&ctx->src_addr;
            if (_mac_tx_request(mac, ctx->src_mode, src_addr) > 0) {
                mac->cbs.dealloc_request(mac, ctx->buf);
            }
        }
        return IEEE802154_MAC_STATE_COORDINATOR;
    case IEEE802154_MAC_FSM_EV_RX_CMD_BEACON_REQ:
        if (ctx) {
            DEBUG("SENDING BEACON\n");
            _mac_enqueue_beacon(mac);
            const void *dst_addr = NULL;
            ieee802154_addr_mode_t dst_mode = IEEE802154_ADDR_MODE_NONE;
            if (ctx->src_len > 0) {
                dst_mode = ctx->src_mode;
                dst_addr = (ctx->src_mode == IEEE802154_ADDR_MODE_SHORT)
                           ? (const void *)ctx->src
                           : (const void *)&ctx->src_addr;
            }
            if (_mac_tx_request(mac, dst_mode, dst_addr) < 0)
            {
                DEBUG("ERROR SENDING BEACON\n");
            }
        }
        return IEEE802154_MAC_STATE_COORDINATOR;
    case IEEE802154_MAC_FSM_EV_TX_REQUEST:
        if (ctx && ctx->dst_addr && ctx->result) {
            *ctx->result = _mac_tx_request(mac, ctx->dst_mode, ctx->dst_addr);
        }
        return IEEE802154_MAC_STATE_COORDINATOR;
    case IEEE802154_MAC_FSM_EV_MCPS_DATA_REQ:
        if (ctx) {
            (void)_mac_data_request(mac, ctx);
        }
        return IEEE802154_MAC_STATE_COORDINATOR;
    case IEEE802154_MAC_FSM_EV_MLME_ASSOC_RES:
        if (ctx) {
            (void)_mac_assoc_response(mac, ctx);
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
        mac->assoc_pending = false;
        return IEEE802154_MAC_STATE_IDLE;
    case IEEE802154_MAC_FSM_EV_RX_DATA:
        if (ctx && mac->cbs.data_indication) {
            mac->cbs.data_indication(mac->cbs.mac, ctx->buf, ctx->info);
        }
        return IEEE802154_MAC_STATE_DEVICE;
    case IEEE802154_MAC_FSM_EV_TX_REQUEST:
        if (ctx && ctx->dst_addr && ctx->result) {
            *ctx->result = _mac_tx_request(mac, ctx->dst_mode, ctx->dst_addr);
        }
        return IEEE802154_MAC_STATE_DEVICE;
    case IEEE802154_MAC_FSM_EV_MLME_POLL:
        if (ctx) {
            (void)_mac_poll_request(mac, ctx);
        }
        return IEEE802154_MAC_STATE_DEVICE;
    case IEEE802154_MAC_FSM_EV_MLME_ASSOC_REQ:
        if (ctx) {
            (void)_mac_assoc_request(mac, ctx);
        }
        return IEEE802154_MAC_STATE_ASSOCIATING;
    case IEEE802154_MAC_FSM_EV_COORD_START:
        return IEEE802154_MAC_STATE_COORDINATOR;
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
        mac->assoc_pending = false;
        if (ctx && mac->cbs.mlme_associate_confirm) {
            mac->cbs.mlme_associate_confirm(mac->cbs.mac, ctx->assoc_status,
                                            ctx->assoc_short_addr);
        }
        if (ctx && ctx->assoc_status == 0) {
            ieee802154_pib_value_t short_addr_value = {
                .type = IEEE802154_PIB_TYPE_NUI16,
                .v.u16 = ctx->assoc_short_addr,
            };
            ieee802154_mac_mlme_set(mac, IEEE802154_PIB_SHORT_ADDR, &short_addr_value);
            (void)ieee802154_set_short_addr(&mac->submac, &short_addr_value.v.short_addr);
            (void)ieee802154_set_idle(&mac->submac);
            return IEEE802154_MAC_STATE_DEVICE;
        }
        (void)ieee802154_set_idle(&mac->submac);
        return IEEE802154_MAC_STATE_IDLE;
    case IEEE802154_MAC_FSM_EV_DISASSOC_RX:
    case IEEE802154_MAC_FSM_EV_RX_CMD_DISASSOC:
        mac->assoc_pending = false;
        return IEEE802154_MAC_STATE_IDLE;
    case IEEE802154_MAC_FSM_EV_ASSOC_TIMEOUT:
        mac->assoc_pending = false;
        if (mac->cbs.mlme_associate_confirm) {
            mac->cbs.mlme_associate_confirm(mac->cbs.mac, -ETIMEDOUT, 0xFFFF);
        }
        (void)ieee802154_set_idle(&mac->submac);
        return IEEE802154_MAC_STATE_IDLE;
    case IEEE802154_MAC_FSM_EV_RX_DATA:
        if (ctx && mac->cbs.data_indication) {
            mac->cbs.data_indication(mac->cbs.mac, ctx->buf, ctx->info);
        }
        return IEEE802154_MAC_STATE_ASSOCIATING;
    case IEEE802154_MAC_FSM_EV_TX_REQUEST:
        if (ctx && ctx->dst_addr && ctx->result) {
            *ctx->result = _mac_tx_request(mac, ctx->dst_mode, ctx->dst_addr);
        }
        return IEEE802154_MAC_STATE_ASSOCIATING;
    case IEEE802154_MAC_FSM_EV_MLME_POLL:
        if (ctx) {
            (void)_mac_poll_request(mac, ctx);
        }
        return IEEE802154_MAC_STATE_ASSOCIATING;
    case IEEE802154_MAC_FSM_EV_MLME_ASSOC_REQ:
        if (ctx) {
            (void)_mac_assoc_request(mac, ctx);
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
        if (mac->state_history != IEEE802154_MAC_STATE_INVALID) {
            return mac->state_history;
        }
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
    else if (ev == IEEE802154_MAC_FSM_EV_SLEEP) {
        mac->state_history = mac->state;
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
            mac->coord_softmode = true;
        }
        else if (res >= 0) {
            mac->coord_softmode = false;
        }
        mac->is_coordinator = true;
    }

    return 0;
}

int ieee802154_mac_fsm_process_ev_ctx(ieee802154_mac_t *mac, ieee802154_mac_fsm_ev_t ev,
                                      const ieee802154_mac_fsm_ctx_t *ctx)
{
    return _mac_fsm_process_ev(mac, ev, ctx);
}

int ieee802154_mac_fsm_request(ieee802154_mac_t *mac, ieee802154_mac_fsm_ev_t ev,
                               const ieee802154_mac_fsm_ctx_t *ctx)
{
    if (!mac) {
        return -EINVAL;
    }

    mutex_lock(&mac->submac_lock);
    int res = _mac_fsm_process_ev(mac, ev, ctx);
    mutex_unlock(&mac->submac_lock);
    return res;
}

int ieee802154_mac_tx(ieee802154_mac_t *mac, const ieee802154_ext_addr_t *dst_addr)
{
    int res = -EINVAL;
    ieee802154_mac_fsm_ctx_t ctx;

    memset(&ctx, 0, sizeof(ctx));
    ctx.dst_addr = dst_addr;
    ctx.dst_mode = IEEE802154_ADDR_MODE_EXTENDED;
    ctx.result = &res;

    if (ieee802154_mac_fsm_request(mac, IEEE802154_MAC_FSM_EV_TX_REQUEST, &ctx) < 0) {
        return -EBUSY;
    }

    return res;
}

static int _mac_enqueue_beacon(ieee802154_mac_t *mac)
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

static int _mac_tx_request(ieee802154_mac_t *mac, ieee802154_addr_mode_t dst_mode,
                           const void *dst_addr)
{
    int slot = ieee802154_mac_indirectq_search_slot(mac, dst_mode, dst_addr);

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
    if (r != 0)
    {
        ieee802154_mac_tx_finish_current(mac, r);
        return -EIO;
    }
    mac->indirect_q.busy = true;
    return 0;
}
