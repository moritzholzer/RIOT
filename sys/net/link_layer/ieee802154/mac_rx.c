/*
 * SPDX-FileCopyrightText: 2026 HAW Hamburg
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <string.h>

#include "mutex.h"

#include "mac_internal_priv.h"

#define ENABLE_DEBUG 1
#include "debug.h"

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
    uint8_t fcf0 = ((const uint8_t *)buf->iol_base)[0];
    uint8_t fcf1 = ((const uint8_t *)buf->iol_base)[1];
    uint8_t dst_mode = fcf1 & IEEE802154_FCF_DST_ADDR_MASK;
    bool dst_match = true;
    frame_type = fcf0 & IEEE802154_FCF_TYPE_MASK;
    if (mac->is_coordinator && mac->coord_softmode) {

        if (dst_mode != IEEE802154_FCF_DST_ADDR_VOID) {
            dst_match = (ieee802154_dst_filter(buf->iol_base, mac->submac.panid,
                                               mac->submac.short_addr,
                                               &mac->submac.ext_addr) == 0);
            if (!dst_match) {
                if (mac->cbs.dealloc_request) {
                    mac->cbs.dealloc_request(mac, buf);
                }
                mutex_unlock(&mac->submac_lock);
                return;
            }
        }
    }
    //dst_len = ieee802154_get_dst(buf->iol_base, dst, &dst_pan);
    src_len = ieee802154_get_src(buf->iol_base, src, &src_pan);
    if (src_len < 0 || (size_t)src_len > sizeof(src_addr)) {
        mutex_unlock(&mac->submac_lock);
        return;
    }
    if (mac->is_coordinator && mac->coord_softmode &&
        (fcf0 & IEEE802154_FCF_ACK_REQ) &&
        (dst_mode != IEEE802154_FCF_DST_ADDR_VOID) &&
        (frame_type != IEEE802154_FCF_TYPE_ACK) &&
        dst_match) {
        uint8_t ack[IEEE802154_ACK_FRAME_LEN - IEEE802154_FCS_LEN];
        bool fp = false;

        if (src_len == IEEE802154_SHORT_ADDRESS_LEN) {
            uint16_t short_addr = (uint16_t)src[0] | ((uint16_t)src[1] << 8);
            int slot = ieee802154_mac_indirectq_search_slot(mac,
                                                            IEEE802154_ADDR_MODE_SHORT,
                                                            &short_addr);
            if ((slot >= 0) && !ieee802154_mac_tx_empty(&mac->indirect_q.q[slot])) {
                fp = true;
            }
        }
        else if (src_len == IEEE802154_LONG_ADDRESS_LEN) {
            ieee802154_ext_addr_t ext;
            memcpy(ext.uint8, src, IEEE802154_LONG_ADDRESS_LEN);
            int slot = ieee802154_mac_indirectq_search_slot(mac,
                                                            IEEE802154_ADDR_MODE_EXTENDED,
                                                            &ext);
            if ((slot >= 0) && !ieee802154_mac_tx_empty(&mac->indirect_q.q[slot])) {
                fp = true;
            }
        }

        ack[0] = IEEE802154_FCF_TYPE_ACK | (fp ? IEEE802154_FCF_FRAME_PEND : 0);
        ack[1] = 0;
        ack[2] = ((const uint8_t *)buf->iol_base)[2];
        iolist_t ack_iol = {
            .iol_base = ack,
            .iol_len = sizeof(ack),
            .iol_next = NULL
        };
        (void)ieee802154_send(&mac->submac, &ack_iol);
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
    ctx.assoc_status = 0xFFU;
    ctx.assoc_short_addr = 0xFFFFU;
    ctx.capability.u8 = 0;
    if (src_len == IEEE802154_SHORT_ADDRESS_LEN) {
        ctx.src_mode = IEEE802154_ADDR_MODE_SHORT;
    }
    else if (src_len == IEEE802154_LONG_ADDRESS_LEN) {
        ctx.src_mode = IEEE802154_ADDR_MODE_EXTENDED;
    }
    else {
        ctx.src_mode = IEEE802154_ADDR_MODE_NONE;
    }
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
            if ((size_t)len >= (size_t)mhr_len + 2U) {
                const uint8_t *pl = ((const uint8_t *)buf->iol_base) + mhr_len;
                ctx.capability.u8 = pl[1];
            }
            break;
        case IEEE802154_CMD_ASSOCIATION_RES:
            DEBUG("IEEE802154 MAC: IEEE802154_CMD_ASSOCIATION_RES\n");
            ev = IEEE802154_MAC_FSM_EV_RX_CMD_ASSOC_RES;
            if ((size_t)len >= (size_t)mhr_len + 3U) {
                const uint8_t *pl = ((const uint8_t *)buf->iol_base) + mhr_len;
                ctx.assoc_short_addr = (uint16_t)pl[0] | ((uint16_t)pl[1] << 8);
                ctx.assoc_status = pl[2];
            }
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
        (void)ieee802154_mac_fsm_process_ev_ctx(mac, ev, &ctx);
    }
    if (mac->scan_active)
    {
        mac->cbs.rx_request(mac);
    }
    mutex_unlock(&mac->submac_lock);
}
