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

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "isrpipe.h"
#include "net/ieee802154/radio.h"
#include "net/ieee802154/mac.h"
#include "net/ieee802154/mac_internal.h"
#include "net/ieee802154/submac.h"

#define ENABLE_DEBUG 0
#include "debug.h"

int ieee802154_mac_mlme_set_request(ieee802154_mac_t *mac,
                                ieee802154_pib_attr_t attr,
                                const ieee802154_pib_value_t *in)
{
    if (!mac || !in) {
        return -EINVAL;
    }

    ieee802154_mac_req_t req;
    memset(&req, 0, sizeof(req));

    /* correct request type */
    req.type = IEEE802154_MAC_REQ_MLME_SET;
    req.handle = 0;

    /* correct union member + copy value */
    req.u.set.attr  = attr;
    req.u.set.value = *in;

    int res = ieee80214_mac_req_ring_push(mac, &req);
    if (res < 0) {
        return res; /* -ENOBUFS */
    }

    ieee802154_mac_post_event(mac, IEEE802154_MAC_EV_REQ);
    return 0;
}

int ieee802154_mac_mlme_get_request(ieee802154_mac_t *mac, ieee802154_pib_attr_t attr)
{
    ieee802154_mac_req_t req;
    memset(&req, 0, sizeof(req));
    req.type = IEEE802154_MAC_REQ_MLME_GET;
    req.handle = 0;
    req.u.get.attr = attr;

    int res = ieee80214_mac_req_ring_push(mac, &req);
    if (res < 0) {
        return res; /* -ENOBUFS */
    }

    ieee802154_mac_post_event(mac, IEEE802154_MAC_EV_REQ);
    return 0;
}

int ieee802154_mac_init(ieee802154_mac_t *mac,
                        const ieee802154_mac_cbs_t *cbs)
{
    if (!mac || !cbs) {
        return -EINVAL;
    }

    ieee802154_init_mac_thread(mac, cbs);

    return 0;
}

int ieee802154_mac_start(ieee802154_mac_t *mac)
{
    if (!mac) {
        return -EINVAL;
    }

    ieee802154_mac_submac_attach(mac);

    ieee802154_mac_radio_attach(mac);

    /* init isrpipe */
    isrpipe_init(&mac->evpipe, mac->evpipe_buf, sizeof(mac->evpipe_buf));
    
    /* init tx ring */
    ieee802154_mac_tx_init(mac);

    /* init mac request ring */
    ieee80214_mac_req_ring_init(mac);

    /* start MAC thread*/
    mac->pid = thread_create(mac->stack, sizeof(mac->stack),
                             IEEE802154_MAC_PRIO,
                             THREAD_CREATE_STACKTEST,
                             ieee802154_mac_thread, mac, "ieee802154-mac");
    if (mac->pid <= KERNEL_PID_UNDEF) {
        return -EAGAIN;
    }

    msg_t init_msg = { .type = IEEE802154_MAC_EV_INIT };

    msg_t reply;
    msg_send_receive(&init_msg, &reply, mac->pid);
    return (int)reply.content.value;
}

int ieee802154_mlme_start_request(ieee802154_mac_t *mac,
                                  uint16_t channel)
{
    if (!mac) {
        return -EINVAL;
    }

    ieee802154_mac_req_t req;
    memset(&req, 0, sizeof(req));
    req.type = IEEE802154_MAC_REQ_MLME_START;
    req.u.start.channel = channel;

    int res = ieee80214_mac_req_ring_push(mac, &req);
    if (res < 0) {
        return res; /* -ENOBUFS */
    }

    /* wake MAC thread to drain requests */
    ieee802154_mac_post_event(mac, IEEE802154_MAC_EV_REQ);

    return 0; /* queued */
}

int ieee802154_mcps_data_request(ieee802154_mac_t *mac,
                                 ieee802154_addr_mode_t src_mode,
                                 ieee802154_addr_mode_t dst_mode,
                                 uint16_t dst_panid,
                                 const void *dst_addr,
                                 ieee802154_octets_t msdu,
                                 uint8_t msdu_handle,
                                 bool ack_req)
{
    if (!mac) {
        return -EINVAL;
    }

    const uint8_t src_len = ieee80214_addr_len_from_mode(src_mode);
    const uint8_t dst_len = ieee80214_addr_len_from_mode(dst_mode);

    if (dst_mode != IEEE802154_ADDR_MODE_NONE) {
        if (dst_len == 0 || dst_addr == NULL) {
            return -EINVAL;
        }
    }
    if (src_mode != IEEE802154_ADDR_MODE_NONE && src_len == 0) {
        return -EINVAL;
    }

    if (msdu.len > IEEE802154_FRAME_LEN_MAX) {
        return -EMSGSIZE;
    }

    ieee802154_mac_payload_t *pl = ieee802154_mac_payload_alloc(mac);
    if (!pl) {
        return -ENOBUFS;
    }
    memcpy(pl->buf, msdu.ptr, msdu.len);
    pl->len = (uint16_t)msdu.len;

    ieee802154_mac_req_t req;
    memset(&req, 0, sizeof(req));
    req.type = IEEE802154_MAC_REQ_TX;
    req.handle = msdu_handle;

    req.u.tx.src_mode = src_mode;
    req.u.tx.dst_mode = dst_mode;
    req.u.tx.dst_panid = dst_panid;

    req.u.tx.dst_len = dst_len;
    if (dst_len) {
        memcpy(req.u.tx.dst_addr, dst_addr, dst_len);
    }

    req.u.tx.ack_req = ack_req;
    req.u.tx.pl = pl;

    int res = ieee80214_mac_req_ring_push(mac, &req);
    if (res < 0) {
        ieee802154_mac_payload_free(mac, pl);
        return res; /* -ENOBUFS */
    }

    ieee802154_mac_post_event(mac, IEEE802154_MAC_EV_REQ);

    return 0;
}
