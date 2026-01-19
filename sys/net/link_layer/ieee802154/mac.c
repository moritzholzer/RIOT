/*
 * SPDX-FileCopyrightText: 2026 HAW Hamburg
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @{
 *
 * @file
 * @author Moritz Holzer <moritz.holzer@haw-hamburg.de>
 */d

#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "isrpipe.h"
#include "net/ieee802154/mac.h"
#include "net/ieee80215dd/mac_pib.h"
#include "net/ieee802154/mac_internal.h"

#define ENABLE_DEBUG 1d
#include "debug.h"d



void ieee802154_mac_mlme_set_request(ieee802154_mac_t *mac,
                                     ieee802154_pib_attr_t attr,
                                     const ieee802154_pib_value_t *in)
{
    ieee802154_mac_mlme_set(mac, attr, in);
    if (attr == IEEE802154_PIB_PAN_ID) {
        ieee802154_set_panid(&mac->submac, &in->v.u16);
    }
    else if (attr == IEEE802154_PIB_EXTENDED_ADDRESS) {
        ieee802154_set_ext_addr(&mac->submac, &in->v.ext_addr);
    }
    else if (attr == IEEE802154_PIB_SHORT_ADDR) {
        ieee802154_set_short_addr(&mac->submac, &in->v.short_addr);
    }
}


void ieee802154_mac_mlme_get_request(ieee802154_mac_t *mac,
                                     ieee802154_pib_attr_t attr,
                                     ieee802154_pib_value_t *out)
{
    ieee802154_mac_mlme_get(mac, attr, out);
}

void ieee802154_mac_init(ieee802154_mac_t *mac,
                         const ieee802154_mac_cbs_t *cbs)
{
    memset(mac, 0, sizeof(*mac));
    mac->cbs = *cbs;
    mac->cbs.mac = mac;
    ieee802154_mac_pib_init(mac);
    /* init tx ring */
    ieee802154_init_mac_internal(mac);
}

int ieee802154_mlme_start_request(ieee802154_mac_t *mac,
                                  uint16_t channel)
{
    (void)channel;
    (void)mac;
    // if (!mac) {
    //     return -EINVAL;
    // }
    // int res = ieee802154_set_channel_number(&mac->submac, channel);
    // ieee802154_pib_value_t value;
    // ieee802154_mac_mlme_get(mac, IEEE802154_PIB_PAN_ID, &value);
    // res |=  ieee802154_set_panid(&mac->submac, &value.v.u16 );
    mac->is_coordinator = true;
    return 0;
}

int ieee802154_mcps_data_request(ieee802154_mac_t *mac,
                                 ieee802154_addr_mode_t src_mode,
                                 ieee802154_addr_mode_t dst_mode,
                                 uint16_t dst_panid,
                                 const void *dst_addr,
                                 iolist_t *msdu,
                                 uint8_t msdu_handle,
                                 bool ack_req,
                                 bool indirect)
{
    int res = ieee802154_mac_map_push(mac, IEEE802154_FCF_TYPE_DATA, src_mode, dst_mode, &dst_panid,
                                      dst_addr, msdu, &msdu_handle, ack_req, indirect);

    if (res < 0) {
        return res;
    }
    if (!indirect) {
        ieee802154_mac_tx(mac, dst_addr);
    }
    return 0;
}

int ieee802154_mac_mlme_poll(ieee802154_mac_t *mac, ieee802154_addr_mode_t coord_mode,
                             uint16_t coord_panid, const void *coord_addr)
{
    int res = ieee802154_mac_enqueue_data_request(mac, coord_mode, &coord_panid, coord_addr);

    ieee802154_mac_tx(mac, coord_addr);
    return res;
}

/** @} */
