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
#include <errno.h>

#include "isrpipe.h"
#include "net/ieee802154/mac.h"
#include "net/ieee802154/mac_pib.h"
#include "net/ieee802154/mac_internal.h"

#define ENABLE_DEBUG 1
#include "debug.h"


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
    ieee802154_init_mac_internal(mac);
}

int ieee802154_mac_mlme_scan_request(ieee802154_mac_t *mac, ieee802154_scan_type_t type,
                                     ieee802154_mlme_scan_req_t *req)
{
    if (mac->scan_active) {
        return -EBUSY;
    }
    if ((req == NULL) || ((req->channels == NULL) && (req->channel_count > 0))) {
        return -EINVAL;
    }
    int res = 0;

    mac->scan_req = req;
    mac->scan_active = true;
    if (req->results_used) {
        *req->results_used = 0;
    }
    mac->scan_timer.callback = mac->cbs.scan_timer_request;
    mac->scan_timer.arg = mac;

    switch (type)
    {
    case IEEE802154_SCAN_ACTIVE:
        mutex_lock(&mac->submac_lock);
        ieee802154_radio_set_frame_filter_mode(&mac->submac.dev, IEEE802154_FILTER_PROMISC);
        mutex_unlock(&mac->submac_lock);
        ieee802154_mac_scan_timer_process(mac);
        break;
    default:
        DEBUG("IEEE802154 MAC: Scan type not implemented\n");
        res = -ENOTSUP;
        mac->scan_active = false;
        mac->scan_req = NULL;
        break;
    }

    return res;
}

int ieee802154_mlme_start_request(ieee802154_mac_t *mac,
                                  uint16_t channel)
{
    (void)channel;
    (void)mac;
    // TODO: implement in radio hal
    bool coord = true;
    int res = ieee802154_radio_config_addr_filter(&mac->submac.dev,IEEE802154_AF_PAN_COORD, (void*) &coord);
    if (res == -ENOTSUP)
    {
        // TODO: filter in rx for the coordinator
        res = ieee802154_radio_set_frame_filter_mode(&mac->submac.dev, IEEE802154_FILTER_PROMISC);
        if (res < 0)
        {
            return res;
        }
    }
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
    mutex_lock(&mac->submac_lock);
    int res = ieee802154_mac_map_push(mac, IEEE802154_FCF_TYPE_DATA, src_mode, dst_mode, &dst_panid,
                                      dst_addr, msdu, &msdu_handle, ack_req, indirect);

    if (res < 0) {
        mutex_unlock(&mac->submac_lock);
        return res;
    }
    if (!indirect) {
        ieee802154_mac_tx(mac, dst_addr);
    }
    mutex_unlock(&mac->submac_lock);
    return 0;
}

int ieee802154_mac_mlme_poll(ieee802154_mac_t *mac, ieee802154_addr_mode_t coord_mode,
                             uint16_t coord_panid, const void *coord_addr)
{
    mutex_lock(&mac->submac_lock);
    int res = ieee802154_mac_enqueue_data_request(mac, coord_mode, &coord_panid, coord_addr);

    ieee802154_mac_tx(mac, coord_addr);
    mutex_unlock(&mac->submac_lock);
    return res;
}

/** @} */
