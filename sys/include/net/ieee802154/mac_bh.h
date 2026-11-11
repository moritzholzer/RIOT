/*
 * SPDX-FileCopyrightText: 2026 HAW Hamburg
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

/**
 * @{
 *
 * @file
 * @brief IEEE 802.15.4 MAC bottom-half events and processing.
 * @author Moritz Holzer <moritz.holzer@haw-hamburg.de>
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "net/ieee802154/mac.h"

/**
 * @brief IEEE 802.15.4 MAC thread event type.
 */
typedef enum {
    IEEE802154_MAC_EV_INIT,          /**< INIT event */
    IEEE802154_MAC_EV_RADIO_TX_DONE, /**< TX done event */
    IEEE802154_MAC_EV_RADIO_RX_DONE, /**< RX done event */
    IEEE802154_MAC_EV_RADIO_CRC_ERR, /**< CRC error event */
    IEEE802154_MAC_EV_SUBMAC_BH,     /**< bottom half event */
    IEEE802154_MAC_EV_ACK_TIMEOUT,   /**< ACK timeout event */
    IEEE802154_MAC_EV_TX,            /**< wakeup event */
} ieee802154_mac_ev_t;

/**
 * @brief Process the active scan timer in thread context.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 */
void ieee802154_mac_scan_timer_process(ieee802154_mac_t *mac);

#ifdef __cplusplus
}
#endif

/** @} */

