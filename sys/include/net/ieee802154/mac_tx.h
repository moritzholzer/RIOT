/*
 * SPDX-FileCopyrightText: 2026 HAW Hamburg
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

/**
 * @{
 *
 * @file
 * @brief IEEE 802.15.4 MAC transmission control.
 * @author Moritz Holzer <moritz.holzer@haw-hamburg.de>
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "net/ieee802154/mac.h"


/**
 * @brief Finish the current TX and report status.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] status   Operation completion status.
 * @param[in] info     Transmission metadata, or NULL if unavailable.
 */
void ieee802154_mac_tx_finish_current(ieee802154_mac_t *mac, int status, ieee802154_tx_info_t *info);

/**
 * @brief Transmit a MAC frame to the given destination.
 *
 * @param[in,out] mac   MAC descriptor or callback context.
 * @param[in] dst_addr  Destination address in network byte order; NULL selects an unaddressed queue where supported.
 * @return 0 when transmission starts, 1 if no queue matches, or a negative error code.
 */
int ieee802154_mac_tx(ieee802154_mac_t *mac, const ieee802154_ext_addr_t *dst_addr);

#ifdef __cplusplus
}
#endif

/** @} */
