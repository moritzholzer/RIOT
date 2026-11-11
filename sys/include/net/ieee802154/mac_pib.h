/*
 * SPDX-FileCopyrightText: 2026 HAW Hamburg
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

/**
 * @{
 *
 * @file
 * @brief IEEE 802.15.4 MAC PIB access.
 * @author Moritz Holzer <moritz.holzer@haw-hamburg.de>
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "net/ieee802154/mac.h"

/**
 * @brief Initialize the MAC PIB defaults.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 */
void ieee802154_mac_pib_init(ieee802154_mac_t *mac);
/**
 * @brief Handle a MAC MLME-SET request.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] attr     PIB attribute identifier.
 * @param[in] in       New attribute value with the matching PIB data type.
 */
void ieee802154_mac_mlme_set(ieee802154_mac_t *mac,
                            ieee802154_pib_attr_t attr,
                            const ieee802154_pib_value_t *in);
/**
 * @brief Handle a MAC MLME-GET request.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] attr     PIB attribute identifier.
 * @param[out] out     Storage for the attribute type and value.
 */
void ieee802154_mac_mlme_get(ieee802154_mac_t *mac,
                            ieee802154_pib_attr_t attr,
                            ieee802154_pib_value_t *out);

#ifdef __cplusplus
}
#endif

/** @} */
