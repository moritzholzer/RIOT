/*
 * SPDX-FileCopyrightText: 2026 HAW Hamburg
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

/**
 * @{
 *
 * @file
 * @brief IEEE 802.15.4 MAC internal initialization.
 * @author Moritz Holzer <moritz.holzer@haw-hamburg.de>
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "mutex.h"

#include "net/ieee802154/mac.h"

/**
 * @brief Initialize internal MAC state.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 */
void ieee802154_init_mac_internal(ieee802154_mac_t *mac);

#ifdef __cplusplus
}
#endif

/** @} */
