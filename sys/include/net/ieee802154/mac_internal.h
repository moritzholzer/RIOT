/*
 * SPDX-FileCopyrightText: 2026 HAW Hamburg
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

/**
 * @{
 *
 * @file
 * @author Moritz Holzer <moritz.holzer@haw-hamburg.de>
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "mutex.h"

#include "net/ieee802154/mac.h"
#include "net/ieee802154/mac_pib.h"

#define ENABLE_DEBUG 1
#include "debug.h"

/**
 * @brief IEEE 802.15.4 MAC thread event type.
 */
typedef enum {
    IEEE802154_MAC_EV_INIT,             /**< INIT event */
    IEEE802154_MAC_EV_REQ,
    IEEE802154_MAC_EV_RADIO_TX_DONE,    /**< TX done event */
    IEEE802154_MAC_EV_RADIO_RX_DONE,    /**< RX done event */
    IEEE802154_MAC_EV_RADIO_CRC_ERR,    /**< CRC error event */
    IEEE802154_MAC_EV_SUBMAC_BH,        /**< bootom half event */
    IEEE802154_MAC_EV_ACK_TIMEOUT,      /**< ACK timeout event */
    IEEE802154_MAC_EV_TX,               /**< wakeup event */
} ieee802154_mac_ev_t;

void ieee802154_init_mac_internal(ieee802154_mac_t *mac);

/**
 * @brief Attaches the IEEE 802.15.4 SubMAC callbacks.
 */
void ieee802154_mac_submac_attach(ieee802154_mac_t *mac);

/**
 * @brief Attaches the IEEE 802.15.4 SubMAC callbacks.
 */
void ieee802154_mac_tx_finish_current(ieee802154_mac_t *mac, int status);

/**
 * @brief Attaches the IEEE 802.15.4 Radio HAL callbacks.
 */
void ieee802154_mac_radio_attach(ieee802154_mac_t *mac);

int ieee802154_mac_tx(ieee802154_mac_t *mac, const ieee802154_ext_addr_t *dst_addr);

/**
 * @brief Whether the TX queue is full.
 */
bool ieee802154_mac_tx_full(const ieee802154_mac_txq_t *txq);

/**
 * @brief Whether the TX queue is empty.
 */
bool ieee802154_mac_tx_empty(const ieee802154_mac_txq_t *txq);

/**
 * @brief Returns a descriptor of TX queue head. Caller fills it.
 */
ieee802154_mac_tx_desc_t *ieee802154_mac_tx_reserve(ieee802154_mac_txq_t *txq);

/**
 * @brief Advances TX queue tail to make it visible to the sender.
 */
void ieee802154_mac_tx_commit(ieee802154_mac_txq_t *txq);

/**
 * @brief Returns descriptor of TX queue head (next to send), does not remove.
 */
ieee802154_mac_tx_desc_t *ieee802154_mac_tx_peek(ieee802154_mac_txq_t *txq);

/**
 * @brief Removes TX queue head entry.
 */
void ieee802154_mac_tx_pop(ieee802154_mac_txq_t *txq);

int ieee802154_indirectq_alloc_slot(ieee802154_mac_indirect_q_t *indirect_q);
void ieee802154_indirectq_free_slot(ieee802154_mac_indirect_q_t *indirect_q, uint8_t slot);
uint16_t ieee802154_indirect_get_deadline(ieee802154_mac_t *mac);
bool ieee802154_mac_frame_is_expired(uint16_t now_tick, uint16_t deadline_tick);
void ieee802154_mac_indirect_fp_update(ieee802154_mac_t *mac,
                                       const ieee802154_ext_addr_t *dst_addr,
                                       bool pending);
void ieee802154_mac_handle_indirectq_auto_free(ieee802154_mac_t *mac,
                                               ieee802154_mac_indirect_q_t *indirect_q,
                                               uint8_t slot);
int ieee802154_mac_indirectq_search_slot(ieee802154_mac_indirect_q_t *indirect_q,
                                         const ieee802154_ext_addr_t *dst_addr);
int ieee802154_mac_indirectq_get_slot(ieee802154_mac_indirect_q_t *indirect_q,
                                      const ieee802154_ext_addr_t *dst_addr);
int ieee802154_mac_map_push(ieee802154_mac_t *mac,
                            uint8_t frame_type,
                            ieee802154_addr_mode_t src_mode,
                            ieee802154_addr_mode_t dst_mode,
                            uint16_t *dst_panid,
                            const void *dst_addr,
                            iolist_t *msdu,
                            const uint8_t *msdu_handle,
                            bool ack_req,
                            bool indirect);
int ieee802154_mac_enqueue_data_request(ieee802154_mac_t *mac,
                                        ieee802154_addr_mode_t dst_mode,
                                        uint16_t *dst_panid,
                                        const void *dst_addr);

#ifdef __cplusplus
}
#endif

/** @} */
