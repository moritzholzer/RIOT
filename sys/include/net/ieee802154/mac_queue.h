/*
 * SPDX-FileCopyrightText: 2026 HAW Hamburg
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

/**
 * @{
 *
 * @file
 * @brief IEEE 802.15.4 MAC transmission queue management.
 * @author Moritz Holzer <moritz.holzer@haw-hamburg.de>
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "mutex.h"

#include "net/ieee802154/mac.h"

/**
 * @brief Whether the TX queue is full.
 *
 * @param[in] txq  Transmission queue.
 * @return true if the transmission queue is full, false otherwise.
 */
bool ieee802154_mac_tx_full(const ieee802154_mac_txq_t *txq);

/**
 * @brief Whether the TX queue is empty.
 *
 * @param[in] txq  Transmission queue.
 * @return true if the transmission queue is empty, false otherwise.
 */
bool ieee802154_mac_tx_empty(const ieee802154_mac_txq_t *txq);

/**
 * @brief Reserve a descriptor at the TX queue tail for the caller to fill.
 *
 * @param[in,out] txq  Transmission queue.
 * @return Writable descriptor at the queue tail, or NULL if the queue is NULL or full.
 */
ieee802154_mac_tx_desc_t *ieee802154_mac_tx_reserve(ieee802154_mac_txq_t *txq);

/**
 * @brief Advances TX queue tail to make it visible to the sender.
 *
 * @param[in,out] txq  Transmission queue.
 */
void ieee802154_mac_tx_commit(ieee802154_mac_txq_t *txq);

/**
 * @brief Returns descriptor of TX queue head (next to send), does not remove.
 *
 * @param[in,out] txq  Transmission queue.
 * @return Descriptor at the queue head, or NULL if no queued descriptor is available.
 */
ieee802154_mac_tx_desc_t *ieee802154_mac_tx_peek(ieee802154_mac_txq_t *txq);

/**
 * @brief Removes TX queue head entry.
 *
 * @param[in,out] txq  Transmission queue.
 */
void ieee802154_mac_tx_pop(ieee802154_mac_txq_t *txq);

/**
 * @brief Allocate a slot in the indirect queue.
 *
 * @param[in,out] indirect_q  Indirect transmission queue set.
 * @return Allocated slot index, or -1 if no slot is available.
 */
int ieee802154_indirectq_alloc_slot(ieee802154_mac_indirect_q_t *indirect_q);
/**
 * @brief Free a slot in the indirect queue.
 *
 * @param[in,out] indirect_q  Indirect transmission queue set.
 * @param[in] slot            Queue slot index.
 */
void ieee802154_indirectq_free_slot(ieee802154_mac_indirect_q_t *indirect_q, uint8_t slot);

/**
 * @brief Whether if indirect queue is empty
 *
 * @param[in] indirect_q  Indirect transmission queue set.
 * @return true if all indirect queue slots are free, false otherwise.
 */
bool ieee802154_indirectq_empty(const ieee802154_mac_indirect_q_t *indirect_q);

/**
 * @brief Check for queued frames addressed to a destination.
 *
 * @param[in,out] indirect_q  Indirect transmission queue set.
 * @param[in] dst_mode        Destination address mode.
 * @param[in] dst_addr        Destination address in network byte order; NULL selects an unaddressed queue where supported.
 * @return true if a nonempty queue matches the address, false otherwise.
 */
bool ieee802154_indirectq_has_addr(ieee802154_mac_indirect_q_t *indirect_q,
                                   ieee802154_addr_mode_t dst_mode,
                                   const void *dst_addr);

/**
 * @brief Get the deadline tick for indirect transmission.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @return Expiration time for a newly queued frame in MAC ticks.
 */
uint32_t ieee802154_indirect_get_deadline(ieee802154_mac_t *mac);
/**
 * @brief Check whether a frame is expired.
 *
 * @param[in] now_tick       Current MAC tick counter.
 * @param[in] deadline_tick  Expiration time in MAC ticks.
 * @return true if the deadline has been reached, false otherwise.
 */
bool ieee802154_mac_frame_is_expired(uint32_t now_tick, uint32_t deadline_tick);

/**
 * @brief Record an associated device's extended-to-short address alias.
 *
 * @param[in,out] mac     MAC descriptor or callback context.
 * @param[in] ext_addr    Device extended address.
 * @param[in] short_addr  Device short address in network byte order.
 */
void ieee802154_mac_assoc_update(ieee802154_mac_t *mac,
                                 const ieee802154_ext_addr_t *ext_addr,
                                 ieee802154_short_addr_t short_addr);
/**
 * @brief Update the frame pending bit for a destination address.
 *
 * @param[in,out] mac   MAC descriptor or callback context.
 * @param[in] dst_mode  Destination address mode.
 * @param[in] dst_addr  Destination address in network byte order; NULL selects an unaddressed queue where supported.
 * @param[in] pending   Whether frames are pending for the destination.
 */
void ieee802154_mac_indirect_fp_update(ieee802154_mac_t *mac,
                                       ieee802154_addr_mode_t dst_mode,
                                       const void *dst_addr,
                                       bool pending);
/**
 * @brief Free an empty indirect queue slot or refresh its head deadline.
 *
 * @param[in,out] mac         MAC descriptor or callback context.
 * @param[in,out] indirect_q  Indirect transmission queue set.
 * @param[in] slot            Queue slot index.
 */
void ieee802154_mac_handle_indirectq_auto_free(ieee802154_mac_t *mac,
                                               ieee802154_mac_indirect_q_t *indirect_q,
                                               uint8_t slot);
/**
 * @brief Find an indirect queue slot by destination address.
 *
 * @param[in,out] mac   MAC descriptor or callback context.
 * @param[in] dst_mode  Destination address mode.
 * @param[in] dst_addr  Destination address in network byte order; NULL selects an unaddressed queue where supported.
 * @return Matching slot index, or -1 if no queue matches.
 */
int ieee802154_mac_indirectq_search_slot(ieee802154_mac_t *mac,
                                         ieee802154_addr_mode_t dst_mode,
                                         const void *dst_addr);
/**
 * @brief Find an indirect queue slot by destination address.
 *
 * The caller must hold @ref ieee802154_mac_indirect_q_t::lock.
 *
 * @param[in,out] mac   MAC descriptor or callback context.
 * @param[in] dst_mode  Destination address mode.
 * @param[in] dst_addr  Destination address in network byte order; NULL selects an unaddressed queue where supported.
 * @return Matching slot index, or -1 if no queue matches.
 */
int ieee802154_mac_indirectq_search_slot_locked(ieee802154_mac_t *mac,
                                                ieee802154_addr_mode_t dst_mode,
                                                const void *dst_addr);
/**
 * @brief Find or allocate a queue slot for a destination address.
 *
 * @param[in,out] mac   MAC descriptor or callback context.
 * @param[in] dst_mode  Destination address mode.
 * @param[in] dst_addr  Destination address in network byte order; NULL selects an unaddressed queue where supported.
 * @return Existing or newly allocated slot index, or -1 if no slot is available.
 */
int ieee802154_mac_indirectq_get_slot(ieee802154_mac_t *mac,
                                      ieee802154_addr_mode_t dst_mode,
                                      const void *dst_addr);
/**
 * @brief Enqueue a data frame into the MAC TX queue.
 *
 * @param[in,out] mac      MAC descriptor or callback context.
 * @param[in] frame_type   IEEE 802.15.4 MAC frame type.
 * @param[in] src_mode     Source address mode.
 * @param[in] dst_mode     Destination address mode.
 * @param[in] dst_panid    Destination PAN identifier in host byte order.
 * @param[in] dst_addr     Destination address in network byte order; NULL selects an unaddressed queue where supported.
 * @param[in] msdu         MAC service data unit as an I/O list.
 * @param[in] msdu_handle  MSDU handle returned with transmission confirmation.
 * @param[in] ack_req      Whether to request an acknowledgment.
 * @param[in] indirect     Whether to wait for a data request before transmission.
 * @return 0 on success, -ENOBUFS if no queue space is available, or -EINVAL if header creation fails.
 */
int ieee802154_mac_map_push(ieee802154_mac_t *mac,
                            uint8_t frame_type,
                            ieee802154_addr_mode_t src_mode,
                            ieee802154_addr_mode_t dst_mode,
                            const uint16_t *dst_panid,
                            const void *dst_addr,
                            iolist_t *msdu,
                            const uint8_t *msdu_handle,
                            bool ack_req,
                            bool indirect);
/**
 * @brief Enqueue a data request command.
 *
 * @param[in,out] mac    MAC descriptor or callback context.
 * @param[in] dst_mode   Destination address mode.
 * @param[in] dst_panid  Destination PAN identifier in host byte order.
 * @param[in] dst_addr   Destination address in network byte order; NULL selects an unaddressed queue where supported.
 * @return 0. The current implementation does not propagate enqueue errors.
 */
int ieee802154_mac_enqueue_data_request(ieee802154_mac_t *mac,
                                        ieee802154_addr_mode_t dst_mode,
                                        uint16_t *dst_panid,
                                        const void *dst_addr);
/**
 * @brief Enqueue a beacon request command.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @return 0. The current implementation does not propagate enqueue errors.
 */
int ieee802154_mac_enqueue_beacon_request(ieee802154_mac_t *mac);

#ifdef __cplusplus
}
#endif

/** @} */
