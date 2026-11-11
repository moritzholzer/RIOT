/*
 * SPDX-FileCopyrightText: 2026 HAW Hamburg
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

/**
 * @{
 *
 * @file
 * @brief IEEE 802.15.4 MAC finite state machine events and requests.
 * @author Moritz Holzer <moritz.holzer@haw-hamburg.de>
 */

#ifdef __cplusplus
extern "C" {
#endif

#include "net/ieee802154/mac.h"


/**
 * @brief IEEE 802.15.4 MAC FSM events.
 */
typedef enum {
    IEEE802154_MAC_FSM_EV_SCAN_START,        /**< Start a scan */
    IEEE802154_MAC_FSM_EV_SCAN_TIMER,        /**< Scan timer expired */
    IEEE802154_MAC_FSM_EV_SCAN_DONE,         /**< Scan completed */
    IEEE802154_MAC_FSM_EV_ASSOC_REQ_RX,      /**< Association request received */
    IEEE802154_MAC_FSM_EV_ASSOC_RES_RX,      /**< Association response received */
    IEEE802154_MAC_FSM_EV_DISASSOC_RX,       /**< Disassociation notification received */
    IEEE802154_MAC_FSM_EV_COORD_START,       /**< Start coordinator operation */
    IEEE802154_MAC_FSM_EV_MLME_ASSOC_REQ,    /**< MLME association request */
    IEEE802154_MAC_FSM_EV_MLME_POLL,         /**< MLME poll request */
    IEEE802154_MAC_FSM_EV_MLME_ASSOC_RES,    /**< MLME association response */
    IEEE802154_MAC_FSM_EV_ASSOC_TIMEOUT,     /**< Association response timed out */
    IEEE802154_MAC_FSM_EV_TX_REQUEST,        /**< Request frame transmission */
    IEEE802154_MAC_FSM_EV_SLEEP,             /**< Enter sleep state */
    IEEE802154_MAC_FSM_EV_WAKE,              /**< Wake from sleep */
    IEEE802154_MAC_FSM_EV_RX_BEACON,         /**< Beacon frame received */
    IEEE802154_MAC_FSM_EV_RX_DATA,           /**< Data frame received */
    IEEE802154_MAC_FSM_EV_RX_CMD_DATA_REQ,   /**< Data request command received */
    IEEE802154_MAC_FSM_EV_RX_CMD_BEACON_REQ, /**< Beacon request command received */
    IEEE802154_MAC_FSM_EV_RX_CMD_ASSOC_REQ,  /**< Association request command received */
    IEEE802154_MAC_FSM_EV_RX_CMD_ASSOC_RES,  /**< Association response command received */
    IEEE802154_MAC_FSM_EV_RX_CMD_DISASSOC,   /**< Disassociation command received */
    IEEE802154_MAC_FSM_EV_MCPS_DATA_REQ,     /**< MCPS data transmission request */
} ieee802154_mac_fsm_ev_t;

/**
 * @brief Parameters shared by MAC FSM events and requests.
 */
typedef struct {
    iolist_t *buf;                            /**< Received frame buffer */
    const ieee802154_rx_info_t *info;         /**< Received frame metadata */

    ieee802154_ext_addr_t src_addr;           /**< Extended source address */
    uint8_t src[IEEE802154_LONG_ADDRESS_LEN]; /**< Source address bytes */
    le_uint16_t src_pan;                      /**< Source PAN identifier in little-endian byte order */
    int src_len;                              /**< Source address length in bytes */
    ieee802154_addr_mode_t src_mode;          /**< Source address mode */

    uint8_t frame_type;                       /**< Received MAC frame type */
    uint8_t cmd_type;                         /**< Received MAC command identifier */

    uint8_t assoc_status;                     /**< Association response status */
    uint16_t assoc_short_addr;                /**< Short address assigned by the association response */
    ieee802154_assoc_capability_t capability; /**< Association capability information */

    const void *dst_addr;                     /**< Event destination address */
    const void *data_dst_addr;                /**< Destination address for an outgoing request */
    ieee802154_addr_mode_t dst_mode;          /**< Destination address mode */
    uint16_t dst_panid;                       /**< Destination PAN identifier */

    iolist_t *msdu;                           /**< Outgoing MAC service data unit */
    uint8_t msdu_handle;                      /**< Outgoing MSDU handle */
    bool ack_req;                             /**< Whether an acknowledgment is requested */
    bool indirect;                            /**< Whether to use indirect transmission */

    int *result;                              /**< Output status of the requested operation */
} ieee802154_mac_fsm_ctx_t;

/**
 * @brief Handle a MAC FSM event and apply state transitions.
 *
 * @pre The caller must hold the SubMAC mutex.
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] ev       MAC FSM event to process.
 * @param[in] ctx      Event parameters, or NULL for events without parameters.
 * @return 0 on success, or a negative error code on failure.
 */
int ieee802154_mac_fsm_process_ev_ctx(ieee802154_mac_t *mac, ieee802154_mac_fsm_ev_t ev,
                                      const ieee802154_mac_fsm_ctx_t *ctx);

/**
 * @brief Process a MAC FSM event while holding the SubMAC mutex.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] ev       MAC FSM event to process.
 * @param[in] ctx      Event parameters, or NULL for events without parameters.
 * @return 0 on success, or a negative error code on failure.
 */
int ieee802154_mac_fsm_request(ieee802154_mac_t *mac, ieee802154_mac_fsm_ev_t ev,
                               const ieee802154_mac_fsm_ctx_t *ctx);


#ifdef __cplusplus
}
#endif

/** @} */

