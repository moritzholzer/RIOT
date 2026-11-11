/*
 * SPDX-FileCopyrightText: 2026 HAW Hamburg
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#pragma once

/**
 * @{
 *
 * @file
 * @brief IEEE 802.15.4 MAC types, configuration, callbacks, and requests.
 * @author Moritz Holzer <moritz.holzer@haw-hamburg.de>
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "ztimer.h"
#include "iolist.h"
#include "kernel_defines.h"

#include "net/ieee802154.h"
#include "net/ieee802154/submac.h"
#include "net/ieee802154/radio.h"

/**
 * @brief Enable indirect MAC transmissions.
 */
#define IEEE802154_MAC_INDIRECT_ENABLE

#if IS_USED(MODULE_ESP_IEEE802154)
/**
 * @brief Radio supports hardware source address matching.
 */
#  define IEEE802154_MAC_HAS_SRC_ADDR_MATCH
#endif

#ifdef IEEE802154_MAC_INDIRECT_ENABLE
#  ifndef IEEE802154_MAC_HAS_SRC_ADDR_MATCH
/**
 * @brief Use software acknowledgments when hardware source address matching is unavailable.
 */
#    define IEEE802154_MAC_FORCE_SOFT_ACK
#  endif
#endif

#ifndef IEEE802154_SCAN_BEACON_PAYLOAD_MAX
/**
 * @brief Maximum stored beacon payload size in bytes.
 */
#  define IEEE802154_SCAN_BEACON_PAYLOAD_MAX  (IEEE802154_FRAME_LEN_MAX)
#endif

#ifndef CONFIG_IEEE802154_MAC_TXQ_LEN
/**
 * @brief Maximum number of frames in each destination queue.
 */
#  define CONFIG_IEEE802154_MAC_TXQ_LEN   (4U)
#endif
#ifndef IEEE802154_MAC_TXQ_LEN
#  define IEEE802154_MAC_TXQ_LEN   CONFIG_IEEE802154_MAC_TXQ_LEN
#endif

#ifndef CONFIG_IEEE802154_MAC_TICK_INTERVAL_MS
/**
 * @brief MAC maintenance tick interval in milliseconds.
 */
#  define CONFIG_IEEE802154_MAC_TICK_INTERVAL_MS     (1U)
#endif
#ifndef IEEE802154_MAC_TICK_INTERVAL_MS
#  define IEEE802154_MAC_TICK_INTERVAL_MS     CONFIG_IEEE802154_MAC_TICK_INTERVAL_MS
#endif

#ifndef CONFIG_IEEE802154_MAC_FRAME_TIMEOUT
/**
 * @brief Queued frame lifetime in PHY symbols.
 */
#  define CONFIG_IEEE802154_MAC_FRAME_TIMEOUT        (125000U)
#endif
#ifndef IEEE802154_MAC_FRAME_TIMEOUT
#  define IEEE802154_MAC_FRAME_TIMEOUT        CONFIG_IEEE802154_MAC_FRAME_TIMEOUT
#endif

#ifndef CONFIG_IEEE802154_MAC_TX_INDIRECTQ_SIZE
/**
 * @brief Number of destination queue slots.
 */
#  define CONFIG_IEEE802154_MAC_TX_INDIRECTQ_SIZE     (4)
#endif
#ifndef IEEE802154_MAC_TX_INDIRECTQ_SIZE
#  define IEEE802154_MAC_TX_INDIRECTQ_SIZE     CONFIG_IEEE802154_MAC_TX_INDIRECTQ_SIZE
#endif

#ifndef CONFIG_IEEE802154_MAC_ASSOC_TABLE_SIZE
/**
 * @brief Maximum number of associated device address aliases.
 */
#  define CONFIG_IEEE802154_MAC_ASSOC_TABLE_SIZE      (IEEE802154_MAC_TX_INDIRECTQ_SIZE)
#endif
#ifndef IEEE802154_MAC_ASSOC_TABLE_SIZE
#  define IEEE802154_MAC_ASSOC_TABLE_SIZE      CONFIG_IEEE802154_MAC_ASSOC_TABLE_SIZE
#endif

#ifndef CONFIG_IEEE802154_MAC_BASE_SLOT_DURATION
/**
 * @brief Base superframe slot duration in symbols.
 */
#  define CONFIG_IEEE802154_MAC_BASE_SLOT_DURATION   (60U)
#endif
#ifndef IEEE802154_MAC_BASE_SLOT_DURATION
#  define IEEE802154_MAC_BASE_SLOT_DURATION   CONFIG_IEEE802154_MAC_BASE_SLOT_DURATION
#endif

#ifndef CONFIG_IEEE802154_MAC_MAX_LOST_BEACONS
/**
 * @brief Maximum number of consecutive lost beacons.
 */
#  define CONFIG_IEEE802154_MAC_MAX_LOST_BEACONS   (4U)
#endif
#ifndef IEEE802154_MAC_MAX_LOST_BEACONS
#  define IEEE802154_MAC_MAX_LOST_BEACONS   CONFIG_IEEE802154_MAC_MAX_LOST_BEACONS
#endif

#ifndef CONFIG_IEEE802154_MAC_MIN_CAP_LENGTH
/**
 * @brief Minimum contention access period length in symbols.
 */
#  define CONFIG_IEEE802154_MAC_MIN_CAP_LENGTH   (440U)
#endif
#ifndef IEEE802154_MAC_MIN_CAP_LENGTH
#  define IEEE802154_MAC_MIN_CAP_LENGTH   CONFIG_IEEE802154_MAC_MIN_CAP_LENGTH
#endif

#ifndef CONFIG_IEEE802154_MAC_NUM_SUPERFRAME_SLOTS
/**
 * @brief Number of slots in a superframe.
 */
#  define CONFIG_IEEE802154_MAC_NUM_SUPERFRAME_SLOTS     (16)
#endif
#ifndef IEEE802154_MAC_NUM_SUPERFRAME_SLOTS
#  define IEEE802154_MAC_NUM_SUPERFRAME_SLOTS     CONFIG_IEEE802154_MAC_NUM_SUPERFRAME_SLOTS
#endif

#ifndef IEEE802154_MAC_BASE_SUPERFRAME_DURATION
/**
 * @brief Base superframe duration in symbols.
 */
#  define IEEE802154_MAC_BASE_SUPERFRAME_DURATION   (IEEE802154_MAC_BASE_SLOT_DURATION * \
                                                   IEEE802154_MAC_NUM_SUPERFRAME_SLOTS)
#endif

#ifndef CONFIG_IEEE802154_MAC_RX_RETRY_MAX
/**
 * @brief Maximum number of retries per RX recovery attempt.
 */
#  define CONFIG_IEEE802154_MAC_RX_RETRY_MAX   (4U)
#endif
#ifndef IEEE802154_MAC_RX_RETRY_MAX
#  define IEEE802154_MAC_RX_RETRY_MAX   CONFIG_IEEE802154_MAC_RX_RETRY_MAX
#endif

/**
 * @brief IEEE 802.15.4 extended adress
 */
typedef eui64_t ieee802154_ext_addr_t;
/**
 * @brief IEEE 802.15.4 MAC short address
 */
typedef network_uint16_t ieee802154_short_addr_t;

/**
 * @brief IEEE 802.15.4 octet (bytes) with len.
 */
typedef struct {
    const uint8_t *ptr; /**< Octet buffer */
    size_t len;         /**< Buffer length in bytes */
} ieee802154_octets_t;

/**
 * @brief IEEE 802.15.4 MAC PIB.
 */
typedef struct {
    uint16_t PAN_ID;                              /**< PAN identifier */
    ieee802154_ext_addr_t EXTENDED_ADDRESS;       /**< Device extended address */
    ieee802154_short_addr_t SHORT_ADDR;           /**< Device short address in network byte order */
    ieee802154_ext_addr_t COORD_EXTENDED_ADDRESS; /**< Coordinator extended address */
    ieee802154_short_addr_t COORD_SHORT_ADDRESS;  /**< Coordinator short address */

    uint8_t BEACON_ORDER;                         /**< Beacon transmission interval order */
    ieee802154_octets_t BEACON_PAYLOAD;           /**< Beacon payload buffer and length */
    uint8_t BSN;                                  /**< Beacon sequence number */
    bool AUTO_REQUEST;                            /**< Enable automatic data requests after beacons */
    bool NOTIFY_ALL_BEACONS;                      /**< Notify the upper layer of all received beacons */

    uint8_t DSN;                                  /**< Data sequence number */
    uint8_t FCS_TYPE;                             /**< Frame check sequence type */

    uint8_t MIN_BE;                               /**< Minimum CSMA-CA backoff exponent */
    uint8_t MAX_BE;                               /**< Maximum CSMA-CA backoff exponent */
    uint8_t MAX_CSMA_BACKOFFS;                    /**< Maximum number of CSMA-CA backoffs */
    uint16_t UNIT_BACKOFF_PERIOD;                 /**< Unit backoff period in symbols */

    uint16_t LIFS_PERIOD;                         /**< Long interframe spacing in symbols */
    uint16_t SIFS_PERIOD;                         /**< Short interframe spacing in symbols */
    uint16_t SYNC_SYMBOL_OFFSET;                  /**< Synchronization offset in symbols */
    uint8_t RESPONSE_WAIT_TIME;                   /**< Response wait time in base superframe durations */
    uint16_t TRANSACTION_PERSISTENCE_TIME;        /**< Transaction persistence time in base superframe durations */

    bool BATT_LIFE_EXT;                           /**< Enable battery life extension */
    uint16_t BATT_LIFE_EXT_PERIODS;               /**< Battery life extension duration in backoff periods */

    bool RX_ON_WHEN_IDLE;                         /**< Keep the receiver enabled when idle */
    bool GROUP_RX_MODE;                           /**< Enable group receive mode */
    bool IMPLICIT_BROADCAST;                      /**< Enable implicit broadcasts */
    bool GTS_PERMIT;                              /**< Permit guaranteed time slot requests */

    bool AOA_ENABLE;                              /**< Enable angle-of-arrival measurements */
    bool TIMESTAMP_SUPPORTED;                     /**< Whether timestamping is supported */
    bool SECURITY_ENABLED;                        /**< Enable MAC security */
} ieee802154_pib_t;

/**
 * @brief IEEE 802.15.4 MAC PIB Attributes.
 */
typedef enum {
    IEEE802154_PIB_AOA_ENABLE,                   /**< Angle-of-arrival measurement enable */
    IEEE802154_PIB_AUTO_REQUEST,                 /**< Automatic data request enable */
    IEEE802154_PIB_BATT_LIFE_EXT,                /**< Battery life extension enable */
    IEEE802154_PIB_BATT_LIFE_EXT_PERIODS,        /**< Battery life extension duration */
    IEEE802154_PIB_BEACON_ORDER,                 /**< Beacon interval order */
    IEEE802154_PIB_BEACON_PAYLOAD,               /**< Beacon payload */
    IEEE802154_PIB_BSN,                          /**< Beacon sequence number */
    IEEE802154_PIB_COORD_EXTENDED_ADDRESS,       /**< Coordinator extended address */
    IEEE802154_PIB_COORD_SHORT_ADDRESS,          /**< Coordinator short address */
    IEEE802154_PIB_DSN,                          /**< Data sequence number */
    IEEE802154_PIB_EXTENDED_ADDRESS,             /**< Device extended address */
    IEEE802154_PIB_FCS_TYPE,                     /**< Frame check sequence type */
    IEEE802154_PIB_GROUP_RX_MODE,                /**< Group receive mode enable */
    IEEE802154_PIB_GTS_PERMIT,                   /**< Guaranteed time slot request permission */
    IEEE802154_PIB_IMPLICIT_BROADCAST,           /**< Implicit broadcast enable */
    IEEE802154_PIB_LIFS_PERIOD,                  /**< Long interframe spacing */
    IEEE802154_PIB_MAX_BE,                       /**< Maximum CSMA-CA backoff exponent */
    IEEE802154_PIB_MAX_CSMA_BACKOFFS,            /**< Maximum number of CSMA-CA backoffs */
    IEEE802154_PIB_NOTIFY_ALL_BEACONS,           /**< Notification of all received beacons */
    IEEE802154_PIB_MIN_BE,                       /**< Minimum CSMA-CA backoff exponent */
    IEEE802154_PIB_PAN_ID,                       /**< PAN identifier */
    IEEE802154_PIB_RESPONSE_WAIT_TIME,           /**< Response wait time */
    IEEE802154_PIB_RX_ON_WHEN_IDLE,              /**< Idle receiver enable */
    IEEE802154_PIB_SECURITY_ENABLED,             /**< MAC security enable */
    IEEE802154_PIB_SHORT_ADDR,                   /**< Device short address */
    IEEE802154_PIB_SIFS_PERIOD,                  /**< Short interframe spacing */
    IEEE802154_PIB_SYNC_SYMBOL_OFFSET,           /**< Synchronization symbol offset */
    IEEE802154_PIB_TIMESTAMP_SUPPORTED,          /**< Timestamp support */
    IEEE802154_PIB_TRANSACTION_PERSISTENCE_TIME, /**< Transaction persistence time */
    IEEE802154_PIB_UNIT_BACKOFF_PERIOD,          /**< Unit backoff period */
    IEEE802154_PIB_ATTR_COUNT                    /**< Number of PIB attributes */
} ieee802154_pib_attr_t;

/**
 * @brief IEEE 802.15.4 MAC PIB data types.
 */
typedef enum {
    IEEE802154_PIB_TYPE_BOOL,  /**< bool */
    IEEE802154_PIB_TYPE_U8,    /**< uint8_t */
    IEEE802154_PIB_TYPE_U16,   /**< uint16_t */
    IEEE802154_PIB_TYPE_EUI64, /**< ext address in ieee802154_ext_addr_t */
    IEEE802154_PIB_TYPE_NUI16, /**< short address in ieee802154_short_addr_t */
    IEEE802154_PIB_TYPE_BYTES  /**< octets in  ieee802154_octets_t*/
} ieee802154_pib_type_t;

/**
 * @brief IEEE 802.15.4 device type identifier.
 */
typedef enum {
    IEEE802154_DEV_TYPE_CC2538_RF,      /**< CC2538 radio */
    IEEE802154_DEV_TYPE_NRF802154,      /**< Nordic IEEE 802.15.4 radio */
    IEEE802154_DEV_TYPE_SOCKET_ZEP,     /**< Socket-based ZEP radio */
    IEEE802154_DEV_TYPE_KW2XRF,         /**< KW2x radio */
    IEEE802154_DEV_TYPE_MRF24J40,       /**< MRF24J40 radio */
    IEEE802154_DEV_TYPE_ESP_IEEE802154, /**< Espressif IEEE 802.15.4 radio */
    IEEE802154_DEV_TYPE_INVALID,        /**< Invalid radio device type */
} ieee802154_dev_type_t;

/**
 * @brief IEEE 802.15.4 address mode.
 */
typedef enum {
    IEEE802154_ADDR_MODE_NONE,    /**< No address */
    IEEE802154_ADDR_MODE_SHORT,   /**< 16-bit short address */
    IEEE802154_ADDR_MODE_EXTENDED /**< 64-bit extended address */
} ieee802154_addr_mode_t;

/**
 * @brief IEEE 802.15.4 address container.
 */
typedef struct {
    ieee802154_addr_mode_t type;            /**< Address mode selecting the union member */
    union {
        ieee802154_ext_addr_t ext_addr;     /**< Extended address */
        ieee802154_short_addr_t short_addr; /**< Short address */
    } v;                                    /**< Address value */
} ieee802154_addr_t;

/**
 * @brief IEEE 802.15.4 PIB attribute value.
 */
typedef struct {
    ieee802154_pib_type_t type;             /**< Data type selecting the union member */
    union {
        bool b;                             /**< Boolean value */
        uint8_t u8;                         /**< Unsigned 8-bit value */
        uint16_t u16;                       /**< Unsigned 16-bit value */
        ieee802154_octets_t bytes;          /**< Octet buffer and length */
        ieee802154_ext_addr_t ext_addr;     /**< Extended address value */
        ieee802154_short_addr_t short_addr; /**< Short address value in network byte order */
    } v;                                    /**< Attribute value */
} ieee802154_pib_value_t;

/**
 * @brief IEEE 802.15.4 PIB attribute access type.
 */
typedef enum {
    IEEE802154_PIB_ACC_RW, /**< Read and write access */
    IEEE802154_PIB_ACC_RO  /**< Read-only access */
} ieee802154_pib_access_t;

/**
 * @brief IEEE 802.15.4 PIB attribute entry metadata.
 */
typedef struct {
    ieee802154_pib_type_t type;     /**< Attribute data type */
    ieee802154_pib_access_t access; /**< Attribute access permissions */

    uint16_t offset;                /**< Byte offset within ieee802154_pib_t */
    uint16_t size;                  /**< Attribute size in bytes */

    ieee802154_pib_value_t def;     /**< Default attribute value */
    ieee802154_pib_value_t min;     /**< Minimum attribute value */
    ieee802154_pib_value_t max;     /**< Maximum attribute value */
} ieee802154_pib_attr_entry_t;

/**
 * @brief IEEE 802.15.4 MAC MCPS-DATA.confirm callback.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] handle   Request or MSDU handle supplied by the caller.
 * @param[in] status   Operation completion status.
 */
typedef void (*ieee802154_mcps_data_confirm_cb_t)(void *mac, uint8_t handle, int status);

/**
 * @brief IEEE 802.15.4 MAC MCPS-DATA.indication callback.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] msdu     MAC service data unit as an I/O list.
 * @param[in] info     Received frame metadata.
 */
typedef void (*ieee802154_mcps_data_indication_cb_t)(void *mac, iolist_t *msdu,
                                                     const ieee802154_rx_info_t *info);

/**
 * @brief IEEE 802.15.4 scan result entry.
 */
typedef struct {
    uint16_t channel;                                           /**< Channel on which the beacon was received */
    uint16_t pan_id;                                            /**< PAN identifier from the beacon */
    ieee802154_addr_t coord_addr;                               /**< Coordinator address */

    uint8_t lqi;                                                /**< Received beacon link quality indicator */
    uint8_t rssi;                                               /**< Received beacon signal strength indicator */

    uint8_t beacon_payload_len;                                 /**< Stored beacon payload length in bytes */
    uint8_t beacon_payload[IEEE802154_SCAN_BEACON_PAYLOAD_MAX]; /**< Stored beacon payload */
} ieee802154_scan_result_t;

/**
 * @brief IEEE 802.15.4 scan request parameters.
 */
typedef struct {
    const uint16_t *channels;          /**< Channels to scan */
    uint8_t channel_count;             /**< Number of channels to scan */
    uint32_t duration;                 /**< Scan duration per channel in symbols */

    ieee802154_scan_result_t *results; /**< Scan result buffer */
    size_t results_len;                /**< Capacity of the result buffer in entries */
    size_t *results_used;              /**< Output number of stored results */
} ieee802154_mlme_scan_req_t;

/**
 * @brief IEEE 802.15.4 association capability information.
 */
typedef union {
    uint8_t u8;                          /**< Raw capability octet */
    struct {
        uint8_t reserved0 : 1;           /**< Reserved bit */
        uint8_t device_type : 1;         /**< Device type: 1 for FFD, 0 for RFD */
        uint8_t power_source : 1;        /**< Whether the device uses mains power */
        uint8_t rx_on_when_idle : 1;     /**< Whether the receiver stays enabled when idle */
        uint8_t association_type : 1;    /**< Association type capability bit */
        uint8_t suspendable_csma_ca : 1; /**< Whether CSMA-CA can be suspended */
        uint8_t security_capability : 1; /**< Whether MAC security is supported */
        uint8_t allocate_address : 1;    /**< Request allocation of a short address */
    } bits;                              /**< Individual capability bits */
} ieee802154_assoc_capability_t;

/**
 * @brief IEEE 802.15.4 association status.
 */
typedef enum {
    IEEE802154_ASSOC_STATUS_SUCCESS = 0,           /**< Association succeeded */
    IEEE802154_ASSOC_STATUS_PAN_AT_CAPACITY = 1,   /**< PAN cannot accept more devices */
    IEEE802154_ASSOC_STATUS_PAN_ACCESS_DENIED = 2, /**< Association denied by the coordinator */
} ieee802154_assoc_status_t;

/**
 * @brief IEEE 802.15.4 MAC MLME-SCAN.confirm callback.
 *
 * @param[in,out] mac      MAC descriptor or callback context.
 * @param[in] status       Operation completion status.
 * @param[in,out] request  Completed scan request and result storage.
 */
typedef void (*ieee802154_mlme_scan_confirm_cb_t)(void *mac, int status,
                                                  ieee802154_mlme_scan_req_t *request);

/* === MLME confirm callback types === */

/**
 * @brief IEEE 802.15.4 MAC MLME-SET.confirm callback.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] handle   Request or MSDU handle supplied by the caller.
 * @param[in] status   Operation completion status.
 * @param[in] attr     PIB attribute identifier.
 */
typedef void (*ieee802154_mlme_set_confirm_cb_t)(void *mac,
                                                 uint8_t handle,
                                                 int status,
                                                 ieee802154_pib_attr_t attr);

/**
 * @brief IEEE 802.15.4 MAC MLME-GET.confirm callback.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] handle   Request or MSDU handle supplied by the caller.
 * @param[in] status   Operation completion status.
 * @param[in] attr     PIB attribute identifier.
 * @param[in] value    PIB attribute value.
 */
typedef void (*ieee802154_mlme_get_confirm_cb_t)(void *mac,
                                                 uint8_t handle,
                                                 int status,
                                                 ieee802154_pib_attr_t attr,
                                                 ieee802154_pib_value_t value);

/**
 * @brief IEEE 802.15.4 MAC MLME-START.confirm callback.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] handle   Request or MSDU handle supplied by the caller.
 * @param[in] status   Operation completion status.
 */
typedef void (*ieee802154_mlme_start_confirm_cb_t)(void *mac,
                                                   uint8_t handle,
                                                   int status);

/**
 * @brief IEEE 802.15.4 MAC MLME-ASSOCIATE.indication callback.
 *
 * @param[in,out] mac           MAC descriptor or callback context.
 * @param[in] device_addr       Associating device address bytes.
 * @param[in] device_addr_len   Device address length in bytes.
 * @param[in] device_addr_mode  Device address mode.
 * @param[in] cap               Associating device capability information.
 */
typedef void (*ieee802154_mlme_associate_indication_cb_t)(void *mac,
                                                          const uint8_t *device_addr,
                                                          uint8_t device_addr_len,
                                                          ieee802154_addr_mode_t device_addr_mode,
                                                          ieee802154_assoc_capability_t cap);

/**
 * @brief IEEE 802.15.4 MAC MLME-ASSOCIATE.confirm callback.
 *
 * @param[in,out] mac     MAC descriptor or callback context.
 * @param[in] status      Operation completion status.
 * @param[in] short_addr  Assigned short address.
 */
typedef void (*ieee802154_mlme_associate_confirm_cb_t)(void *mac,
                                                       int status,
                                                       uint16_t short_addr);

/**
 * @brief IEEE 802.15.4 MAC ACK timeout callback.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 */
typedef void (*ieee802154_mac_ack_timeout_fired_cb_t)(void *mac);

/**
 * @brief IEEE 802.15.4 MAC bottom-half request callback.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 */
typedef void (*ieee802154_mac_bh_request_cb_t)(void *mac);

/* === RADIO callbacks === */
/**
 * @brief IEEE 802.15.4 MAC radio event callback.
 *
 * @param[in,out] dev  Radio device descriptor.
 * @param[in] st       Radio event to process.
 */
typedef void (*ieee802154_radio_cb_request_t)(ieee802154_dev_t *dev, ieee802154_trx_ev_t st);

/* === Transmission callbacks === */
/**
 * @brief IEEE 802.15.4 MAC tick callback.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 */
typedef void (*ieee802154_mac_tick_t)(void *mac);
/**
 * @brief IEEE 802.15.4 MAC scan timer request callback.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 */
typedef void (*ieee802154_mac_scan_timer_request_t)(void *mac);
/**
 * @brief IEEE 802.15.4 MAC allocate request callback.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] len      Required buffer size in bytes.
 */
typedef void (*ieee802154_mac_allocate_request_t)(void *mac, size_t len);
/**
 * @brief Schedule @ref ieee802154_mac_rx_request_process in thread context.
 *
 * @param[in] mac  Pointer to the IEEE 802.15.4 MAC descriptor.
 */
typedef void (*ieee802154_mac_rx_request_t)(void *mac);
/**
 * @brief IEEE 802.15.4 MAC deallocation request callback.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] iolist   I/O list to release.
 */
typedef void (*ieee802154_mac_dealloc_request_t)(void *mac, iolist_t *iolist);

/**
 * @brief IEEE 802.15.4 MAC callbacks.
 */
typedef struct {
    ieee802154_mcps_data_confirm_cb_t data_confirm;                      /**< MCPS-DATA.confirm callback*/
    ieee802154_mcps_data_indication_cb_t data_indication;                /**< MCPS-DATA.indication callback*/

    ieee802154_mlme_scan_confirm_cb_t mlme_scan_confirm;                 /**< MLME-SCAN.confirm callback */
    ieee802154_mlme_start_confirm_cb_t mlme_start_confirm;               /**< MLME-START.confirm callback */
    ieee802154_mlme_associate_indication_cb_t mlme_associate_indication; /**< MLME-ASSOCIATE.indication callback */
    ieee802154_mlme_associate_confirm_cb_t mlme_associate_confirm;       /**< MLME-ASSOCIATE.confirm callback */

    ieee802154_mac_ack_timeout_fired_cb_t ack_timeout;                   /**< ieee802154_mac_ack_timeout_fired() should be dispatched */
    ieee802154_radio_cb_request_t radio_cb_request;                      /**< ieee802154_mac_handle_radio() should be dispatched */
    ieee802154_mac_scan_timer_request_t scan_timer_request;              /**< ieee802154_mac_scan_timer_process() should be dispatched */
    ieee802154_mac_tick_t tick_request;                                  /**< ieee802154_mac_tick() should be dispatched */

    ieee802154_mac_allocate_request_t allocate_request;                  /**< allocate TX queue entry ieee802154_mac_tx_process() should be dispatched */
    ieee802154_mac_dealloc_request_t dealloc_request;                    /**< release TX queue entry */
    ieee802154_mac_rx_request_t rx_request;                              /**< RX request from MAC */
} ieee802154_mac_cbs_t;

/**
 * @brief IEEE 802.15.4 MAC global state.
 */
typedef enum {
    IEEE802154_MAC_STATE_IDLE,        /**< Idle MAC */
    IEEE802154_MAC_STATE_SCAN_ACTIVE, /**< Active channel scan */
    IEEE802154_MAC_STATE_ASSOCIATING, /**< Association in progress */
    IEEE802154_MAC_STATE_COORDINATOR, /**< Operating as coordinator */
    IEEE802154_MAC_STATE_DEVICE,      /**< Operating as an associated device */
    IEEE802154_MAC_STATE_SLEEP,       /**< Sleeping MAC */
    IEEE802154_MAC_STATE_INVALID,     /**< Invalid MAC state */
} ieee802154_mac_state_t;

/**
 * @brief IEEE 802.15.4 MAC TX descriptor state.
 */
typedef enum {
    IEEE802154_TX_STATE_QUEUED,      /**< Frame queued for transmission */
    IEEE802154_TX_STATE_IN_PROGRESS, /**< Frame transmission in progress */
    IEEE802154_TX_STATE_DONE,        /**< Frame transmission completed */
} ieee802154_tx_state_t;

/**
 * @brief IEEE 802.15.4 MAC TX descriptor.
 */
typedef struct {
    bool in_use;                         /**< wheather ring buffer element is in use */
    uint8_t handle;                      /**< the MSDU handle */
    uint8_t type;                        /**< MAC frame type */
    ieee802154_tx_state_t tx_state;      /**< current TX state */

    bool indirect;                       /**< Whether transmission waits for a data request */
    bool ack;                            /**< Whether an acknowledgment is requested */
    uint32_t deadline_tick;              /**< Frame expiration time in MAC ticks */

    uint8_t mhr[IEEE802154_MAX_HDR_LEN]; /**< persistent header storage */
    iolist_t iol_mhr;                    /**< persistent mhr */
    iolist_t *iol_msdu;                  /**< iolist nodes */
} ieee802154_mac_tx_desc_t;

/**
 * @brief IEEE 802.15.4 MAC TX queue.
 */
typedef struct {
    ieee802154_mac_tx_desc_t q[IEEE802154_MAC_TXQ_LEN]; /**< outgoing queue */

    ieee802154_ext_addr_t dst_ext_addr;                 /**< key or destination extended addr */
    ieee802154_short_addr_t dst_short_addr;             /**< destination short addr (network order) */
    ieee802154_addr_mode_t key_mode;                    /**< key type for queue matching */
    ieee802154_addr_mode_t dst_mode;                    /**< destination addr mode for frame */
    bool has_dst_addr;                                  /**< Whether a destination address is configured */

    uint8_t head;                                       /**< queue head */
    uint8_t tail;                                       /**< queue tail */
    uint8_t cnt;                                        /**< queue count */

    uint32_t *deadline_tick;                            /**< Pointer to the head frame expiration time in MAC ticks */
} ieee802154_mac_txq_t;

/**
 * @brief IEEE 802.15.4 MAC indirect transmission queue.
 */
typedef struct {
    ieee802154_mac_txq_t q[IEEE802154_MAC_TX_INDIRECTQ_SIZE]; /**< Per-destination transmission queues */
    uint32_t free_mask;                                       /**< Bit mask of available queue slots */

    ieee802154_mac_txq_t *current_txq;                        /**< Queue selected for the current transmission */
    unsigned current_slot;                                    /**< Slot index of the current transmission queue */
    bool busy;                                                /**< Whether a transmission is in progress */

    uint32_t tick;                                            /**< Current MAC tick counter */

    mutex_t lock;                                             /**< Mutex protecting the indirect queues */
} ieee802154_mac_indirect_q_t;

/**
 * @brief IEEE 802.15.4 association address alias entry.
 */
typedef struct {
    ieee802154_ext_addr_t ext_addr;     /**< Associated device extended address */
    ieee802154_short_addr_t short_addr; /**< Associated device short address */

    bool valid;                         /**< Whether this alias entry is valid */
} ieee802154_mac_assoc_entry_t;

/**
 * @brief IEEE 802.15.4 MAC descriptor
 */
typedef struct {
    bool is_coordinator;                                                       /**< Whether the MAC acts as a coordinator */
    ieee802154_mac_state_t state;                                              /**< Current MAC state */
    ieee802154_mac_state_t state_history;                                      /**< Saved MAC state for restoration after a temporary state */
    ieee802154_dev_type_t dev_type;                                            /**< Radio device type */

    ieee802154_pib_t pib;                                                      /**< PIB of the MAC */
    mutex_t pib_lock;                                                          /**< Mutex protecting PIB access */

    ieee802154_submac_t submac;                                                /**< SubMAC descriptor */
    mutex_t submac_lock;                                                       /**< Mutex protecting SubMAC access */

    ieee802154_mac_cbs_t cbs;                                                  /**< callbacks for the SubMAC */

    ztimer_t ack_timer;                                                        /**< timer for ACK timeout */
    ztimer_t tick;                                                             /**< tick for frame timeouts */
    uint16_t sym_us;                                                           /**< PHY symbol duration in microseconds */

    uint8_t cmd_buf[IEEE802154_FRAME_LEN_MAX];                                 /**< receiving buf */
    iolist_t cmd;                                                              /**< I/O list node for the command buffer */

    ieee802154_mac_indirect_q_t indirect_q;                                    /**< Indirect transmission queues and scheduling state */
    ieee802154_mac_assoc_entry_t assoc_table[IEEE802154_MAC_ASSOC_TABLE_SIZE]; /**< Associated device address aliases */

    ieee802154_mlme_scan_req_t *scan_req;                                      /**< Current scan request */
    bool scan_active;                                                          /**< Whether a scan is in progress */
    uint8_t scan_idx;                                                          /**< Index of the channel currently being scanned */
    ztimer_t scan_timer;                                                       /**< Timer for the per-channel scan duration */
    bool scan_timer_pending;                                                   /**< Whether scan timer processing is pending */

    bool assoc_pending;                                                        /**< Whether an association response is pending */
    uint32_t assoc_deadline_tick;                                              /**< Association response deadline in MAC ticks */

    bool poll_rx_active;                                                       /**< Whether reception after a data poll is active */
    uint32_t poll_rx_deadline;                                                 /**< Reception deadline after a data poll in MAC ticks */

    uint8_t rx_retry_count;                                                    /**< Number of RX recovery retries */
    bool rx_retry_pending;                                                     /**< Whether an RX recovery retry is pending */
} ieee802154_mac_t;

/**
 * @brief IEEE 802.15.4 scan type.
 */
typedef enum {
    IEEE802154_SCAN_ACTIVE,  /**< Scan by transmitting beacon requests */
    IEEE802154_SCAN_PASSIVE, /**< Scan by listening for beacons */
    IEEE802154_SCAN_ED,      /**< Energy detection scan */
} ieee802154_scan_type_t;

/* === Function that has to be dispatched and called on callbacks */

/**
 * @brief Has to be called from thread context when ieee802154_mac_ack_timeout_fired_cb_t is called.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 */
void ieee802154_mac_ack_timeout_fired(ieee802154_mac_t *mac);

/**
 * @brief Has to be called from thread context when ieee802154_radio_cb_request_t is called.
 *
 * @param[in,out] dev  Radio device descriptor.
 * @param[in] st       Radio event to process.
 */
void ieee802154_mac_handle_radio(ieee802154_dev_t *dev, ieee802154_trx_ev_t st);

/**
 * @brief Read and process a received MAC frame.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in,out] buf  Buffer for the received frame.
 */
void ieee802154_mac_rx_process(ieee802154_mac_t *mac, iolist_t *buf);

/**
 * @brief Handle periodic MAC tick.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 */
void ieee802154_mac_tick(ieee802154_mac_t *mac);

/**
 * @brief Process the active scan timer in thread context.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 */
void ieee802154_mac_scan_timer_process(ieee802154_mac_t *mac);

/**
 * @brief Process an RX request in thread context.
 *
 * Reschedule busy RX requests through the RX request callback, up to
 * IEEE802154_MAC_RX_RETRY_MAX times per recovery attempt.
 *
 * @param[in] mac  Pointer to the MAC descriptor.
 */
void ieee802154_mac_rx_request_process(ieee802154_mac_t *mac);

/**
 * @brief Init the IEEE 802.15.4 MAC
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] cbs      MAC callback set.
 */
void ieee802154_mac_init(ieee802154_mac_t *mac,
                         const ieee802154_mac_cbs_t *cbs);

/**
 * @brief Initialize IEEE 802.15.4 MAC with explicit radio type
 *
 * @param[in] mac       pointer to MAC descriptor
 * @param[in] cbs       callback set
 * @param[in] dev_type  radio type to initialize
 */
void ieee802154_mac_init_with_devtype(ieee802154_mac_t *mac,
                                      const ieee802154_mac_cbs_t *cbs,
                                      ieee802154_dev_type_t dev_type);

/**
 * @brief Issue a MAC scan request.
 *
 * @note The current implementation ignores the scan type and performs an active scan.
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] type     Requested scan type.
 * @param[in,out] req  Scan parameters and result storage; keep valid until scan completion.
 * @return 0 on success, or a negative error code on failure.
 */
int ieee802154_mac_mlme_scan_request(ieee802154_mac_t *mac, ieee802154_scan_type_t type,
                                     ieee802154_mlme_scan_req_t *req);
/**
 * @brief Issue a MAC MLME-SET request.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] attr     PIB attribute identifier.
 * @param[in] in       New attribute value with the matching PIB data type.
 */
void ieee802154_mac_mlme_set_request(ieee802154_mac_t *mac,
                                     ieee802154_pib_attr_t attr,
                                     const ieee802154_pib_value_t *in);
/**
 * @brief Issue a MAC MLME-GET request.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] attr     PIB attribute identifier.
 * @param[out] out     Storage for the attribute type and value.
 */
void ieee802154_mac_mlme_get_request(ieee802154_mac_t *mac,
                                     ieee802154_pib_attr_t attr,
                                     ieee802154_pib_value_t *out);
/**
 * @brief Issue a MAC MLME-START request.
 *
 * @param[in,out] mac  MAC descriptor or callback context.
 * @param[in] channel  Radio channel number.
 * @return 0 on success, or a negative error code on failure.
 */
int ieee802154_mlme_start_request(ieee802154_mac_t *mac, uint16_t channel);
/**
 * @brief Issue a MAC MCPS-DATA request.
 *
 * @param[in,out] mac      MAC descriptor or callback context.
 * @param[in] src_mode     Source address mode.
 * @param[in] dst_mode     Destination address mode.
 * @param[in] dst_panid    Destination PAN identifier in host byte order.
 * @param[in] dst_addr     Destination address in network byte order; NULL selects an unaddressed queue where supported.
 * @param[in] msdu         MAC service data unit as an I/O list.
 * @param[in] msdu_handle  MSDU handle returned with transmission confirmation.
 * @param[in] ack_req      Whether to request an acknowledgment.
 * @param[in] indirect     Whether to wait for a data request before transmission.
 * @return 0 on success, or a negative error code on failure.
 */
int ieee802154_mcps_data_request(ieee802154_mac_t *mac,
                                 ieee802154_addr_mode_t src_mode,
                                 ieee802154_addr_mode_t dst_mode,
                                 uint16_t dst_panid,
                                 const void *dst_addr,
                                 iolist_t *msdu,
                                 uint8_t msdu_handle,
                                 bool ack_req,
                                 bool indirect);
/**
 * @brief Issue a MAC MLME-ASSOCIATE request.
 *
 * @note The coordinator address is expected in network byte order.
 *
 * @param[in,out] mac      MAC descriptor or callback context.
 * @param[in] coord_addr   Coordinator address in network byte order.
 * @param[in] channel_num  Coordinator radio channel number.
 * @param[in] coord_panid  Coordinator PAN identifier in host byte order.
 * @param[in] capability   Device association capability information.
 * @return 0 on success, or a negative error code on failure.
 */
int ieee802154_mac_mlme_associate_request(ieee802154_mac_t *mac,
                                          const ieee802154_addr_t *coord_addr,
                                          uint16_t channel_num,
                                          uint16_t coord_panid,
                                          ieee802154_assoc_capability_t capability);
/**
 * @brief Issue a MAC MLME-ASSOCIATE response (coordinator).
 *
 * @note The destination address is expected in network byte order.
 *
 * @param[in,out] mac     MAC descriptor or callback context.
 * @param[in] dst_addr    Destination address in network byte order; NULL selects an unaddressed queue where supported.
 * @param[in] status      Operation completion status.
 * @param[in] short_addr  Assigned short address.
 * @return 0 on success, or a negative error code on failure.
 */
int ieee802154_mac_mlme_associate_response(ieee802154_mac_t *mac,
                                           const ieee802154_addr_t *dst_addr,
                                           ieee802154_assoc_status_t status,
                                           uint16_t short_addr);
/**
 * @brief Issue a MAC MLME-POLL request.
 *
 * @param[in,out] mac      MAC descriptor or callback context.
 * @param[in] coord_mode   Coordinator address mode.
 * @param[in] coord_panid  Coordinator PAN identifier in host byte order.
 * @param[in] coord_addr   Coordinator address in network byte order.
 * @return 0 on success, or a negative error code on failure.
 */
int ieee802154_mac_mlme_poll(ieee802154_mac_t *mac, ieee802154_addr_mode_t coord_mode,
                             uint16_t coord_panid, const void *coord_addr);
/**
 * @brief Issue a MAC MCPS-DATA request using the queued descriptor.
 *
 * @note This function is declared but currently has no implementation.
 * @return No return contract is defined yet.
 */
int ieee802154_mac_mcps_data(void);
/**
 * @brief Issue a MAC MCPS-RESET request.
 *
 * @note This function is declared but currently has no implementation.
 * @return No return contract is defined yet.
 */
int ieee802154_mac_mcps_reset(void);
/**
 * @brief Issue a MAC MLME-PURGE request.
 *
 * @note This function is declared but currently has no implementation.
 * @return No return contract is defined yet.
 */
int ieee802154_mac_mlme_purge(void);

#ifdef __cplusplus
}
#endif

/** @} */
