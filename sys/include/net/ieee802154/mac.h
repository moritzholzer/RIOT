#pragma once

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

#define IEEE802154_MAC_INDIRECT_ENABLE

#if IS_USED(MODULE_ESP_IEEE802154)
#define IEEE802154_MAC_HAS_SRC_ADDR_MATCH
#endif

#ifdef IEEE802154_MAC_INDIRECT_ENABLE
#  ifndef IEEE802154_MAC_HAS_SRC_ADDR_MATCH
#    define IEEE802154_MAC_FORCE_SOFT_ACK
#  endif
#endif

#ifndef IEEE802154_MAC_TXQ_LEN
#define IEEE802154_MAC_TXQ_LEN   (4U)
#endif

#ifndef IEEE802154_MAC_TICK_INTERVAL_US
#define IEEE802154_MAC_TICK_INTERVAL_US     (1000U)
#endif

#ifndef IEEE802154_MAC_TX_INDIRECTQ_SIZE
#define IEEE802154_MAC_TX_INDIRECTQ_SIZE     (4)
#endif

#ifndef IEEE802154_MAC_BASE_SLOT_DURATION
#define IEEE802154_MAC_BASE_SLOT_DURATION   (60U)
#endif

#ifndef IEEE802154_MAC_MAX_LOST_BEACONS
#define IEEE802154_MAC_MAX_LOST_BEACONS   (4U)
#endif

#ifndef IEEE802154_MAC_MIN_CAP_LENGTH
#define IEEE802154_MAC_MIN_CAP_LENGTH   (440U)
#endif

#ifndef IEEE802154_MAC_NUM_SUPERFRAME_SLOTS
#define IEEE802154_MAC_NUM_SUPERFRAME_SLOTS     (16)
#endif

#ifndef IEEE802154_MAC_BASE_SUPERFRAME_DURATION
#define IEEE802154_MAC_BASE_SUPERFRAME_DURATION   (IEEE802154_MAC_BASE_SLOT_DURATION * IEEE802154_MAC_NUM_SUPERFRAME_SLOTS)
#endif

#
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
    const uint8_t *ptr;
    size_t len;
} ieee802154_octets_t;

/**
 * @brief IEEE 802.15.4 MAC PIB.
 */
typedef struct {
    bool AOA_ENABLE;
    bool AUTO_REQUEST;
    bool BATT_LIFE_EXT;
    uint16_t BATT_LIFE_EXT_PERIODS;
    uint8_t BEACON_ORDER;
    ieee802154_octets_t BEACON_PAYLOAD;
    uint8_t BSN;
    ieee802154_ext_addr_t COORD_EXTENDED_ADDRESS;
    ieee802154_short_addr_t COORD_SHORT_ADDRESS;
    uint8_t DSN;
    eui64_t EXTENDED_ADDRESS;
    uint8_t FCS_TYPE;
    bool GROUP_RX_MODE;
    bool GTS_PERMIT;
    bool IMPLICIT_BROADCAST;
    uint16_t LIFS_PERIOD;
    uint8_t MAX_BE;
    uint8_t MAX_CSMA_BACKOFFS;
    bool NOTIFY_ALL_BEACONS;
    uint8_t MIN_BE;
    uint16_t PAN_ID;
    uint8_t RESPONSE_WAIT_TIME;
    bool RX_ON_WHEN_IDLE;
    bool SECURITY_ENABLED;
    network_uint16_t SHORT_ADDR;
    uint16_t SIFS_PERIOD;
    uint16_t SYNC_SYMBOL_OFFSET;
    bool TIMESTAMP_SUPPORTED;
    uint16_t TRANSACTION_PERSISTENCE_TIME;
    uint16_t UNIT_BACKOFF_PERIOD;
} ieee802154_pib_t;

/**
 * @brief IEEE 802.15.4 MAC PIB Attributes.
 */
typedef enum {
    IEEE802154_PIB_AOA_ENABLE,
    IEEE802154_PIB_AUTO_REQUEST,
    IEEE802154_PIB_BATT_LIFE_EXT,
    IEEE802154_PIB_BATT_LIFE_EXT_PERIODS,
    IEEE802154_PIB_BEACON_ORDER,
    IEEE802154_PIB_BEACON_PAYLOAD,
    IEEE802154_PIB_BSN,
    IEEE802154_PIB_COORD_EXTENDED_ADDRESS,
    IEEE802154_PIB_COORD_SHORT_ADDRESS,
    IEEE802154_PIB_DSN,
    IEEE802154_PIB_EXTENDED_ADDRESS,
    IEEE802154_PIB_FCS_TYPE,
    IEEE802154_PIB_GROUP_RX_MODE,
    IEEE802154_PIB_GTS_PERMIT,
    IEEE802154_PIB_IMPLICIT_BROADCAST,
    IEEE802154_PIB_LIFS_PERIOD,
    IEEE802154_PIB_MAX_BE,
    IEEE802154_PIB_MAX_CSMA_BACKOFFS,
    IEEE802154_PIB_NOTIFY_ALL_BEACONS,
    IEEE802154_PIB_MIN_BE,
    IEEE802154_PIB_PAN_ID,
    IEEE802154_PIB_RESPONSE_WAIT_TIME,
    IEEE802154_PIB_RX_ON_WHEN_IDLE,
    IEEE802154_PIB_SECURITY_ENABLED,
    IEEE802154_PIB_SHORT_ADDR,
    IEEE802154_PIB_SIFS_PERIOD,
    IEEE802154_PIB_SYNC_SYMBOL_OFFSET,
    IEEE802154_PIB_TIMESTAMP_SUPPORTED,
    IEEE802154_PIB_TRANSACTION_PERSISTENCE_TIME,
    IEEE802154_PIB_UNIT_BACKOFF_PERIOD,
    IEEE802154_PIB_ATTR_COUNT
} ieee802154_pib_attr_t;

/**
 * @brief IEEE 802.15.4 MAC PIB data types.
 */
typedef enum {
    IEEE802154_PIB_TYPE_BOOL,   /**< bool */
    IEEE802154_PIB_TYPE_U8,     /**< uint8_t */
    IEEE802154_PIB_TYPE_U16,    /**< uint16_t */
    IEEE802154_PIB_TYPE_EUI64,  /**< ext address in ieee802154_ext_addr_t */
    IEEE802154_PIB_TYPE_NUI16,  /**< short address in ieee802154_short_addr_t */
    IEEE802154_PIB_TYPE_BYTES   /**< octets in  ieee802154_octets_t*/
} ieee802154_pib_type_t;

typedef enum {
    IEEE802154_DEV_TYPE_CC2538_RF,
    IEEE802154_DEV_TYPE_NRF802154,
    IEEE802154_DEV_TYPE_SOCKET_ZEP,
    IEEE802154_DEV_TYPE_KW2XRF,
    IEEE802154_DEV_TYPE_MRF24J40,
    IEEE802154_DEV_TYPE_ESP_IEEE802154,
} ieee802154_dev_type_t;

typedef enum {
    IEEE802154_ADDR_MODE_NONE,
    IEEE802154_ADDR_MODE_SHORT,
    IEEE802154_ADDR_MODE_EXTENDED
} ieee802154_addr_mode_t;

typedef struct {
    ieee802154_addr_mode_t type;
    union {
        ieee802154_ext_addr_t ext_addr;
        ieee802154_short_addr_t short_addr;
    } v;
} ieee802154_addr_t;

typedef struct {
    ieee802154_pib_type_t type;
    union {
        bool b;
        uint8_t u8;
        uint16_t u16;
        ieee802154_octets_t bytes;
        eui64_t ext_addr;
        network_uint16_t short_addr;
    } v;
} ieee802154_pib_value_t;

typedef enum {
    IEEE802154_PIB_ACC_RW,
    IEEE802154_PIB_ACC_RO
} ieee802154_pib_access_t;

typedef struct {
    ieee802154_pib_type_t type;
    ieee802154_pib_access_t access;

    uint16_t offset;
    uint16_t size;

    ieee802154_pib_value_t def;
    ieee802154_pib_value_t min;
    ieee802154_pib_value_t max;
} ieee802154_pib_attr_entry_t;

/**
 * @brief IEEE 802.15.4 MAC MCPS-DATA.confirm callback.
 */
typedef void (*ieee802154_mcps_data_confirm_cb_t)(void *mac, uint8_t handle, int status);

/*t i*
 * @brief IEEE 802.15.4 MAC MCPS-DATA.indication callback.
 */
typedef void (*ieee802154_mcps_data_indication_cb_t)(void *mac, iolist_t *msdu,
                                                    const ieee802154_rx_info_t *info);

/* === MLME confirm callback types === */

typedef void (*ieee802154_mlme_set_confirm_cb_t)(void *mac,
                                                uint8_t handle,
                                                int status,
                                                ieee802154_pib_attr_t attr);

typedef void (*ieee802154_mlme_get_confirm_cb_t)(void *mac,
                                                uint8_t handle,
                                                int status,
                                                ieee802154_pib_attr_t attr,
                                                ieee802154_pib_value_t value);

typedef void (*ieee802154_mlme_start_confirm_cb_t)(void *mac,
                                                  uint8_t handle,
                                                  int status);

typedef void (*ieee802154_mac_ack_timeout_fired_cb_t)(void *mac);

typedef void (*ieee802154_mac_bh_request_cb_t)(void *mac);

/* === RADIO callbacks === */
typedef void (*ieee802154_radio_cb_request_t)(ieee802154_dev_t *dev, ieee802154_trx_ev_t st);

/* === Transmission callbacks === */
typedef void (*ieee802154_mac_tick_t)(void *mac);
typedef void (*ieee802154_mac_allocate_request_t)(void *mac);
typedef void (*ieee802154_mac_rx_request_t)(void *mac);
typedef void (*ieee802154_mac_dealloc_request_t)(void *mac, iolist_t *iolist);

/**
 * @brief IEEE 802.15.4 MAC callbacks.
 */
typedef struct {
    ieee802154_mcps_data_confirm_cb_t       data_confirm;       /**< MCPS-DATA.confirm callback*/
    ieee802154_mcps_data_indication_cb_t    data_indication;    /**< MCPS-DATA.indication callback*/
    ieee802154_mlme_start_confirm_cb_t      mlme_start_confirm; /**< MLME-START.confirm callback */
    ieee802154_mac_ack_timeout_fired_cb_t   ack_timeout;        /**< ieee802154_mac_ack_timeout_fired() should be dispatched */
    ieee802154_mac_bh_request_cb_t          bh_request;         /**< ieee802154_mac_bh_process() should be dispatched */
    ieee802154_radio_cb_request_t           radio_cb_request;   /**< ieee802154_mac_handle_radio() should be dispatched */
    ieee802154_mac_tick_t                   tick_request;
    ieee802154_mac_allocate_request_t       allocate_request;
    ieee802154_mac_dealloc_request_t        dealloc_request;
    ieee802154_mac_rx_request_t             rx_request;
    void *mac;
} ieee802154_mac_cbs_t;


typedef struct {
    bool in_use;                                 /**< wheather ring buffer element is in use */
    uint8_t handle;                              /**< the MSDU handle */
    bool indirect;
    bool ack;
    uint16_t deadline_tick;
    uint8_t mhr[IEEE802154_MAX_HDR_LEN];         /**< persistent header storage */
    iolist_t iol_mhr;                            /**< persistent mhr */
    iolist_t *iol_msdu;                          /**< iolist nodes */
} ieee802154_mac_tx_desc_t;

typedef struct {
    ieee802154_mac_tx_desc_t q[IEEE802154_MAC_TXQ_LEN]; /**< outgoing queue */
    eui64_t dst_addr;
    uint8_t head;                                       /**< queue head */
    uint8_t tail;                                       /**< queue tail */
    uint8_t cnt;                                        /**< queue count */
    uint16_t *deadline_tick;
} ieee802154_mac_txq_t;

typedef struct {
    ieee802154_mac_txq_t q[IEEE802154_MAC_TX_INDIRECTQ_SIZE];
    ieee802154_mac_txq_t *current_txq;
    unsigned current_slot;
    bool busy;
    uint16_t tick;
    uint32_t free_mask;
    mutex_t lock;
} ieee802154_mac_indirect_q_t;

/**
 * @brief IEEE 802.15.4 MAC descriptor
 */
typedef struct {
    bool is_coordinator;
    ieee802154_pib_t pib;                                       /**< PIB of the MAC */
    mutex_t pib_lock;
    ieee802154_submac_t submac;                                 /**< SubMAC descriptor */
    mutex_t submac_lock;
    ieee802154_mac_cbs_t cbs;                                   /**< callbacks for the SubMAC */
    ztimer_t ack_timer;                                         /**< timer for ACK timeout */
    ztimer_t tick;                                              /**< tick for frame timeouts */
    uint8_t cmd_buf[IEEE802154_FRAME_LEN_MAX];                   /**< receiving buf */
    iolist_t cmd;
    ieee802154_mac_indirect_q_t indirect_q;
    uint16_t sym_us;
} ieee802154_mac_t;

/* === Function that has to be dispatched and called on callbacks */

/**
 * Has to ba called from thread context when ieee802154_mac_ack_timeout_fired_cb_t is called
 */
void ieee802154_mac_ack_timeout_fired(ieee802154_mac_t *mac);

/**
 * @brief Has to be called from thread context when ieee802154_mac_bh_request_cb_t is called
 */
void ieee802154_mac_bh_process(ieee802154_mac_t *mac);

/**
 * @brief Hast to be called from thread context when ieeee802154_radio_cb_request_t is called
 */
void ieee802154_mac_handle_radio(ieee802154_dev_t *dev, ieee802154_trx_ev_t st);

void ieee802154_mac_send_process(ieee802154_mac_t *mac, iolist_t *buf);

void ieee802154_mac_tick(ieee802154_mac_t *mac);

/**
 * @brief Init the IEEE 802.15.4 MAC
 */
void ieee802154_mac_init(ieee802154_mac_t *mac,
                        const ieee802154_mac_cbs_t *cbs);

int ieee802154_mac_mlme_scan_request(void);
void ieee802154_mac_mlme_set_request(ieee802154_mac_t *mac,
                            ieee802154_pib_attr_t attr,
                            const ieee802154_pib_value_t *in);
void ieee802154_mac_mlme_get_request(ieee802154_mac_t *mac,
                            ieee802154_pib_attr_t attr,
                            ieee802154_pib_value_t *out);
int ieee802154_mlme_start_request(ieee802154_mac_t *mac, uint16_t channel);
int ieee802154_mcps_data_request(ieee802154_mac_t *mac,
                                 ieee802154_addr_mode_t src_mode,
                                 ieee802154_addr_mode_t dst_mode,
                                 uint16_t dst_panid,
                                 const void *dst_addr,
                                 iolist_t *msdu,
                                 uint8_t msdu_handle,
                                 bool ack_req,
                                 bool indirect);
int ieee802154_mac_mlme_associate(void);
int ieee802154_mac_mlme_poll(ieee802154_mac_t *mac, ieee802154_addr_mode_t coord_mode, uint16_t coord_panid, const void *coord_addr);
int ieee802154_mac_mcps_data(void);
int ieee802154_mac_mcps_reset(void);
int ieee802154_mac_mlme_purge(void);
#ifdef __cplusplus
}
#endif
