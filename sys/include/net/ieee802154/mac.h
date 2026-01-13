#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "assert.h"
#include "sched.h"
#include "thread.h"
#include "isrpipe.h"
#include "ztimer.h"
#include "iolist.h"

#include "net/ieee802154.h"
#include "net/ieee802154/submac.h"
#include "net/ieee802154/radio.h"


#ifndef IEEE802154_MAC_TXQ_LEN
#define IEEE802154_MAC_TXQ_LEN   (4U)
#endif

#ifndef IEEE802154_MAC_EVPIPE_LEN
#define IEEE802154_MAC_EVPIPE_LEN (16U)
#endif

#ifndef IEEE802154_MAC_STACKSIZE
#define IEEE802154_MAC_STACKSIZE (THREAD_STACKSIZE_DEFAULT)
#endif

#ifndef IEEE802154_MAC_PRIO
#define IEEE802154_MAC_PRIO      (THREAD_PRIORITY_MAIN - 1)
#endif

#ifndef IEEE802154_MAC_PAYLOAD_POOL_N
#define IEEE802154_MAC_PAYLOAD_POOL_N  8
#endif

#ifndef IEEE802154_MAC_PAYLOAD_MAX
#define IEEE802154_MAC_PAYLOAD_MAX     IEEE802154_FRAME_LEN_MAX
#endif

#ifndef IEEE802154_MAC_REQ_RING_LEN
#define IEEE802154_MAC_REQ_RING_LEN  (8)
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
    const uint8_t *ptr;
    size_t len;
} ieee802154_octets_t;

/**
 * @brief IEEE 802.15.4 MAC PIB.
 */
typedef struct ieee802154_pib_t {
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
typedef void (*ieee802154_mcps_data_confirm_cb_t)(void *arg, uint8_t handle, int status);

/**
 * @brief IEEE 802.15.4 MAC MCPS-DATA.indication callback.
 */
typedef void (*ieee802154_mcps_data_indication_cb_t)(void *arg,
                                                    const uint8_t *psdu, size_t len,
                                                    const ieee802154_rx_info_t *info);

/* === MLME confirm callback types === */

typedef void (*ieee802154_mlme_set_confirm_cb_t)(void *arg,
                                                uint8_t handle,
                                                int status,
                                                ieee802154_pib_attr_t attr);

typedef void (*ieee802154_mlme_get_confirm_cb_t)(void *arg,
                                                uint8_t handle,
                                                int status,
                                                ieee802154_pib_attr_t attr,
                                                ieee802154_pib_value_t value);

typedef void (*ieee802154_mlme_start_confirm_cb_t)(void *arg,
                                                  uint8_t handle,
                                                  int status);

/**
 * @brief IEEE 802.15.4 MAC callbacks.
 */
typedef struct {
    ieee802154_mcps_data_confirm_cb_t data_confirm;         /**< MCPS-DATA.confirm callback*/
    ieee802154_mcps_data_indication_cb_t data_indication;   /**< MCPS-DATA.indication callback*/
    /* MLME (async confirms) */
    ieee802154_mlme_set_confirm_cb_t   mlme_set_confirm;    /**< MLME-SET.confirm callback */
    ieee802154_mlme_get_confirm_cb_t   mlme_get_confirm;    /**< MLME-GET.confirm callback */
    ieee802154_mlme_start_confirm_cb_t mlme_start_confirm;  /**< MLME-START.confirm callback */
    void *arg;
} ieee802154_mac_cbs_t;

typedef struct {
    bool in_use;
    size_t len;
    uint8_t buf[IEEE802154_MAC_PAYLOAD_MAX];
} ieee802154_mac_payload_t;

typedef struct {
    bool in_use;                                /**< wheather ring buffer element is in use */
    uint8_t handle;                             /**< the MSDU handle */
    uint8_t mhr[IEEE802154_MAX_HDR_LEN];        /**< persistent header storage */
    size_t mhr_len;                            /**< len of the header */
    iolist_t iol_mhr;                           /**< persistent iolist nodes */
    iolist_t iol_msdu;                          /**< persistent iolist nodes */
    ieee802154_mac_payload_t *payload;
} ieee802154_mac_tx_desc_t;

typedef enum {
    IEEE802154_MAC_REQ_TX,
    IEEE802154_MAC_REQ_MLME_SET,
    IEEE802154_MAC_REQ_MLME_GET,
    IEEE802154_MAC_REQ_MLME_START,
} ieee802154_mac_req_type_t;

typedef struct {
    ieee802154_mac_req_type_t type;
    uint8_t handle;

    union {
        struct {
            ieee802154_addr_mode_t src_mode;
            ieee802154_addr_mode_t dst_mode;
            uint16_t dst_panid;
            uint8_t dst_addr[8];
            uint8_t dst_len;
            bool ack_req;
            ieee802154_mac_payload_t *pl;
        } tx;

        struct {
            ieee802154_pib_attr_t attr;
            ieee802154_pib_value_t value;
        } set;

        struct {
            ieee802154_pib_attr_t attr;
        } get;

        struct {
            uint16_t panid;
            uint8_t channel;
            bool beaconing;
        } start;

    } u;
} ieee802154_mac_req_t;

typedef struct {
    ieee802154_mac_req_t q[IEEE802154_MAC_REQ_RING_LEN];
    uint8_t head, tail, cnt;
    mutex_t lock;
} ieee802154_mac_req_ring_t;

typedef struct {
    ieee802154_mac_tx_desc_t q[IEEE802154_MAC_TXQ_LEN]; /**< outgoing queue */
    uint8_t head;                                       /**< queue head */
    uint8_t tail;                                       /**< queue tail */
    uint8_t cnt;                                        /**< queue count */
    bool busy;                                          /**< currently sending */
    mutex_t lock;                                       /**< guard access (optional) */
} ieee802154_mac_txq_t;

/**
 * @brief IEEE 802.15.4 MAC descriptor
 */
typedef struct {
    ieee802154_pib_t pib;                                       /**< PIB of the MAC */
    mutex_t pib_lock;
    ieee802154_submac_t submac;                                 /**< SubMAC descriptor */
    mutex_t submac_lock;
    ieee802154_mac_cbs_t cbs;                                   /**< callbacks for the SubMAC */
    kernel_pid_t pid;                                           /**< pid of MAC thread */
    char stack[IEEE802154_MAC_STACKSIZE];                       /**< stack size of the mac thread */
    isrpipe_t evpipe;                                           /**< event pipe for the submac ISR */
    uint8_t evpipe_buf[IEEE802154_MAC_EVPIPE_LEN];              /**< buffer of the event pipe */
    ztimer_t ack_timer;                                         /**< timer for ACK timeout */
    ieee802154_mac_payload_t payload_pool[IEEE802154_MAC_PAYLOAD_POOL_N];  /**< pool for the payloads (TX) */
    mutex_t payload_pool_lock;                                  /**< pool lock */
    uint8_t rx_buf[IEEE802154_FRAME_LEN_MAX];                   /**< receiving buf */
    ieee802154_mac_req_ring_t req_ring;
    ieee802154_mac_txq_t tx_ring;
} ieee802154_mac_t;

/**
 * @brief Init the IEEE 802.15.4 MAC
 */
int ieee802154_mac_init(ieee802154_mac_t *mac,
                        const ieee802154_mac_cbs_t *cbs);

/**
 * @brief Starts the IEEE 802.15.4 MAC
 */
int ieee802154_mac_start(ieee802154_mac_t *mac);

int ieee802154_mac_mlme_scan_request(void);
int ieee802154_mac_mlme_set_request(ieee802154_mac_t *mac,
                                ieee802154_pib_attr_t attr,
                                const ieee802154_pib_value_t *in);
int ieee802154_mac_mlme_get_request(ieee802154_mac_t *mac, ieee802154_pib_attr_t attr);
int ieee802154_mlme_start_request(ieee802154_mac_t *mac, uint16_t channel);
int ieee802154_mcps_data_request(ieee802154_mac_t *mac,
                                 ieee802154_addr_mode_t src_mode,
                                 ieee802154_addr_mode_t dst_mode,
                                 uint16_t dst_panid,
                                 const void *dst_addr,
                                 ieee802154_octets_t msdu,
                                 uint8_t msdu_handle,
                                 bool ack_req);
int ieee802154_mac_mlme_associate(void);
int ieee802154_mac_mlme_poll(void);
int ieee802154_mac_mcps_data(void);
int ieee802154_mac_mcps_reset(void);
int ieee802154_mac_mlme_purge(void);
#ifdef __cplusplus
}
#endif
