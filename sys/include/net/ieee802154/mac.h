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
#define IEEE802154_MAC_EVPIPE_LEN (16U) /* bytes */
#endif

#ifndef IEEE802154_MAC_STACKSIZE
#define IEEE802154_MAC_STACKSIZE (THREAD_STACKSIZE_DEFAULT)
#endif

#ifndef IEEE802154_MAC_PRIO
#define IEEE802154_MAC_PRIO      (THREAD_PRIORITY_MAIN - 1)
#endif

typedef eui64_t ieee802154_ext_addr_t;
typedef network_uint16_t ieee802154_short_addr_t;

typedef struct {
    const uint8_t *ptr;
    size_t len;
} ieee802154_octets_t;

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

typedef enum {
    IEEE802154_PIB_TYPE_BOOL,
    IEEE802154_PIB_TYPE_U8,
    IEEE802154_PIB_TYPE_U16,
    IEEE802154_PIB_TYPE_EUI64,
    IEEE802154_PIB_TYPE_NUI16,
    IEEE802154_PIB_TYPE_BYTES
} ieee802154_pib_type_t;

typedef enum {
    IEEE802154_PIB_OK           = 0,
    IEEE802154_PIB_ERR_BAD_ARGS = -1,
    IEEE802154_PIB_ERR_ATTR     = -2,
    IEEE802154_PIB_ERR_TYPE     = -3,
    IEEE802154_PIB_ERR_ACCESS   = -4,
    IEEE802154_PIB_ERR_SIZE     = -5
} ieee802154_pib_res_t;

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
    IEEE802154_MAC_EV_RADIO_TX_DONE = 1,
    IEEE802154_MAC_EV_RADIO_RX_DONE = 2,
    IEEE802154_MAC_EV_RADIO_CRC_ERR = 3,
    IEEE802154_MAC_EV_SUBMAC_BH     = 4,
    IEEE802154_MAC_EV_ACK_TIMEOUT   = 5,
    IEEE802154_MAC_EV_TX_KICK       = 6,
} ieee802154_mac_ev_t;

typedef void (*ieee802154_mcps_data_confirm_cb_t)(void *arg, uint8_t handle, int status);
typedef void (*ieee802154_mcps_data_indication_cb_t)(void *arg,
                                                    const uint8_t *psdu, size_t len,
                                                    const ieee802154_rx_info_t *info);

typedef struct {
    ieee802154_mcps_data_confirm_cb_t data_confirm;
    ieee802154_mcps_data_indication_cb_t data_indication;
    void *arg;
} ieee802154_mac_cbs_t;

typedef struct {
    bool in_use;
    uint8_t handle;

    /* persistent header storage */
    uint8_t mhr[IEEE802154_MAX_HDR_LEN];
    uint8_t mhr_len;

    /* persistent iolist nodes (must live until TX done) */
    iolist_t iol_mhr;
    iolist_t iol_msdu;

    /* borrowed payload (Option A) */
    ieee802154_octets_t msdu;
} ieee802154_mac_tx_desc_t;

typedef struct {
    ieee802154_pib_t pib;
    ieee802154_submac_t submac;
    ieee802154_mac_cbs_t cbs;

    kernel_pid_t pid;
    char stack[IEEE802154_MAC_STACKSIZE];

    /* ISR->thread event pipe */
    isrpipe_t evpipe;
    uint8_t evpipe_buf[IEEE802154_MAC_EVPIPE_LEN];

    /* ACK timeout timer (SubMAC hook) */
    ztimer_t ack_timer;

    /* RX scratch buffer */
    uint8_t rx_buf[127];

    /* TX ring */
    ieee802154_mac_tx_desc_t tx_queue[IEEE802154_MAC_TXQ_LEN];
    uint8_t tx_head;
    uint8_t tx_tail;
    uint8_t tx_cnt;
    bool tx_busy;
} ieee802154_mac_t;

int ieee802154_mac_init(ieee802154_mac_t *mac,
                        const ieee802154_mac_cbs_t *cbs);

int ieee802154_mac_start(ieee802154_mac_t *mac);

int ieee802154_mac_mlme_scan(void);
ieee802154_pib_res_t ieee802154_mac_mlme_set(ieee802154_mac_t *mac, ieee802154_pib_attr_t pib_attr, const ieee802154_pib_value_t *pib_attr_value);
ieee802154_pib_res_t ieee802154_mac_mlme_get(const ieee802154_mac_t *mac, ieee802154_pib_attr_t pib_attr, ieee802154_pib_value_t *pib_attr_value);
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
