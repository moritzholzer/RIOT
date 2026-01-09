#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include "assert.h"
#include "net/ieee802154.h"

typedef struct ieee802154_pib_t {
    bool     AOA_ENABLE;
    bool     AUTO_REQUEST;
    bool     BATT_LIFE_EXT;
    uint16_t BATT_LIFE_EXT_PERIODS;
    uint8_t  BEACON_ORDER;

    const uint8_t *BEACON_PAYLOAD;
    size_t         BEACON_PAYLOAD_LEN;

    uint8_t  BSN;

    eui64_t          COORD_EXTENDED_ADDRESS;
    network_uint16_t COORD_SHORT_ADDRESS;

    uint8_t  DSN;

    eui64_t EXTENDED_ADDRESS;
    uint8_t FCS_TYPE;
    bool    GROUP_RX_MODE;
    bool    GTS_PERMIT;
    bool    IMPLICIT_BROADCAST;
    uint16_t LIFS_PERIOD;
    uint8_t  MAX_BE;
    uint8_t  MAX_CSMA_BACKOFFS;
    bool     NOTIFY_ALL_BEACONS;
    uint8_t  MIN_BE;
    uint16_t PAN_ID;
    uint8_t  RESPONSE_WAIT_TIME;
    bool     RX_ON_WHEN_IDLE;
    bool     SECURITY_ENABLED;
    network_uint16_t SHORT_ADDR;
    uint16_t SIFS_PERIOD;
    uint16_t SYNC_SYMBOL_OFFSET;
    bool     TIMESTAMP_SUPPORTED;
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

typedef struct {
    ieee802154_pib_type_t type;
    union {
        bool     b;
        uint8_t u8;
        uint16_t u16;
        struct { const uint8_t *ptr; size_t len; } bytes;
        eui64_t ext_addr;
        network_uint16_t short_addr;
    } v;
} ieee802154_pib_value_t;

void ieee802154_pib_init(ieee802154_pib_t *pib);
int ieee802154_mac_mlme_scan(void);
int ieee802154_mac_mlme_set(ieee802154_pib_attr_t pib_attr, ieee802154_pib_value_t pib_attr_value);
//int ieee802154_mac_mlme_start(uint16_t pan_id, );
int ieee802154_mac_mlme_associate(void);
int ieee802154_mac_mlme_get(void);
int ieee802154_mac_mlme_poll(void);
int ieee802154_mac_mcps_data(void);
int ieee802154_mac_mcps_reset(void);
int ieee802154_mac_mlme_purge(void);
#ifdef __cplusplus
}
#endif
