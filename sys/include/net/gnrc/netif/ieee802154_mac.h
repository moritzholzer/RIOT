#pragma once

/**
 * @ingroup     net_gnrc_netif
 * @{
 *
 * @file
 * @brief       GNRC netif adapter for IEEE 802.15.4 MAC (mac.h)
 *
 * @}
 */

#ifdef __cplusplus
extern "C" {
#endif

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "event.h"
#include "mutex.h"
#include "ztimer.h"

#include "net/gnrc/netif.h"
#include "net/gnrc/pkt.h"
#include "net/ieee802154.h"
#include "net/ieee802154/mac.h"
#include "net/netdev.h"
#include "iolist.h"

/**
 * @brief   RX buffer count for GNRC IEEE 802.15.4 MAC adapter
 */
#ifndef GNRC_NETIF_IEEE802154_MAC_RX_BUF_NUM
#define GNRC_NETIF_IEEE802154_MAC_RX_BUF_NUM   (4U)
#endif

/**
 * @brief   TX buffer count for GNRC IEEE 802.15.4 MAC adapter
 */
#ifndef GNRC_NETIF_IEEE802154_MAC_TX_BUF_NUM
#define GNRC_NETIF_IEEE802154_MAC_TX_BUF_NUM   (IEEE802154_MAC_TXQ_LEN)
#endif

/**
 * @brief   Scan channel list size for GNRC IEEE 802.15.4 MAC adapter
 */
#ifndef GNRC_NETIF_IEEE802154_MAC_SCAN_MAX_CH
#define GNRC_NETIF_IEEE802154_MAC_SCAN_MAX_CH  (16U)
#endif

/**
 * @brief   Buffer structure for GNRC IEEE 802.15.4 MAC adapter
 */
typedef struct {
    iolist_t iol;
    uint8_t buf[IEEE802154_FRAME_LEN_MAX];
    bool in_use;
} gnrc_netif_ieee802154_mac_buf_t;

/**
 * @brief   RX queue entry for GNRC IEEE 802.15.4 MAC adapter
 */
typedef struct {
    gnrc_pktsnip_t *pkt;
    ieee802154_rx_info_t info;
} gnrc_netif_ieee802154_mac_rx_entry_t;

/**
 * @brief   Device structure for gnrc_netif_ieee802154_mac
 */
typedef struct gnrc_netif_ieee802154_mac_dev {
    netdev_t netdev;
    ieee802154_mac_t mac;
    gnrc_netif_t *netif;
    gnrc_nettype_t proto;

    mutex_t rx_lock;
    gnrc_netif_ieee802154_mac_buf_t rx_pool[GNRC_NETIF_IEEE802154_MAC_RX_BUF_NUM];
    gnrc_netif_ieee802154_mac_rx_entry_t rxq[GNRC_NETIF_IEEE802154_MAC_RX_BUF_NUM];
    uint8_t rxq_head;
    uint8_t rxq_tail;
    uint8_t rxq_len;
    gnrc_netif_ieee802154_mac_buf_t tx_pool[GNRC_NETIF_IEEE802154_MAC_TX_BUF_NUM];

    mutex_t tx_lock;
    bool tx_done;
    int last_tx_status;
    size_t rx_alloc_len;

    ieee802154_dev_t *radio_dev;
    ieee802154_trx_ev_t radio_ev;

    event_t ev_alloc;
    event_t ev_rx;
    event_t ev_tick;
    event_t ev_scan_timer;
    event_t ev_ack_timeout;
    event_t ev_bh_request;
    event_t ev_radio;
    event_t ev_poll;
    event_t ev_assoc_res;
    ztimer_t poll_timer;
    uint32_t poll_interval_ms;
    bool tx_indirect;

    bool assoc_res_pending;
    ieee802154_addr_t assoc_res_dst;
    ieee802154_assoc_status_t assoc_res_status;
    uint16_t assoc_res_short_addr;

    bool assoc_panid_pending_valid;
    uint16_t assoc_panid_pending;
    uint16_t assoc_panid_old;

    uint8_t beacon_payload[IEEE802154_SCAN_BEACON_PAYLOAD_MAX];
    size_t beacon_payload_len;
} gnrc_netif_ieee802154_mac_dev_t;

/**
 * @brief   Radio init callback for GNRC IEEE 802.15.4 MAC adapter
 *
 * @param[in,out] radio     Radio HAL device storage
 * @param[in]     dev_type  Radio device type
 * @param[in]     idx       Device index (0..n-1)
 * @param[in]     arg       User context pointer
 *
 * @return 0 on success, negative error code on failure
 */
typedef int (*gnrc_netif_ieee802154_mac_radio_init_cb_t)(ieee802154_dev_t *radio,
                                                         ieee802154_dev_type_t dev_type,
                                                         unsigned idx,
                                                         void *arg);

/**
 * @brief   Set radio init callback for GNRC IEEE 802.15.4 MAC adapter
 *
 * If set, the adapter will call this callback to initialize the radio HAL
 * before MAC initialization.
 *
 * @param[in] cb   radio init callback (NULL to clear)
 * @param[in] arg  user context pointer
 */
void gnrc_netif_ieee802154_mac_set_radio_init_cb(gnrc_netif_ieee802154_mac_radio_init_cb_t cb,
                                                 void *arg);

/**
 * @brief   Create a GNRC netif instance using IEEE 802.15.4 MAC (mac.h)
 *
 * @param[out] netif    GNRC netif instance
 * @param[in]  stack    Stack for the GNRC netif thread
 * @param[in]  stacksize Stack size
 * @param[in]  priority Thread priority
 * @param[in]  name     Thread name (may be NULL)
 * @param[in]  dev      Device storage for the adapter
 *
 * @return  0 on success
 * @return  negative error code on failure
 */
int gnrc_netif_ieee802154_mac_create(gnrc_netif_t *netif, char *stack,
                                     int stacksize, char priority,
                                     const char *name,
                                     gnrc_netif_ieee802154_mac_dev_t *dev);

/**
 * @brief   Set radio type for IEEE 802.15.4 MAC adapter
 *
 * @param[in] dev_type  radio type to initialize
 */
void gnrc_netif_ieee802154_mac_set_dev_type(ieee802154_dev_type_t dev_type);

/**
 * @brief   Get the MAC instance used by the GNRC IEEE 802.15.4 MAC adapter
 *
 * @return pointer to MAC instance, or NULL if not initialized
 */
ieee802154_mac_t *gnrc_netif_ieee802154_mac_get(void);


#ifdef __cplusplus
}
#endif
