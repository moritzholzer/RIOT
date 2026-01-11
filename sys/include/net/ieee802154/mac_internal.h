#pragma once

#include "msg.h"
#include "container.h"

#include "net/ieee802154/mac.h"

/**
 * @brief INIT event for the IEEE 802.15.4 MAC thread, send to start.
 */
enum {
    _MAC_MSG_INIT = 0x154A,
};

/**
 * @brief IEEE 802.15.4 MAC thread event type.
 */
typedef enum {
    IEEE802154_MAC_EV_RADIO_TX_DONE = 1,
    IEEE802154_MAC_EV_RADIO_RX_DONE = 2,
    IEEE802154_MAC_EV_RADIO_CRC_ERR = 3,
    IEEE802154_MAC_EV_SUBMAC_BH     = 4,
    IEEE802154_MAC_EV_ACK_TIMEOUT   = 5,
    IEEE802154_MAC_EV_TX_KICK       = 6,
} ieee802154_mac_ev_t;

/**
 * @brief Handle for the IEEE 802.15.4 MAC thread.
 */
void *ieee802154_mac_thread(void *arg);

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

/**
 * @brief Posts an event for the IEEE 802.15.4 MAC thread.
 */
void ieee802154_mac_post_event(ieee802154_mac_t *mac, ieee802154_mac_ev_t ev);


/**
 * @brief Whether the TX queue is full.
 */
static inline bool ieee802154_mac_tx_full(const ieee802154_mac_t *mac)
{
    return mac->tx_cnt >= IEEE802154_MAC_TXQ_LEN;
}

/**
 * @brief Whether the TX queue is empty.
 */
static inline bool ieee802154_mac_tx_empty(const ieee802154_mac_t *mac)
{
    return (mac->tx_cnt == 0);
}

/**
 * @brief Returns a descriptor of TX queue head. Caller fills it.
 */
static inline ieee802154_mac_tx_desc_t * ieee802154_mac_tx_reserve(ieee802154_mac_t *mac)
{
    if (!mac || ieee802154_mac_tx_full(mac)) {
        return NULL;
    }

    ieee802154_mac_tx_desc_t *d = &mac->tx_queue[mac->tx_tail];
    memset(d, 0, sizeof(*d));
    d->in_use = true;
    return d;
}

/**
 * @brief Advances TX queue tail to make it visible to the sender.
 */
static inline void ieee802154_mac_tx_commit(ieee802154_mac_t *mac)
{
    mac->tx_tail = (uint8_t)((mac->tx_tail + 1) % IEEE802154_MAC_TXQ_LEN);
    mac->tx_cnt++;
}

/**
 * @brief Returns descriptor of TX queue head (next to send), does not remove.
 */
static inline ieee802154_mac_tx_desc_t * ieee802154_mac_tx_peek(ieee802154_mac_t *mac)
{
    if (!mac || ieee802154_mac_tx_empty(mac)) {
        return NULL;
    }

    ieee802154_mac_tx_desc_t *d = &mac->tx_queue[mac->tx_head];

    if (!d->in_use) {
        return NULL;
    }

    return d;
}

/**
 * @brief Removes TX queue head entry.
 */
static inline void ieee802154_mac_tx_pop(ieee802154_mac_t *mac)
{
    if (!mac || ieee802154_mac_tx_empty(mac)) {
        return;
    }

    ieee802154_mac_tx_desc_t *d = &mac->tx_queue[mac->tx_head];
    memset(d, 0, sizeof(*d));

    mac->tx_head = (uint8_t)((mac->tx_head + 1) % IEEE802154_MAC_TXQ_LEN);
    mac->tx_cnt--;
}
