/*
 * SPDX-FileCopyrightText: 2026 HAW Hamburg
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @{
 *
 * @file
 * @author Moritz Holzer <moritz.holzer@haw-hamburg.de>
 */

#pragma once

#include "msg.h"
#include "container.h"
#include "mutex.h"

#include "net/ieee802154/mac.h"

static inline ieee802154_mac_payload_t *ieee802154_mac_payload_alloc(ieee802154_mac_t *mac)
{
    if (!mac) {
        return NULL;
    }

    mutex_lock(&mac->payload_pool_lock);
    for (uint8_t i = 0; i < IEEE802154_MAC_PAYLOAD_POOL_N; i++) {
        ieee802154_mac_payload_t *p = &mac->payload_pool[i];
        if (!p->in_use) {
            p->in_use = true;
            p->len = 0;
            mutex_unlock(&mac->payload_pool_lock);
            return p;
        }
    }
    mutex_unlock(&mac->payload_pool_lock);
    return NULL;
}

static inline void ieee802154_mac_payload_free(ieee802154_mac_t *mac, ieee802154_mac_payload_t *p)
{
    if (!mac || !p) {
        return;
    }

    mutex_lock(&mac->payload_pool_lock);
    p->in_use = false;
    p->len = 0;
    mutex_unlock(&mac->payload_pool_lock);
}

static inline void ieee80214_mac_req_ring_init(ieee802154_mac_t *mac)
{
    ieee802154_mac_req_ring_t *r = &mac->req_ring;
    memset(r, 0, sizeof(*r));
    mutex_init(&r->lock);
}

static inline int ieee80214_mac_req_ring_push(ieee802154_mac_t *mac, const ieee802154_mac_req_t *in)
{
    ieee802154_mac_req_ring_t *r = &mac->req_ring;
    mutex_lock(&r->lock);
    if (r->cnt >= IEEE802154_MAC_REQ_RING_LEN) {
        mutex_unlock(&r->lock);
        return -ENOBUFS;
    }
    r->q[r->tail] = *in;
    r->tail = (uint8_t)((r->tail + 1) % IEEE802154_MAC_REQ_RING_LEN);
    r->cnt++;
    mutex_unlock(&r->lock);
    return 0;
}

static inline bool ieee80214_mac_req_ring_pop(ieee802154_mac_t *mac, ieee802154_mac_req_t *out)
{
    ieee802154_mac_req_ring_t *r = &mac->req_ring;
    bool ok = false;
    mutex_lock(&r->lock);
    if (r->cnt) {
        *out = r->q[r->head];
        r->head = (uint8_t)((r->head + 1) % IEEE802154_MAC_REQ_RING_LEN);
        r->cnt--;
        ok = true;
    }
    mutex_unlock(&r->lock);
    return ok;
}

static inline uint8_t ieee80214_addr_len_from_mode(ieee802154_addr_mode_t mode)
{
    switch (mode) {
    case IEEE802154_ADDR_MODE_NONE:  return 0;
    case IEEE802154_ADDR_MODE_SHORT: return IEEE802154_SHORT_ADDRESS_LEN;
    case IEEE802154_ADDR_MODE_EXTENDED:  return IEEE802154_LONG_ADDRESS_LEN;
    default:                    return 0;
    }
}

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
    IEEE802154_MAC_EV_TX ,                 /**< wakeup event */
} ieee802154_mac_ev_t;

void ieee802154_init_mac_thread(ieee802154_mac_t *mac, const ieee802154_mac_cbs_t *cbs);

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


static inline void ieee802154_mac_tx_init(ieee802154_mac_t *mac)
{
    memset(&mac->tx_ring, 0, sizeof(mac->tx_ring));
    mutex_init(&mac->tx_ring.lock);
}

/**
 * @brief Whether the TX queue is full.
 */
static inline bool ieee802154_mac_tx_full(const ieee802154_mac_t *mac)
{
    return mac->tx_ring.cnt >= IEEE802154_MAC_TXQ_LEN;
}

/**
 * @brief Whether the TX queue is empty.
 */
static inline bool ieee802154_mac_tx_empty(const ieee802154_mac_t *mac)
{
    return (mac->tx_ring.cnt == 0);
}

/**
 * @brief Returns a descriptor of TX queue head. Caller fills it.
 */
static inline ieee802154_mac_tx_desc_t * ieee802154_mac_tx_reserve(ieee802154_mac_t *mac)
{
    if (!mac || ieee802154_mac_tx_full(mac)) {
        return NULL;
    }

    ieee802154_mac_tx_desc_t *d = &mac->tx_ring.q[mac->tx_ring.tail];
    memset(d, 0, sizeof(*d));
    d->in_use = true;
    return d;
}

/**
 * @brief Advances TX queue tail to make it visible to the sender.
 */
static inline void ieee802154_mac_tx_commit(ieee802154_mac_t *mac)
{
    mac->tx_ring.tail = (uint8_t)((mac->tx_ring.tail + 1) % IEEE802154_MAC_TXQ_LEN);
    mac->tx_ring.cnt++;
}

/**
 * @brief Returns descriptor of TX queue head (next to send), does not remove.
 */
static inline ieee802154_mac_tx_desc_t * ieee802154_mac_tx_peek(ieee802154_mac_t *mac)
{
    if (!mac || ieee802154_mac_tx_empty(mac)) {
        return NULL;
    }

    ieee802154_mac_tx_desc_t *d = &mac->tx_ring.q[mac->tx_ring.head];

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

    ieee802154_mac_tx_desc_t *d = &mac->tx_ring.q[mac->tx_ring.head];
    memset(d, 0, sizeof(*d));

    mac->tx_ring.head = (uint8_t)((mac->tx_ring.head + 1) % IEEE802154_MAC_TXQ_LEN);
    mac->tx_ring.cnt--;
}
