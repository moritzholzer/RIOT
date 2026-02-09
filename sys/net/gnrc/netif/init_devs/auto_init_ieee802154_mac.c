/*
 * Copyright (C) 2026
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup sys_auto_init_gnrc_netif
 * @{
 *
 * @file
 * @brief   Auto initialization for IEEE 802.15.4 MAC netif (mac.h)
 *
 * @}
 */

#include "net/gnrc/netif.h"
#include "kernel_defines.h"
#include "net/gnrc/netif/ieee802154_mac.h"
#include "include/init_devs.h"

#if IS_USED(MODULE_GNRC_NETIF_IEEE802154_MAC)

#define IEEE802154_MAC_NETIF_STACKSIZE   (IEEE802154_STACKSIZE_DEFAULT)
#ifndef IEEE802154_MAC_DEV_TYPE
#if IS_USED(MODULE_KW2XRF)
#define IEEE802154_MAC_DEV_TYPE  (IEEE802154_DEV_TYPE_KW2XRF)
#elif IS_USED(MODULE_MRF24J40)
#define IEEE802154_MAC_DEV_TYPE  (IEEE802154_DEV_TYPE_MRF24J40)
#elif IS_USED(MODULE_NRF802154)
#define IEEE802154_MAC_DEV_TYPE  (IEEE802154_DEV_TYPE_NRF802154)
#elif IS_USED(MODULE_CC2538_RF)
#define IEEE802154_MAC_DEV_TYPE  (IEEE802154_DEV_TYPE_CC2538_RF)
#elif IS_USED(MODULE_ESP_IEEE802154)
#define IEEE802154_MAC_DEV_TYPE  (IEEE802154_DEV_TYPE_ESP_IEEE802154)
#elif IS_USED(MODULE_SOCKET_ZEP)
#define IEEE802154_MAC_DEV_TYPE  (IEEE802154_DEV_TYPE_SOCKET_ZEP)
#else
#error "IEEE802154_MAC_DEV_TYPE must be defined (e.g., -DIEEE802154_MAC_DEV_TYPE=IEEE802154_DEV_TYPE_KW2XRF)"
#endif
#endif

static char _stack[IEEE802154_MAC_NETIF_STACKSIZE];
static gnrc_netif_t _netif;
static gnrc_netif_ieee802154_mac_dev_t _dev;

void auto_init_ieee802154_mac(void)
{
    gnrc_netif_ieee802154_mac_set_dev_type(IEEE802154_MAC_DEV_TYPE);
    gnrc_netif_ieee802154_mac_create(&_netif, _stack,
                                     IEEE802154_MAC_NETIF_STACKSIZE,
                                     GNRC_NETIF_PRIO, "ieee802154_mac",
                                     &_dev);
}

#endif
