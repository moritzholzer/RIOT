/*
 * Copyright (C) 2016 Freie Universität Berlin
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 */

/**
 * @ingroup sys_auto_init_gnrc_netif
 * @{
 *
 * @file
 * @brief   Auto initialization for @ref netdev_socket_zep devices
 *
 * @author  Martine Lenders <m.lenders@fu-berlin.de>
 */

#include "kernel_defines.h"
#include "log.h"
#include "socket_zep.h"
#include "socket_zep_params.h"
#include "net/gnrc/netif/ieee802154.h"
#include "net/gnrc/netif/ieee802154_mac.h"
#include "include/init_devs.h"
#include "net/netdev/ieee802154_submac.h"

#define ENABLE_DEBUG 0
#include "debug.h"

/**
 * @brief   Define stack parameters for the MAC layer thread
 */
#define SOCKET_ZEP_MAC_STACKSIZE    (IEEE802154_STACKSIZE_DEFAULT + DEBUG_EXTRA_STACKSIZE)
#ifndef SOCKET_ZEP_MAC_PRIO
#define SOCKET_ZEP_MAC_PRIO         (GNRC_NETIF_PRIO)
#endif

/**
 * @brief   Stacks for the MAC layer threads
 */
static char _socket_zep_stacks[SOCKET_ZEP_MAX][SOCKET_ZEP_MAC_STACKSIZE];
static socket_zep_t _socket_zeps[SOCKET_ZEP_MAX];
static gnrc_netif_t _netif[SOCKET_ZEP_MAX];
#if IS_USED(MODULE_GNRC_NETIF_IEEE802154_MAC)
static gnrc_netif_ieee802154_mac_dev_t _socket_zep_netdev[SOCKET_ZEP_MAX];

static int _radio_init_cb(ieee802154_dev_t *radio, ieee802154_dev_type_t dev_type,
                          unsigned idx, void *arg)
{
    (void)dev_type;
    (void)arg;
    if (idx >= SOCKET_ZEP_MAX) {
        return -EINVAL;
    }

    socket_zep_hal_setup(&_socket_zeps[idx], radio);
    socket_zep_setup(&_socket_zeps[idx], &socket_zep_params[idx]);
    return 0;
}
#else
static netdev_ieee802154_submac_t _socket_zep_netdev[SOCKET_ZEP_MAX];
#endif

void auto_init_socket_zep(void)
{
#if IS_USED(MODULE_GNRC_NETIF_IEEE802154_MAC)
    gnrc_netif_ieee802154_mac_set_dev_type(IEEE802154_DEV_TYPE_SOCKET_ZEP);
    gnrc_netif_ieee802154_mac_set_radio_init_cb(_radio_init_cb, NULL);
#endif

    for (int i = 0; i < SOCKET_ZEP_MAX; i++) {
        LOG_DEBUG("[auto_init_netif: initializing socket ZEP device #%u\n", i);
#if IS_USED(MODULE_GNRC_NETIF_IEEE802154_MAC)
        gnrc_netif_ieee802154_mac_create(&_netif[i], _socket_zep_stacks[i],
                                         SOCKET_ZEP_MAC_STACKSIZE,
                                         SOCKET_ZEP_MAC_PRIO, "socket_zep",
                                         &_socket_zep_netdev[i]);
#else
        /* setup netdev device */
        netdev_register(&_socket_zep_netdev[i].dev.netdev, NETDEV_SOCKET_ZEP, i);
        netdev_ieee802154_submac_init(&_socket_zep_netdev[i]);
        socket_zep_hal_setup(&_socket_zeps[i], &_socket_zep_netdev[i].submac.dev);

        socket_zep_setup(&_socket_zeps[i], &socket_zep_params[i]);
        gnrc_netif_ieee802154_create(&_netif[i], _socket_zep_stacks[i],
                                     SOCKET_ZEP_MAC_STACKSIZE,
                                     SOCKET_ZEP_MAC_PRIO, "socket_zep",
                                     &_socket_zep_netdev[i].dev.netdev);
#endif
    }
}
/** @} */
