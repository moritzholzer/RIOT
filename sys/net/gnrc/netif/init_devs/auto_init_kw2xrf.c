/*
 * Copyright (C) 2015 Kaspar Schleiser <kaspar@schleiser.de>
 * Copyright (C) 2016 PHYTEC Messtechnik GmbH
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 *
 */

/*
 * @ingroup sys_auto_init_gnrc_netif
 * @{
 *
 * @file
 * @brief   Auto initialization for kw2xrf network interfaces
 *
 * @author  Kaspar Schleiser <kaspar@schleiser.de>
 * @author  Jonas Remmert <j.remmert@phytec.de>
 * @author  Sebastian Meiling <s@mlng.net>
 */

#include "kernel_defines.h"

#if IS_USED(MODULE_GNRC_NETIF_IEEE802154_MAC)

#include "log.h"
#include "net/gnrc/netif/ieee802154_mac.h"
#include "include/init_devs.h"
#include "bhp/event.h"
#include "kw2xrf.h"
#include "kw2xrf_params.h"

/**
 * @brief   Define stack parameters for the MAC layer thread
 * @{
 */
#define KW2XRF_MAC_STACKSIZE     (IEEE802154_STACKSIZE_DEFAULT + THREAD_EXTRA_STACKSIZE_PRINTF)
#ifndef KW2XRF_MAC_PRIO
#define KW2XRF_MAC_PRIO          (GNRC_NETIF_PRIO)
#endif

#define KW2XRF_NUM ARRAY_SIZE(kw2xrf_params)

static kw2xrf_t kw2xrf_devs[KW2XRF_NUM];
static gnrc_netif_ieee802154_mac_dev_t kw2xrf_netdev[KW2XRF_NUM];
static char _kw2xrf_stacks[KW2XRF_NUM][KW2XRF_MAC_STACKSIZE];
static gnrc_netif_t _netif[KW2XRF_NUM];
static bhp_event_t kw2xrf_bhp[KW2XRF_NUM];

static int _radio_init_cb(ieee802154_dev_t *radio, ieee802154_dev_type_t dev_type,
                          unsigned idx, void *arg)
{
    (void)dev_type;
    (void)arg;
    if (idx >= KW2XRF_NUM) {
        return -EINVAL;
    }

    const kw2xrf_params_t *p = &kw2xrf_params[idx];
    bhp_event_init(&kw2xrf_bhp[idx], &_netif[idx].evq[GNRC_NETIF_EVQ_INDEX_PRIO_HIGH],
                   &kw2xrf_radio_hal_irq_handler, radio);
    return kw2xrf_init(&kw2xrf_devs[idx], p, radio, bhp_event_isr_cb,
                       &kw2xrf_bhp[idx]);
}

void auto_init_kw2xrf(void)
{
    gnrc_netif_ieee802154_mac_set_dev_type(IEEE802154_DEV_TYPE_KW2XRF);
    gnrc_netif_ieee802154_mac_set_radio_init_cb(_radio_init_cb, NULL);

    for (unsigned i = 0; i < KW2XRF_NUM; i++) {
        LOG_DEBUG("[auto_init_netif] initializing kw2xrf #%u\n", i);

        gnrc_netif_ieee802154_mac_create(&_netif[i], _kw2xrf_stacks[i], KW2XRF_MAC_STACKSIZE,
                                         KW2XRF_MAC_PRIO, "kw2xrf",
                                         &kw2xrf_netdev[i]);
    }
}
/** @} */

#else /* IS_USED(MODULE_GNRC_NETIF_IEEE802154_MAC) */

#include "log.h"
#include "board.h"
#include "net/gnrc/netif/ieee802154.h"
#include "net/gnrc.h"
#include "include/init_devs.h"
#include "net/netdev/ieee802154_submac.h"
#include "bhp/event.h"

#include "kw2xrf.h"
#include "kw2xrf_params.h"

/**
 * @brief   Define stack parameters for the MAC layer thread
 * @{
 */
#define KW2XRF_MAC_STACKSIZE     (IEEE802154_STACKSIZE_DEFAULT + THREAD_EXTRA_STACKSIZE_PRINTF)
#ifndef KW2XRF_MAC_PRIO
#define KW2XRF_MAC_PRIO          (GNRC_NETIF_PRIO)
#endif

#define KW2XRF_NUM ARRAY_SIZE(kw2xrf_params)

static kw2xrf_t kw2xrf_devs[KW2XRF_NUM];
static netdev_ieee802154_submac_t kw2xrf_netdev[KW2XRF_NUM];
static char _kw2xrf_stacks[KW2XRF_NUM][KW2XRF_MAC_STACKSIZE];
static gnrc_netif_t _netif[KW2XRF_NUM];
static bhp_event_t kw2xrf_bhp[KW2XRF_NUM];

void auto_init_kw2xrf(void)
{
    for (unsigned i = 0; i < KW2XRF_NUM; i++) {
        const kw2xrf_params_t *p = &kw2xrf_params[i];

        LOG_DEBUG("[auto_init_netif] initializing kw2xrf #%u\n", i);

        /* Init Bottom Half Processor (with events module) and radio */
        bhp_event_init(&kw2xrf_bhp[i], &_netif[i].evq[GNRC_NETIF_EVQ_INDEX_PRIO_HIGH],
                       &kw2xrf_radio_hal_irq_handler, &kw2xrf_netdev[i].submac.dev);
        kw2xrf_init(&kw2xrf_devs[i], p, &kw2xrf_netdev[i].submac.dev,
                        bhp_event_isr_cb, &kw2xrf_bhp[i]);

        netdev_register(&kw2xrf_netdev[i].dev.netdev, NETDEV_KW2XRF, i);
        netdev_ieee802154_submac_init(&kw2xrf_netdev[i]);

        gnrc_netif_ieee802154_create(&_netif[i], _kw2xrf_stacks[i], KW2XRF_MAC_STACKSIZE,
                                     KW2XRF_MAC_PRIO, "kw2xrf",
                                     &kw2xrf_netdev[i].dev.netdev);

    }
}
/** @} */

#endif /* IS_USED(MODULE_GNRC_NETIF_IEEE802154_MAC) */
