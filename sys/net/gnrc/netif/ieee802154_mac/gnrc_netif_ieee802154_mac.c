/*
 * Copyright (C) 2026
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     net_gnrc_netif
 * @{
 *
 * @file
 * @brief       GNRC netif adapter for IEEE 802.15.4 MAC (mac.h)
 *
 * @}
 */

#include <assert.h>
#include <ctype.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ztimer.h"
#include "event.h"
#include "mutex.h"
#include "byteorder.h"
#include "luid.h"

#include "net/gnrc.h"
#include "net/gnrc/netif/hdr.h"
#include "net/gnrc/netif/ieee802154_mac.h"
#include "net/gnrc/netif/flags.h"
#include "net/gnrc/pktbuf.h"
#include "net/gnrc/netif/internal.h"
#include "net/gnrc/netapi.h"
#include "net/gnrc/nettype.h"
#include "net/gnrc/netif/dedup.h"


#include "net/ieee802154.h"
#include "net/ieee802154/mac.h"
#include "net/ieee802154/submac.h"
#include "net/eui_provider.h"
#include "net/eui_provider.h"

#include "net/netopt.h"
#include "net/netdev.h"
#include "net/l2util.h"
#ifdef MODULE_L2FILTER
#include "net/l2filter.h"
#endif

#define ENABLE_DEBUG 0
#include "debug.h"

#ifndef GNRC_NETIF_IEEE802154_MAC_POLL_INTERVAL_MS
#define GNRC_NETIF_IEEE802154_MAC_POLL_INTERVAL_MS (1000U)
#endif

static gnrc_netif_ieee802154_mac_dev_t *_global_dev;
static ieee802154_dev_type_t _dev_type_cfg = IEEE802154_DEV_TYPE_INVALID;
static gnrc_netif_ieee802154_mac_radio_init_cb_t _radio_init_cb;
static void *_radio_init_arg;
static unsigned _radio_init_idx;
mutex_t assoc_lock;
static int _netdev_init(netdev_t *dev);
static int _netdev_send(netdev_t *dev, const iolist_t *iolist);
static int _netdev_recv(netdev_t *dev, void *buf, size_t len, void *info);
static void _netdev_isr(netdev_t *dev);
static int _netdev_get(netdev_t *dev, netopt_t opt, void *value, size_t max_len);
static int _netdev_set(netdev_t *dev, netopt_t opt, const void *value, size_t len);
static int _netdev_confirm_send(netdev_t *dev, void *info);
#if IS_USED(MODULE_SHELL_CMD_IWPAN)
extern void iwpan_scan_confirm(void *arg, int status,
                               ieee802154_mlme_scan_req_t *req);
extern void iwpan_associate_confirm(void *arg, int status, uint16_t short_addr);
#endif
static void _mac_scan_confirm(void *arg, int status, ieee802154_mlme_scan_req_t *req);
static void _mac_associate_indication(void *arg, const uint8_t *device_addr,
                                      uint8_t device_addr_len,
                                      ieee802154_addr_mode_t device_addr_mode,
                                      ieee802154_assoc_capability_t cap);
static void _poll_timer_cb(void *arg);

static const netdev_driver_t _netdev_driver = {
    .init = _netdev_init,
    .send = _netdev_send,
    .recv = _netdev_recv,
    .isr = _netdev_isr,
    .get = _netdev_get,
    .set = _netdev_set,
    .confirm_send = _netdev_confirm_send,
};

static int _send(gnrc_netif_t *netif, gnrc_pktsnip_t *pkt);
static gnrc_pktsnip_t *_recv(gnrc_netif_t *netif);

static const gnrc_netif_ops_t _ops = {
    .init = gnrc_netif_default_init,
    .send = _send,
    .recv = _recv,
    .get = gnrc_netif_get_from_netdev,
    .set = gnrc_netif_set_from_netdev,
};

static inline gnrc_netif_ieee802154_mac_dev_t *_dev_from_mac(ieee802154_mac_t *mac)
{
    return container_of(mac, gnrc_netif_ieee802154_mac_dev_t, mac);
}

static inline gnrc_netif_ieee802154_mac_dev_t *_dev_from_netdev(netdev_t *dev)
{
    return container_of(dev, gnrc_netif_ieee802154_mac_dev_t, netdev);
}

static inline gnrc_pktsnip_t *_pkt_from_iolist(iolist_t *iol)
{
    return (gnrc_pktsnip_t *)iol;
}

static iolist_t *_mac_buf_alloc(gnrc_netif_ieee802154_mac_dev_t *dev, size_t len)
{
    (void)dev;
    if ((len == 0) || (len > IEEE802154_FRAME_LEN_MAX)) {
        return NULL;
    }
    gnrc_pktsnip_t *pkt = gnrc_pktbuf_add(NULL, NULL, len, GNRC_NETTYPE_UNDEF);
    if (!pkt) {
        return NULL;
    }
    return (iolist_t *)pkt;
}

static void _mac_buf_free(gnrc_netif_ieee802154_mac_dev_t *dev, gnrc_pktsnip_t *p)
{
    if (!p) {
        return;
    }
    (void)dev;
    gnrc_pktbuf_release(p);
}

static netdev_type_t _netdev_type_from_devtype(ieee802154_dev_type_t dev_type)
{
    switch (dev_type) {
        case IEEE802154_DEV_TYPE_CC2538_RF:
            return NETDEV_CC2538;
        case IEEE802154_DEV_TYPE_NRF802154:
            return NETDEV_NRF802154;
        case IEEE802154_DEV_TYPE_SOCKET_ZEP:
            return NETDEV_SOCKET_ZEP;
        case IEEE802154_DEV_TYPE_KW2XRF:
            return NETDEV_KW2XRF;
        case IEEE802154_DEV_TYPE_AT86RF2XX:
            return NETDEV_AT86RF2XX;
        case IEEE802154_DEV_TYPE_MRF24J40:
            return NETDEV_MRF24J40;
        case IEEE802154_DEV_TYPE_ESP_IEEE802154:
            return NETDEV_ESP_IEEE802154;
        default:
            return NETDEV_KW2XRF;
    }
}

static int _rxq_push(gnrc_netif_ieee802154_mac_dev_t *dev,
                     gnrc_pktsnip_t *pkt,
                     const ieee802154_rx_info_t *info)
{
    int res = 0;

    mutex_lock(&dev->rx_lock);
    if (dev->rxq_len >= GNRC_NETIF_IEEE802154_MAC_RX_BUF_NUM) {
        res = -ENOBUFS;
        goto out;
    }

    dev->rxq[dev->rxq_tail].pkt = pkt;
    dev->rxq[dev->rxq_tail].info = *info;
    dev->rxq_tail = (uint8_t)((dev->rxq_tail + 1) % GNRC_NETIF_IEEE802154_MAC_RX_BUF_NUM);
    dev->rxq_len++;

out:
    mutex_unlock(&dev->rx_lock);
    return res;
}

static gnrc_netif_ieee802154_mac_rx_entry_t _rxq_pop(gnrc_netif_ieee802154_mac_dev_t *dev)
{
    gnrc_netif_ieee802154_mac_rx_entry_t entry = { .pkt = NULL };

    mutex_lock(&dev->rx_lock);
    if (dev->rxq_len == 0) {
        mutex_unlock(&dev->rx_lock);
        return entry;
    }

    entry = dev->rxq[dev->rxq_head];
    dev->rxq_head = (uint8_t)((dev->rxq_head + 1) % GNRC_NETIF_IEEE802154_MAC_RX_BUF_NUM);
    dev->rxq_len--;
    mutex_unlock(&dev->rx_lock);
    return entry;
}

static void _ev_alloc_handler(event_t *event)
{
    gnrc_netif_ieee802154_mac_dev_t *dev =
        container_of(event, gnrc_netif_ieee802154_mac_dev_t, ev_alloc);
    iolist_t *buf = _mac_buf_alloc(dev, dev->rx_alloc_len);

    if (!buf) {
        return;
    }
    ieee802154_mac_rx_process(&dev->mac, buf);
}

static void _ev_rx_handler(event_t *event)
{
    gnrc_netif_ieee802154_mac_dev_t *dev =
        container_of(event, gnrc_netif_ieee802154_mac_dev_t, ev_rx);
    (void)ieee802154_set_rx(&dev->mac.submac);
}

static void _ev_tick_handler(event_t *event)
{
    gnrc_netif_ieee802154_mac_dev_t *dev =
        container_of(event, gnrc_netif_ieee802154_mac_dev_t, ev_tick);
    ieee802154_mac_tick(&dev->mac);
}

static void _ev_scan_timer_handler(event_t *event)
{
    gnrc_netif_ieee802154_mac_dev_t *dev =
        container_of(event, gnrc_netif_ieee802154_mac_dev_t, ev_scan_timer);
    ieee802154_mac_scan_timer_process(&dev->mac);
}

static void _ev_ack_timeout_handler(event_t *event)
{
    gnrc_netif_ieee802154_mac_dev_t *dev =
        container_of(event, gnrc_netif_ieee802154_mac_dev_t, ev_ack_timeout);
    ieee802154_mac_ack_timeout_fired(&dev->mac);
}

static void _ev_assoc_res_handler(event_t *event)
{
    gnrc_netif_ieee802154_mac_dev_t *dev =
        container_of(event, gnrc_netif_ieee802154_mac_dev_t, ev_assoc_res);
    mutex_lock(&assoc_lock);
    if (!dev->assoc_res_pending) {
        return;
    }
#if IS_USED(MODULE_SHELL_CMD_IWPAN)
    char addr_str[3 * IEEE802154_LONG_ADDRESS_LEN];
    if (dev->assoc_res_dst.type == IEEE802154_ADDR_MODE_SHORT) {
        snprintf(addr_str, sizeof(addr_str), "0x%04x", dev->assoc_res_short_addr);
    }
    else {
        l2util_addr_to_str(dev->assoc_res_dst.v.ext_addr.uint8,
                           IEEE802154_LONG_ADDRESS_LEN, addr_str);
    }
    printf("ASSOC indication from %s, status=%u\n",
           addr_str, (unsigned)dev->assoc_res_status);
#endif

    dev->assoc_res_pending = false;
    int res = ieee802154_mac_mlme_associate_response(&dev->mac,
                                                     &dev->assoc_res_dst,
                                                     dev->assoc_res_status,
                                                     dev->assoc_res_short_addr);
#if IS_USED(MODULE_SHELL_CMD_IWPAN)
    if (res < 0) {
        printf("ASSOC response failed: %d (%s)\n", res, strerror(-res));
    }
    else {
        printf("ASSOC response sent: status=%u short_addr=0x%04x\n",
               (unsigned)dev->assoc_res_status, dev->assoc_res_short_addr);
    }
#endif
    if (res < 0) {
        DEBUG("IEEE802154 MAC: auto-assoc response failed (%d)\n", res);
    }
    mutex_unlock(&assoc_lock);
}

static void _ev_bh_request_handler(event_t *event)
{
    gnrc_netif_ieee802154_mac_dev_t *dev =
        container_of(event, gnrc_netif_ieee802154_mac_dev_t, ev_bh_request);
    ieee802154_mac_bh_process(&dev->mac);
}

static void _ev_poll_handler(event_t *event)
{
    gnrc_netif_ieee802154_mac_dev_t *dev =
        container_of(event, gnrc_netif_ieee802154_mac_dev_t, ev_poll);

    if (dev->mac.state == IEEE802154_MAC_STATE_DEVICE) {
        ieee802154_pib_value_t panid;
        ieee802154_pib_value_t coord_short;
        ieee802154_pib_value_t coord_ext;

        ieee802154_mac_mlme_get_request(&dev->mac, IEEE802154_PIB_PAN_ID, &panid);
        ieee802154_mac_mlme_get_request(&dev->mac, IEEE802154_PIB_COORD_SHORT_ADDRESS, &coord_short);
        ieee802154_mac_mlme_get_request(&dev->mac, IEEE802154_PIB_COORD_EXTENDED_ADDRESS, &coord_ext);

        if (coord_short.v.short_addr.u16 != 0xffff) {
            (void)ieee802154_mac_mlme_poll(&dev->mac, IEEE802154_ADDR_MODE_SHORT,
                                           panid.v.u16, &coord_short.v.short_addr);
        }
        else {
            (void)ieee802154_mac_mlme_poll(&dev->mac, IEEE802154_ADDR_MODE_EXTENDED,
                                           panid.v.u16, &coord_ext.v.ext_addr);
        }
    }

    if (dev->poll_interval_ms > 0) {
        ztimer_set(ZTIMER_MSEC, &dev->poll_timer, dev->poll_interval_ms);
    }
}

static void _ev_radio_handler(event_t *event)
{
    gnrc_netif_ieee802154_mac_dev_t *dev =
        container_of(event, gnrc_netif_ieee802154_mac_dev_t, ev_radio);
    if (dev->radio_dev) {
        ieee802154_mac_handle_radio(dev->radio_dev, dev->radio_ev);
    }
}

static void _mac_data_confirm(void *arg, uint8_t handle, int status)
{
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;
    gnrc_netif_ieee802154_mac_dev_t *dev = _dev_from_mac(mac);
    (void)status;

    (void)handle;

    mutex_lock(&dev->tx_lock);
    dev->last_tx_status = status;
    dev->tx_done = true;
    mutex_unlock(&dev->tx_lock);
    if (dev->netif && dev->netif->dev && dev->netif->dev->event_callback) {
        dev->netif->dev->event_callback(dev->netif->dev, NETDEV_EVENT_TX_COMPLETE);
    }
}

static void _mac_data_indication(void *arg, iolist_t *psdu,
                                 const ieee802154_rx_info_t *info)
{
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;
    gnrc_netif_ieee802154_mac_dev_t *dev = _dev_from_mac(mac);
    gnrc_pktsnip_t *pkt = _pkt_from_iolist(psdu);

    if (!dev->netif || !info) {
        _mac_buf_free(dev, pkt);
        return;
    }

    if (_rxq_push(dev, pkt, info) < 0) {
        _mac_buf_free(dev, pkt);
        return;
    }

    dev->netif->dev->event_callback(dev->netif->dev, NETDEV_EVENT_RX_COMPLETE);
}

static void _mac_associate_indication(void *arg, const uint8_t *device_addr,
                                      uint8_t device_addr_len,
                                      ieee802154_addr_mode_t device_addr_mode,
                                      ieee802154_assoc_capability_t cap)
{
    (void)cap;
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;
    gnrc_netif_ieee802154_mac_dev_t *dev = _dev_from_mac(mac);
    ieee802154_addr_t dst_addr;
    ieee802154_assoc_status_t status = IEEE802154_ASSOC_STATUS_SUCCESS;
    uint16_t short_addr = 0xFFFE;

    if (!device_addr || (device_addr_len == 0)) {
        return;
    }

    if ((device_addr_mode == IEEE802154_ADDR_MODE_SHORT) &&
        (device_addr_len == IEEE802154_SHORT_ADDRESS_LEN)) {
        dst_addr.type = IEEE802154_ADDR_MODE_SHORT;
        dst_addr.v.short_addr.u8[0] = device_addr[0];
        dst_addr.v.short_addr.u8[1] = device_addr[1];
        short_addr = byteorder_ntohs(dst_addr.v.short_addr);
    }
    else if ((device_addr_mode == IEEE802154_ADDR_MODE_EXTENDED) &&
             (device_addr_len == IEEE802154_LONG_ADDRESS_LEN)) {
        dst_addr.type = IEEE802154_ADDR_MODE_EXTENDED;
        memcpy(dst_addr.v.ext_addr.uint8, device_addr, IEEE802154_LONG_ADDRESS_LEN);
        network_uint16_t short_n;
        eui_short_from_eui64(&dst_addr.v.ext_addr, &short_n);
        short_addr = byteorder_ntohs(short_n);
    }
    else {
        status = IEEE802154_ASSOC_STATUS_PAN_ACCESS_DENIED;
        return;
    }
    mutex_lock(&assoc_lock);
    dev->assoc_res_dst = dst_addr;
    dev->assoc_res_status = status;
    dev->assoc_res_short_addr = short_addr;
    dev->assoc_res_pending = true;
    mutex_unlock(&assoc_lock);
    event_post(&dev->netif->evq[GNRC_NETIF_EVQ_INDEX_PRIO_HIGH], &dev->ev_assoc_res);
}

static void _mac_dealloc_request(void *arg, iolist_t *iolist)
{
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;
    gnrc_netif_ieee802154_mac_dev_t *dev = _dev_from_mac(mac);
    gnrc_pktsnip_t *pkt = _pkt_from_iolist(iolist);
    _mac_buf_free(dev, pkt);
}

static void _mac_scan_timer_request(void *arg)
{
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;
    gnrc_netif_ieee802154_mac_dev_t *dev = _dev_from_mac(mac);
    event_post(&dev->netif->evq[GNRC_NETIF_EVQ_INDEX_PRIO_HIGH], &dev->ev_scan_timer);
}

static void _mac_tick_request(void *arg)
{
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;
    gnrc_netif_ieee802154_mac_dev_t *dev = _dev_from_mac(mac);
    event_post(&dev->netif->evq[GNRC_NETIF_EVQ_INDEX_PRIO_HIGH], &dev->ev_tick);
}

static void _mac_bh_request(void *arg)
{
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;
    gnrc_netif_ieee802154_mac_dev_t *dev = _dev_from_mac(mac);
    event_post(&dev->netif->evq[GNRC_NETIF_EVQ_INDEX_PRIO_HIGH], &dev->ev_bh_request);
}

static void _mac_ack_timeout(void *arg)
{
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;
    gnrc_netif_ieee802154_mac_dev_t *dev = _dev_from_mac(mac);
    event_post(&dev->netif->evq[GNRC_NETIF_EVQ_INDEX_PRIO_HIGH], &dev->ev_ack_timeout);
}

static void _mac_allocate_request(void *arg, size_t len)
{
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;
    gnrc_netif_ieee802154_mac_dev_t *dev = _dev_from_mac(mac);
    if ((len == 0) || (len > IEEE802154_FRAME_LEN_MAX)) {
        dev->rx_alloc_len = IEEE802154_FRAME_LEN_MAX;
    }
    else {
        dev->rx_alloc_len = len;
    }
    event_post(&dev->netif->evq[GNRC_NETIF_EVQ_INDEX_PRIO_HIGH], &dev->ev_alloc);
}

static void _mac_rx_request(void *arg)
{
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;
    gnrc_netif_ieee802154_mac_dev_t *dev = _dev_from_mac(mac);
    event_post(&dev->netif->evq[GNRC_NETIF_EVQ_INDEX_PRIO_HIGH], &dev->ev_rx);
}

static void _mac_radio_cb(ieee802154_dev_t *dev, ieee802154_trx_ev_t st)
{
    ieee802154_mac_t *mac = container_of(dev, ieee802154_mac_t, submac.dev);
    gnrc_netif_ieee802154_mac_dev_t *mdev = _dev_from_mac(mac);

    mdev->radio_dev = dev;
    mdev->radio_ev = st;
    event_post(&mdev->netif->evq[GNRC_NETIF_EVQ_INDEX_PRIO_HIGH], &mdev->ev_radio);
}

static void _poll_timer_cb(void *arg)
{
    gnrc_netif_ieee802154_mac_dev_t *dev = arg;
    if (!dev->netif) {
        return;
    }
    event_post(&dev->netif->evq[GNRC_NETIF_EVQ_INDEX_PRIO_HIGH], &dev->ev_poll);
}

static void _mac_scan_confirm(void *arg, int status, ieee802154_mlme_scan_req_t *req)
{
#if IS_USED(MODULE_SHELL_CMD_IWPAN)
    iwpan_scan_confirm(arg, status, req);
#else
    (void)arg;
    (void)status;
    (void)req;
#endif
}

ieee802154_mac_t *gnrc_netif_ieee802154_mac_get(void)
{
    if (!_global_dev) {
        return NULL;
    }
    return &_global_dev->mac;
}

void gnrc_netif_ieee802154_mac_set_dev_type(ieee802154_dev_type_t dev_type)
{
    _dev_type_cfg = dev_type;
}

void gnrc_netif_ieee802154_mac_set_radio_init_cb(gnrc_netif_ieee802154_mac_radio_init_cb_t cb,
                                                 void *arg)
{
    _radio_init_cb = cb;
    _radio_init_arg = arg;
    _radio_init_idx = 0;
}


static gnrc_pktsnip_t *_make_netif_hdr(uint8_t *mhr)
{
    gnrc_netif_hdr_t *hdr;
    gnrc_pktsnip_t *snip;
    uint8_t src[IEEE802154_LONG_ADDRESS_LEN], dst[IEEE802154_LONG_ADDRESS_LEN];
    int src_len, dst_len;
    le_uint16_t _pan_tmp;

    dst_len = ieee802154_get_dst(mhr, dst, &_pan_tmp);
    src_len = ieee802154_get_src(mhr, src, &_pan_tmp);
    if ((dst_len < 0) || (src_len <= 0)) {
        DEBUG("_make_netif_hdr: unable to get addresses\n");
        return NULL;
    }
    snip = gnrc_netif_hdr_build(src, (size_t)src_len, dst, (size_t)dst_len);
    if (snip == NULL) {
        DEBUG("_make_netif_hdr: no space left in packet buffer\n");
        return NULL;
    }
    hdr = snip->data;
    if ((dst_len == 2) && (dst[0] == 0xff) && (dst[1] == 0xff)) {
        hdr->flags |= GNRC_NETIF_HDR_FLAGS_BROADCAST;
    }
    if (mhr[0] & IEEE802154_FCF_FRAME_PEND) {
        hdr->flags |= GNRC_NETIF_HDR_FLAGS_MORE_DATA;
    }
    return snip;
}

#if MODULE_GNRC_NETIF_DEDUP
static inline bool _already_received(gnrc_netif_t *netif,
                                     gnrc_netif_hdr_t *netif_hdr,
                                     uint8_t *mhr)
{
    const uint8_t seq = ieee802154_get_seq(mhr);

    return  (netif->last_pkt.seq == seq) &&
            (netif->last_pkt.src_len == netif_hdr->src_l2addr_len) &&
            (memcmp(netif->last_pkt.src, gnrc_netif_hdr_get_src_addr(netif_hdr),
                    netif_hdr->src_l2addr_len) == 0);
}
#endif

static gnrc_pktsnip_t *_recv(gnrc_netif_t *netif)
{
    gnrc_netif_ieee802154_mac_dev_t *dev = _dev_from_netdev(netif->dev);
    gnrc_netif_ieee802154_mac_rx_entry_t entry = _rxq_pop(dev);
    gnrc_pktsnip_t *pkt = NULL;

    if (!entry.pkt) {
        return NULL;
    }

    int nread = (int)entry.pkt->size;
    ieee802154_rx_info_t rx_info = entry.info;

    if (nread >= (int)IEEE802154_MIN_FRAME_LEN) {
        pkt = entry.pkt;

#ifdef MODULE_NETSTATS_L2
        netif->stats.rx_count++;
        netif->stats.rx_bytes += nread;
#endif

        if (netif->flags & GNRC_NETIF_FLAGS_RAWMODE) {
            gnrc_pktsnip_t *netif_snip = gnrc_netif_hdr_build(NULL, 0, NULL, 0);
            if (netif_snip == NULL) {
                DEBUG("_recv_ieee802154_mac: no space left in packet buffer\n");
                gnrc_pktbuf_release(pkt);
                return NULL;
            }
            gnrc_netif_hdr_t *hdr = netif_snip->data;
            hdr->lqi = rx_info.lqi;
            hdr->rssi = rx_info.rssi;
#if IS_USED(MODULE_GNRC_NETIF_TIMESTAMP)
            if (ieee802154_radio_has_capability(&dev->mac.submac.dev,
                                                IEEE802154_CAP_RX_TIMESTAMP)) {
                gnrc_netif_hdr_set_timestamp(hdr, rx_info.timestamp);
            }
#endif
            gnrc_netif_hdr_set_netif(hdr, netif);
            pkt = gnrc_pkt_append(pkt, netif_snip);
        }
        else {
            gnrc_pktsnip_t *ieee802154_hdr, *netif_hdr;
            gnrc_netif_hdr_t *hdr;
            size_t mhr_len = ieee802154_get_frame_hdr_len(pkt->data);
            uint8_t *mhr = pkt->data;
            if ((mhr_len == 0) || ((size_t)nread < mhr_len)) {
                DEBUG("_recv_ieee802154_mac: illegally formatted frame received\n");
                gnrc_pktbuf_release(pkt);
                return NULL;
            }
            netif_hdr = _make_netif_hdr(mhr);
            if (netif_hdr == NULL) {
                DEBUG("_recv_ieee802154_mac: no space left in packet buffer\n");
                gnrc_pktbuf_release(pkt);
                return NULL;
            }
            hdr = netif_hdr->data;

#ifdef MODULE_L2FILTER
            if (!l2filter_pass(netif->dev->filter, gnrc_netif_hdr_get_src_addr(hdr),
                               hdr->src_l2addr_len)) {
                gnrc_pktbuf_release(pkt);
                gnrc_pktbuf_release(netif_hdr);
                DEBUG("_recv_ieee802154_mac: packet dropped by l2filter\n");
                return NULL;
            }
#endif
#ifdef MODULE_GNRC_NETIF_DEDUP
            if (_already_received(netif, hdr, mhr)) {
                gnrc_pktbuf_release(pkt);
                gnrc_pktbuf_release(netif_hdr);
                DEBUG("_recv_ieee802154_mac: packet dropped by deduplication\n");
                return NULL;
            }
            memcpy(netif->last_pkt.src, gnrc_netif_hdr_get_src_addr(hdr),
                   hdr->src_l2addr_len);
            netif->last_pkt.src_len = hdr->src_l2addr_len;
            netif->last_pkt.seq = ieee802154_get_seq(mhr);
#endif
            hdr->lqi = rx_info.lqi;
            hdr->rssi = rx_info.rssi;
#if IS_USED(MODULE_GNRC_NETIF_TIMESTAMP)
            if (ieee802154_radio_has_capability(&dev->mac.submac.dev,
                                                IEEE802154_CAP_RX_TIMESTAMP)) {
                gnrc_netif_hdr_set_timestamp(hdr, rx_info.timestamp);
            }
#endif
            gnrc_netif_hdr_set_netif(hdr, netif);
            _netdev_get(netif->dev, NETOPT_PROTO, &pkt->type, sizeof(pkt->type));

            ieee802154_hdr = gnrc_pktbuf_mark(pkt, mhr_len, GNRC_NETTYPE_UNDEF);
            if (ieee802154_hdr == NULL) {
                DEBUG("_recv_ieee802154_mac: no space left in packet buffer\n");
                gnrc_pktbuf_release(pkt);
                gnrc_pktbuf_release(netif_hdr);
                return NULL;
            }
            nread -= (int)ieee802154_hdr->size;
            gnrc_pktbuf_remove_snip(pkt, ieee802154_hdr);
            pkt = gnrc_pkt_append(pkt, netif_hdr);
        }

        gnrc_pktbuf_realloc_data(pkt, (size_t)nread);
    }

    return pkt;
}

static int _send(gnrc_netif_t *netif, gnrc_pktsnip_t *pkt)
{
    gnrc_netif_ieee802154_mac_dev_t *dev = _dev_from_netdev(netif->dev);
    gnrc_netif_hdr_t *netif_hdr;
    const uint8_t *dst = NULL;
    size_t dst_len;
    ieee802154_addr_mode_t dst_mode;
    ieee802154_addr_mode_t src_mode;
    int res;
    size_t payload_len;

    if (!pkt || (pkt->type != GNRC_NETTYPE_NETIF)) {
        return -EBADMSG;
    }
    netif_hdr = pkt->data;

    if (netif_hdr->flags &
        (GNRC_NETIF_HDR_FLAGS_BROADCAST | GNRC_NETIF_HDR_FLAGS_MULTICAST)) {
        dst = ieee802154_addr_bcast;
        dst_len = IEEE802154_ADDR_BCAST_LEN;
    }
    else {
        dst = gnrc_netif_hdr_get_dst_addr(netif_hdr);
        dst_len = netif_hdr->dst_l2addr_len;
    }

    if (dst_len == IEEE802154_SHORT_ADDRESS_LEN) {
        dst_mode = IEEE802154_ADDR_MODE_SHORT;
    }
    else if (dst_len == IEEE802154_LONG_ADDRESS_LEN) {
        dst_mode = IEEE802154_ADDR_MODE_EXTENDED;
    }
    else {
        return -EINVAL;
    }

    if (netif_hdr->src_l2addr_len == IEEE802154_SHORT_ADDRESS_LEN) {
        src_mode = IEEE802154_ADDR_MODE_SHORT;
    }
    else if (netif_hdr->src_l2addr_len == IEEE802154_LONG_ADDRESS_LEN) {
        src_mode = IEEE802154_ADDR_MODE_EXTENDED;
    }
    else {
        src_mode = IEEE802154_ADDR_MODE_EXTENDED;
    }

    ieee802154_pib_value_t panid;
    ieee802154_mac_mlme_get_request(&dev->mac, IEEE802154_PIB_PAN_ID, &panid);

    bool ack_req = !(netif_hdr->flags &
                     (GNRC_NETIF_HDR_FLAGS_BROADCAST | GNRC_NETIF_HDR_FLAGS_MULTICAST));

    payload_len = gnrc_pkt_len(pkt->next);
    if (payload_len > IEEE802154_FRAME_LEN_MAX) {
        return -EMSGSIZE;
    }

    res = ieee802154_mcps_data_request(&dev->mac,
                                       src_mode, dst_mode,
                                       panid.v.u16,
                                       dst,
                                       (iolist_t *)pkt->next,
                                       0xFF,
                                       ack_req,
                                       dev->tx_indirect);
    if (res < 0) {
        return res;
    }
    if (gnrc_netif_netdev_new_api(netif)) {
        return 0;
    }
    return (int)payload_len;
}

static int _netdev_init(netdev_t *dev)
{
    gnrc_netif_ieee802154_mac_dev_t *mdev = _dev_from_netdev(dev);
    assert(_dev_type_cfg != IEEE802154_DEV_TYPE_INVALID);

    netdev_register(dev, _netdev_type_from_devtype(_dev_type_cfg), 0);
    dev->driver = &_netdev_driver;

    mutex_init(&assoc_lock);
    mutex_init(&mdev->rx_lock);
    mutex_init(&mdev->tx_lock);
    memset(mdev->rxq, 0, sizeof(mdev->rxq));
    mdev->tx_done = false;
    mdev->last_tx_status = 0;
    mdev->rx_alloc_len = 0;

    mdev->ev_alloc.handler = _ev_alloc_handler;
    mdev->ev_rx.handler = _ev_rx_handler;
    mdev->ev_tick.handler = _ev_tick_handler;
    mdev->ev_scan_timer.handler = _ev_scan_timer_handler;
    mdev->ev_ack_timeout.handler = _ev_ack_timeout_handler;
    mdev->ev_assoc_res.handler = _ev_assoc_res_handler;
    mdev->ev_bh_request.handler = _ev_bh_request_handler;
    mdev->ev_radio.handler = _ev_radio_handler;
    mdev->ev_poll.handler = _ev_poll_handler;

    if (_radio_init_cb) {
        int res = _radio_init_cb(&mdev->mac.submac.dev, _dev_type_cfg,
                                 _radio_init_idx++, _radio_init_arg);
        if (res < 0) {
            return res;
        }
    }

    ieee802154_mac_cbs_t cbs = {
        .data_confirm = _mac_data_confirm,
        .data_indication = _mac_data_indication,
        .mlme_scan_confirm = _mac_scan_confirm,
        .mlme_start_confirm = NULL,
        .mlme_associate_indication = _mac_associate_indication,
        .mlme_associate_confirm =
#if IS_USED(MODULE_SHELL_CMD_IWPAN)
            iwpan_associate_confirm,
#else
            NULL,
#endif
        .ack_timeout = _mac_ack_timeout,
        .bh_request = _mac_bh_request,
        .radio_cb_request = _mac_radio_cb,
        .scan_timer_request = _mac_scan_timer_request,
        .tick_request = _mac_tick_request,
        .allocate_request = _mac_allocate_request,
        .dealloc_request = _mac_dealloc_request,
        .rx_request = _mac_rx_request,
    };

    ieee802154_mac_init_with_devtype(&mdev->mac, &cbs, _dev_type_cfg);

    ieee802154_pib_value_t pib_value;
    eui64_t long_addr;

    luid_base(&long_addr, sizeof(long_addr));
    eui64_set_local(&long_addr);
    eui64_clear_group(&long_addr);

    pib_value.type = IEEE802154_PIB_TYPE_EUI64;
    pib_value.v.ext_addr = long_addr;
    ieee802154_mac_mlme_set_request(&mdev->mac, IEEE802154_PIB_EXTENDED_ADDRESS, &pib_value);

    pib_value.type = IEEE802154_PIB_TYPE_NUI16;
    pib_value.v.short_addr = byteorder_htons(0xffff);
    ieee802154_mac_mlme_set_request(&mdev->mac, IEEE802154_PIB_SHORT_ADDR, &pib_value);

    #if IS_USED(MODULE_GNRC_NETTYPE_SIXLOWPAN)
    mdev->proto = GNRC_NETTYPE_SIXLOWPAN;
    #else
    mdev->proto = GNRC_NETTYPE_UNDEF;
    #endif

    mdev->poll_timer.callback = _poll_timer_cb;
    mdev->poll_timer.arg = mdev;
    mdev->poll_interval_ms = GNRC_NETIF_IEEE802154_MAC_POLL_INTERVAL_MS;
    if (mdev->poll_interval_ms > 0) {
        ztimer_set(ZTIMER_MSEC, &mdev->poll_timer, mdev->poll_interval_ms);
    }
    return 0;
}

static int _netdev_send(netdev_t *dev, const iolist_t *iolist)
{
    (void)dev;
    (void)iolist;
    return -ENOTSUP;
}

static int _netdev_recv(netdev_t *dev, void *buf, size_t len, void *info)
{
    (void)dev;
    (void)buf;
    (void)len;
    (void)info;
    return -ENOTSUP;
}

static void _netdev_isr(netdev_t *dev)
{
    (void)dev;
}

static int _netdev_get(netdev_t *dev, netopt_t opt, void *value, size_t max_len)
{
    gnrc_netif_ieee802154_mac_dev_t *mdev = _dev_from_netdev(dev);
    int res = -ENOTSUP;

    switch (opt) {
        case NETOPT_DEVICE_TYPE: {
            assert(max_len == sizeof(uint16_t));
            *((uint16_t *)value) = NETDEV_TYPE_IEEE802154;
            res = sizeof(uint16_t);
            break;
        }
        case NETOPT_PROTO: {
            assert(max_len == sizeof(gnrc_nettype_t));
            *((gnrc_nettype_t *)value) = mdev->proto;
            res = sizeof(gnrc_nettype_t);
            break;
        }
        case NETOPT_ADDRESS: {
            ieee802154_pib_value_t v;
            ieee802154_mac_mlme_get_request(&mdev->mac, IEEE802154_PIB_SHORT_ADDR, &v);
            assert(max_len >= sizeof(v.v.short_addr));
            memcpy(value, &v.v.short_addr, sizeof(v.v.short_addr));
            res = sizeof(v.v.short_addr);
            break;
        }
        case NETOPT_ADDRESS_LONG: {
            ieee802154_pib_value_t v;
            ieee802154_mac_mlme_get_request(&mdev->mac, IEEE802154_PIB_EXTENDED_ADDRESS, &v);
            assert(max_len >= sizeof(v.v.ext_addr));
            memcpy(value, &v.v.ext_addr, sizeof(v.v.ext_addr));
            res = sizeof(v.v.ext_addr);
            break;
        }
        case NETOPT_SRC_LEN: {
            ieee802154_pib_value_t v;
            ieee802154_mac_mlme_get_request(&mdev->mac, IEEE802154_PIB_SHORT_ADDR, &v);
            uint16_t len = (byteorder_ntohs(v.v.short_addr) == 0xffff)
                ? IEEE802154_LONG_ADDRESS_LEN
                : IEEE802154_SHORT_ADDRESS_LEN;
            assert(max_len == sizeof(uint16_t));
            *((uint16_t *)value) = len;
            res = sizeof(uint16_t);
            break;
        }
        case NETOPT_NID: {
            ieee802154_pib_value_t v;
            ieee802154_mac_mlme_get_request(&mdev->mac, IEEE802154_PIB_PAN_ID, &v);
            assert(max_len == sizeof(uint16_t));
            *((uint16_t *)value) = v.v.u16;
            res = sizeof(uint16_t);
            break;
        }
        case NETOPT_CHANNEL: {
            assert(max_len == sizeof(uint16_t));
            *((uint16_t *)value) = mdev->mac.submac.channel_num;
            res = sizeof(uint16_t);
            break;
        }
        case NETOPT_TX_POWER: {
            assert(max_len == sizeof(int16_t));
            *((int16_t *)value) = mdev->mac.submac.tx_pow;
            res = sizeof(int16_t);
            break;
        }
        case NETOPT_TX_INDIRECT: {
            assert(max_len == sizeof(netopt_enable_t));
            *((netopt_enable_t *)value) = mdev->tx_indirect ? NETOPT_ENABLE : NETOPT_DISABLE;
            res = sizeof(netopt_enable_t);
            break;
        }
        default:
            break;
    }
    return res;
}

static int _netdev_set(netdev_t *dev, netopt_t opt, const void *value, size_t len)
{
    gnrc_netif_ieee802154_mac_dev_t *mdev = _dev_from_netdev(dev);
    int res = -ENOTSUP;

    switch (opt) {
        case NETOPT_PROTO:
            assert(len == sizeof(gnrc_nettype_t));
            mdev->proto = *((const gnrc_nettype_t *)value);
            res = sizeof(gnrc_nettype_t);
            break;
        case NETOPT_ADDRESS: {
            ieee802154_pib_value_t v = {
                .type = IEEE802154_PIB_TYPE_NUI16,
            };
            assert(len == sizeof(v.v.short_addr));
            memcpy(&v.v.short_addr, value, len);
            ieee802154_mac_mlme_set_request(&mdev->mac, IEEE802154_PIB_SHORT_ADDR, &v);
            res = len;
            break;
        }
        case NETOPT_ADDRESS_LONG: {
            ieee802154_pib_value_t v = {
                .type = IEEE802154_PIB_TYPE_EUI64,
            };
            assert(len == sizeof(v.v.ext_addr));
            memcpy(&v.v.ext_addr, value, len);
            ieee802154_mac_mlme_set_request(&mdev->mac, IEEE802154_PIB_EXTENDED_ADDRESS, &v);
            res = len;
            break;
        }
        case NETOPT_NID: {
            ieee802154_pib_value_t v = {
                .type = IEEE802154_PIB_TYPE_U16,
                .v.u16 = *((const uint16_t *)value),
            };
            assert(len == sizeof(uint16_t));
            ieee802154_mac_mlme_set_request(&mdev->mac, IEEE802154_PIB_PAN_ID, &v);
            res = len;
            break;
        }
        case NETOPT_CHANNEL:
            assert(len == sizeof(uint16_t));
            res = ieee802154_set_channel_number(&mdev->mac.submac, *(const uint16_t *)value);
            if (res == 0) {
                res = sizeof(uint16_t);
            }
            break;
        case NETOPT_TX_POWER:
            assert(len == sizeof(int16_t));
            res = ieee802154_set_tx_power(&mdev->mac.submac, *(const int16_t *)value);
            if (res == 0) {
                res = sizeof(int16_t);
            }
            break;
        case NETOPT_TX_INDIRECT:
            assert(len == sizeof(netopt_enable_t));
            mdev->tx_indirect = (*(const netopt_enable_t *)value == NETOPT_ENABLE);
            res = sizeof(netopt_enable_t);
            break;
        case NETOPT_STATE: {
            assert(len == sizeof(netopt_state_t));
            netopt_state_t state = *((const netopt_state_t *)value);
            ieee802154_pib_value_t rx_on = {
                .type = IEEE802154_PIB_TYPE_BOOL,
                .v.b = (state == NETOPT_STATE_IDLE),
            };
            ieee802154_mac_mlme_set_request(&mdev->mac, IEEE802154_PIB_RX_ON_WHEN_IDLE, &rx_on);
            if (state == NETOPT_STATE_SLEEP) {
                res = ieee802154_set_idle(&mdev->mac.submac);
            }
            else if (state == NETOPT_STATE_IDLE) {
                res = ieee802154_set_rx(&mdev->mac.submac);
            }
            else if (state == NETOPT_STATE_OFF) {
                ieee802154_pib_value_t rx_on = {
                    .type = IEEE802154_PIB_TYPE_BOOL,
                    .v.b = false,
                };
                ieee802154_mac_mlme_set_request(&mdev->mac, IEEE802154_PIB_RX_ON_WHEN_IDLE, &rx_on);
                (void)ieee802154_set_idle(&mdev->mac.submac);
                res = ieee802154_radio_off(&mdev->mac.submac.dev);
            }
            else {
                return -ENOTSUP;
            }
            if (res == 0) {
                res = sizeof(netopt_state_t);
            }
            break;
        }
        default:
            break;
    }

    return res;
}

static int _netdev_confirm_send(netdev_t *dev, void *info)
{
    (void)info;
    gnrc_netif_ieee802154_mac_dev_t *mdev = _dev_from_netdev(dev);
    int res = -EAGAIN;

    mutex_lock(&mdev->tx_lock);
    if (mdev->tx_done) {
        res = mdev->last_tx_status;
        mdev->tx_done = false;
    }
    mutex_unlock(&mdev->tx_lock);
    return res;
}

int gnrc_netif_ieee802154_mac_create(gnrc_netif_t *netif, char *stack,
                                     int stacksize, char priority,
                                     const char *name,
                                     gnrc_netif_ieee802154_mac_dev_t *dev)
{
    assert(netif);
    assert(stack);
    assert(dev);

    memset(dev, 0, sizeof(*dev));
    dev->netdev.driver = &_netdev_driver;
    dev->netif = netif;
    _global_dev = dev;
    _radio_init_idx = 0;

    int res = gnrc_netif_create(netif, stack, stacksize, priority,
                                name, &dev->netdev, &_ops);
    return res;
}
