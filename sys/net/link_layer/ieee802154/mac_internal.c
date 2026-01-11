#include <errno.h>
#include <string.h>

#include "container.h"
#include "isrpipe/read_timeout.h"
#include "ztimer.h"
#include "msg.h"

#include "net/ieee802154/mac_internal.h"
#include "net/ieee802154/mac.h"
                         
void ieee802154_mac_post_event(ieee802154_mac_t *mac, ieee802154_mac_ev_t ev)
{
    isrpipe_write_one(&mac->evpipe, (uint8_t)ev);
}

static void _radio_cb(ieee802154_dev_t *dev, ieee802154_trx_ev_t st)
{
    ieee802154_submac_t *submac = container_of(dev, ieee802154_submac_t, dev);
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);

    ieee802154_mac_ev_t ev;
    switch (st) {
        case IEEE802154_RADIO_CONFIRM_TX_DONE:      ev = IEEE802154_MAC_EV_RADIO_TX_DONE; break;
        case IEEE802154_RADIO_INDICATION_RX_DONE:   ev = IEEE802154_MAC_EV_RADIO_RX_DONE; break;
        case IEEE802154_RADIO_INDICATION_CRC_ERROR: ev = IEEE802154_MAC_EV_RADIO_CRC_ERR; break;
        default:
            return;
    }

    ieee802154_mac_post_event(mac, ev);
}

void ieee802154_mac_radio_attach(ieee802154_mac_t *mac)
{
    mac->submac.dev.cb     = _radio_cb;
}

/* ----- ACK timer callback: enqueue event only ----- */
static void _ack_timer_cb(void *arg){
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;
    ieee802154_mac_post_event(mac, IEEE802154_MAC_EV_ACK_TIMEOUT);
}

/* ===== Required SubMAC extern hooks ===== */
void ieee802154_submac_bh_request(ieee802154_submac_t *submac){
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);
    ieee802154_mac_post_event(mac, IEEE802154_MAC_EV_SUBMAC_BH);
}

void ieee802154_submac_ack_timer_set(ieee802154_submac_t *submac)
{
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);
    mac->ack_timer.callback = _ack_timer_cb;
    mac->ack_timer.arg = mac;

    ztimer_set(ZTIMER_USEC, &mac->ack_timer, (uint32_t)submac->ack_timeout_us);
}


void ieee802154_submac_ack_timer_cancel(ieee802154_submac_t *submac){
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);
    ztimer_remove(ZTIMER_USEC, &mac->ack_timer);
}

/* ===== SubMAC callbacks ===== */
static void _submac_rx_done(ieee802154_submac_t *submac){
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);
    puts("received\n");
    int len = ieee802154_get_frame_length(submac);
    if (len <= 0 || len > (int)sizeof(mac->rx_buf)) {
        (void)ieee802154_read_frame(submac, NULL, 0, NULL);
        return;
    }

    ieee802154_rx_info_t info;
    int r = ieee802154_read_frame(submac, mac->rx_buf, sizeof(mac->rx_buf), &info);
    if (r > 0 && mac->cbs.data_indication) {
        mac->cbs.data_indication(mac->cbs.arg, mac->rx_buf, (size_t)r, &info);
    }
}

static void _submac_tx_done(ieee802154_submac_t *submac, int status, ieee802154_tx_info_t *info){
    (void)info;
    ieee802154_mac_t *mac = container_of(submac, ieee802154_mac_t, submac);

    int res;
    switch (status) {
        case TX_STATUS_SUCCESS:
        case TX_STATUS_FRAME_PENDING: res = 0; break;
        case TX_STATUS_NO_ACK:        res = -ETIMEDOUT; break;
        case TX_STATUS_MEDIUM_BUSY:   res = -EBUSY; break;
        default:                      res = -EIO; break;
    }

    ieee802154_mac_tx_finish_current(mac, res);

    /* start next if queued */
    ieee802154_mac_post_event(mac, IEEE802154_MAC_EV_TX_KICK);
}

static const ieee802154_submac_cb_t _submac_cbs = {
    .rx_done = _submac_rx_done,
    .tx_done = _submac_tx_done,
};

void ieee802154_mac_submac_attach(ieee802154_mac_t *mac){
    mac->submac.cb = &_submac_cbs;
}

static inline bool _txq_full(const ieee802154_mac_t *mac){
    return mac->tx_cnt >= IEEE802154_MAC_TXQ_LEN;
}

static inline bool _txq_empty(const ieee802154_mac_t *mac){
    return mac->tx_cnt == 0;
}

void ieee802154_mac_tx_finish_current(ieee802154_mac_t *mac, int status)
{
    if (_txq_empty(mac)) {
        mac->tx_busy = false;
        return;
    }

    ieee802154_mac_tx_desc_t *d = ieee802154_mac_tx_peek(mac);

    if (mac->cbs.data_confirm) {
        mac->cbs.data_confirm(mac->cbs.arg, d->handle, status);
    }

    d->in_use = false;
    ieee802154_mac_tx_pop(mac);
    mac->tx_busy = false;
}

void _tx_kick(ieee802154_mac_t *mac)
{
    if (mac->tx_busy || _txq_empty(mac)) {
        return;
    }

    ieee802154_mac_tx_desc_t *d = ieee802154_mac_tx_peek(mac);

    /* persistent iolist nodes */
    d->iol_msdu.iol_base = (void *)d->msdu.ptr;
    d->iol_msdu.iol_len  = d->msdu.len;
    d->iol_msdu.iol_next = NULL;

    d->iol_mhr.iol_base  = d->mhr;
    d->iol_mhr.iol_len   = d->mhr_len;
    d->iol_mhr.iol_next  = &d->iol_msdu;

    int r = ieee802154_send(&mac->submac, &d->iol_mhr);
    if (r == 0) {
        mac->tx_busy = true;
    }
    else {
        /* immediate failure: confirm + pop */
        ieee802154_mac_tx_finish_current(mac, r);
        /* and try next (in case next can send) */
        _tx_kick(mac);
    }
}

void _process_event(ieee802154_mac_t *mac, uint8_t ev)
{
    switch ((ieee802154_mac_ev_t)ev) {
        case IEEE802154_MAC_EV_RADIO_TX_DONE:
            ieee802154_submac_tx_done_cb(&mac->submac);
            break;

        case IEEE802154_MAC_EV_RADIO_RX_DONE:
            ieee802154_submac_rx_done_cb(&mac->submac);
            break;

        case IEEE802154_MAC_EV_RADIO_CRC_ERR:
            ieee802154_submac_crc_error_cb(&mac->submac);
            break;

        case IEEE802154_MAC_EV_SUBMAC_BH:
            ieee802154_submac_bh_process(&mac->submac);
            break;

        case IEEE802154_MAC_EV_ACK_TIMEOUT:
            /* Must be thread context (submac.h note) */
            ieee802154_submac_ack_timeout_fired(&mac->submac);
            break;

        case IEEE802154_MAC_EV_TX_KICK:
            puts("sending");
            _tx_kick(mac);
            break;

        default:
            break;
    }
}

void *ieee802154_mac_thread(void *arg)
{
    ieee802154_mac_t *mac = (ieee802154_mac_t *)arg;

    /* init handshake */
    msg_t m;
    msg_receive(&m);

    if (m.type == _MAC_MSG_INIT) {
        ieee802154_pib_value_t short_addr_value;
        ieee802154_pib_value_t ext_addr_value;
        ieee802154_pib_res_t res = ieee802154_mac_mlme_get(mac, IEEE802154_PIB_SHORT_ADDR, &short_addr_value);
        if (res != IEEE802154_PIB_OK){
            puts("err getting short");
        }
        res = ieee802154_mac_mlme_get(mac, IEEE802154_PIB_EXTENDED_ADDRESS, &ext_addr_value);
        if (res != IEEE802154_PIB_OK){
            puts("err getting ext");
        }
        ieee802154_submac_init(&mac->submac, &short_addr_value.v.short_addr, &ext_addr_value.v.ext_addr);
        msg_t reply = { .type = _MAC_MSG_INIT };
        reply.content.value = (uint32_t)res;
        msg_reply(&m, &reply);
    }
    else {
        msg_t reply = { .type = _MAC_MSG_INIT };
        reply.content.value = (uint32_t)(-EINVAL);
        msg_reply(&m, &reply);
    }

    /* main loop */
    while (1) {
        uint8_t ev;

        /* block if nothing to do */
        int n = isrpipe_read(&mac->evpipe, &ev, 1);
        if (n == 1) {
            puts("event\n");
            _process_event(mac, ev);
        }
        /* read rest */
        while (isrpipe_read_timeout(&mac->evpipe, &ev, 1, 0) == 1) {
            _process_event(mac, ev);
        }
    }

    return NULL;
}
