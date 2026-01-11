#pragma once

#include "msg.h"
#include "container.h"

#include "net/ieee802154/mac.h"

enum {
    _MAC_MSG_INIT = 0x154A,
};

typedef struct {
    const network_uint16_t *short_addr;
    const eui64_t *ext_addr;
} mac_init_args_t;

/* thread entry */
void *ieee802154_mac_thread(void *arg);

/* event dispatcher (thread context) */
void ieee802154_mac_process_event(ieee802154_mac_t *mac, uint8_t ev);

/* submac glue setup */
void ieee802154_mac_submac_attach(ieee802154_mac_t *mac);

/* tx functions */
void ieee802154_mac_tx_kick(ieee802154_mac_t *mac);
void ieee802154_mac_tx_finish_current(ieee802154_mac_t *mac, int status);

/* radio callback getter */
void ieee802154_mac_radio_attach(ieee802154_mac_t *mac);

void ieee802154_mac_post_ev(ieee802154_mac_t *mac, ieee802154_mac_ev_t ev);
