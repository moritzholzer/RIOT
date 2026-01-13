#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#include "net/ieee802154/mac.h"

void ieee802154_mac_pib_init(ieee802154_mac_t *mac);
int ieee802154_mac_mlme_set(ieee802154_mac_t *mac,
                            ieee802154_pib_attr_t attr,
                            const ieee802154_pib_value_t *in);
int ieee802154_mac_mlme_get(const ieee802154_mac_t *mac,
                            ieee802154_pib_attr_t attr,
                            ieee802154_pib_value_t *out);

#ifdef __cplusplus
}
#endif
