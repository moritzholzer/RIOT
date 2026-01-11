#include "net/eui_provider.h"
#include "net/ieee802154.h"
#include "net/ieee802154/mac.h"
#include "net/ieee802154/radio.h"
#include "luid.h"
#include <stdio.h>

int main(void){
    ieee802154_pib_t pib;
    ieee802154_pib_init(&pib);
    ieee802154_pib_attr_t pib_attr = IEEE802154_PIB_BEACON_PAYLOAD;
    ieee802154_pib_value_t pib_value;
    eui64_t long_addr;
    network_uint16_t short_addr;

    pib_value.type = IEEE802154_PIB_TYPE_BYTES;
    static const uint8_t data[] = { 0x01, 0x02, 0x03, 0x04 };
    printf("ptr=%p\n", (void *)data);
    pib_value.v.bytes.ptr = data;
    pib_value.v.bytes.len = sizeof(data);
    ieee802154_pib_res_t res = ieee802154_mac_mlme_set(&pib, pib_attr, &pib_value);
    if (res != IEEE802154_PIB_OK) {
        printf("set failed: %d\n", res);
        return 1;
    }

    ieee802154_pib_value_t pib_value2 ={ 0 };
    pib_value2.type = IEEE802154_PIB_TYPE_BYTES;

    res = ieee802154_mac_mlme_get(&pib, pib_attr, &pib_value2);
    if (res != IEEE802154_PIB_OK) {
        printf("get failed: %d\n", res);
        return -1;
    }
    printf("ptr=%p len=%zu\n", (void *)pib_value2.v.bytes.ptr, pib_value2.v.bytes.len);
    printf("got %zu bytes: \n", pib_value2.v.bytes.len);
    for (size_t i = 0; i < pib_value2.v.bytes.len; i++) {
        printf("%02X\n", pib_value2.v.bytes.ptr[i]);
    }


    luid_base(&long_addr, sizeof(long_addr));
    eui64_set_local(&long_addr);
    eui64_clear_group(&long_addr);
    eui_short_from_eui64(&long_addr, &short_addr);

    pib_attr = IEEE802154_PIB_EXTENDED_ADDRESS;
    pib_value.type = IEEE802154_PIB_TYPE_EUI64;
    pib_value.v.ext_addr = long_addr;
    res = ieee802154_mac_mlme_set(&pib, pib_attr, &pib_value);
    if (res != IEEE802154_PIB_OK) {
        printf("set failed: %d\n", res);
        return 1;
    }
    pib_attr = IEEE802154_PIB_SHORT_ADDR;
    pib_value.type = IEEE802154_PIB_TYPE_NUI16;
    pib_value.v.short_addr = short_addr;
    res = ieee802154_mac_mlme_set(&pib, pib_attr, &pib_value);
    if (res != IEEE802154_PIB_OK) {
        printf("set failed: %d\n", res);
        return 1;
    }

    ieee802154_mac_mlme_start(&pib, CONFIG_IEEE802154_DEFAULT_CHANNEL);

    return 0;
}
