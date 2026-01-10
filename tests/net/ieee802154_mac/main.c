#include "net/ieee802154/mac.h"
#include "net/ieee802154/radio.h"
#include <stdio.h>

int main(void){
    ieee802154_pib_t pib;
    ieee802154_pib_init(&pib);
    ieee802154_pib_attr_t pib_attr = IEEE802154_PIB_BEACON_PAYLOAD;
    ieee802154_pib_value_t pib_value;

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
    return 0;
}
