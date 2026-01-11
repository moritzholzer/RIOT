#include "net/eui_provider.h"
#include "net/ieee802154.h"
#include "net/ieee802154/mac.h"
#include "net/ieee802154/radio.h"
#include "luid.h"
#include <stdio.h>
#include <ctype.h>

static ieee802154_mac_t mac;

static void my_confirm(void *arg, uint8_t handle, int status) {
    (void)arg; (void)handle;
    printf("res=%d (%s)\n", status, strerror(-status));
}
static void my_ind(void *arg,
                   const uint8_t *psdu, size_t len,
                   const ieee802154_rx_info_t *info)
{
    (void)arg;
    (void)info;

    /* Get MAC header length (MHR) */
    size_t mhr_len = ieee802154_get_frame_hdr_len(psdu);
    if (mhr_len == 0) {
        puts("RX: get_frame_hdr_len failed");
        return;
    }
    if (mhr_len > len) {
        puts("RX: bad header length");
        return;
    }

    const uint8_t *payload = psdu + mhr_len;
    size_t plen = len - mhr_len;   /* PSDU excludes FCS in RIOT SubMAC :contentReference[oaicite:1]{index=1} */

    printf("RX payload (as string): ");
    for (size_t i = 0; i < plen; i++) {
        unsigned char c = payload[i];
        putchar(isprint(c) ? (char)c : '.');
    }
    putchar('\n');
}

int main(void){

    ieee802154_mac_cbs_t cbs = {
        .data_confirm = my_confirm,
        .data_indication = my_ind,
        .arg = NULL,
    };
    ieee802154_mac_init(&mac, &cbs);

    ieee802154_pib_value_t pib_value;
    eui64_t long_addr;
    network_uint16_t short_addr;

    luid_base(&long_addr, sizeof(long_addr));
    eui64_set_local(&long_addr);
    eui64_clear_group(&long_addr);
    eui_short_from_eui64(&long_addr, &short_addr);
    pib_value.type = IEEE802154_PIB_TYPE_EUI64;
    pib_value.v.ext_addr = long_addr;
    int res = ieee802154_mac_mlme_set(&mac, IEEE802154_PIB_EXTENDED_ADDRESS, &pib_value);
    if (res != IEEE802154_PIB_OK) {
        printf("set failed: %d\n", res);
        return 1;
    }
    pib_value.type = IEEE802154_PIB_TYPE_NUI16;
    pib_value.v.short_addr = short_addr;
    res = ieee802154_mac_mlme_set(&mac, IEEE802154_PIB_SHORT_ADDR, &pib_value);
    if (res != IEEE802154_PIB_OK) {
        printf("set failed: %d\n", res);
        return 1;
    }
    // printf("addr = 0x%02x%02x\n", short_addr.u8[0], short_addr.u8[1]);
    printf("SRC EUI64 = ");
    for (unsigned i = 0; i < 8; i++) {
        printf("%02x", long_addr.uint8[i]);
    }
    puts("\n");
    res = ieee802154_mac_start(&mac);
    if (res != IEEE802154_PIB_OK) {
        printf("set failed: %d\n", res);
        return 1;
    }

    ieee802154_ext_addr_t dst = { .uint8 = { 0xde, 0xe2, 0x51, 0xe6, 0x0d, 0x67, 0x87, 0x83 }};

    char *data = "hello world";
    ieee802154_octets_t msdu = {.ptr = (const uint8_t *)data, .len=strlen(data)};
    ieee802154_mcps_data_request(&mac,
                                 IEEE802154_ADDR_MODE_EXTENDED,
                                 IEEE802154_ADDR_MODE_EXTENDED,
                                 CONFIG_IEEE802154_DEFAULT_PANID,
                                 &dst,
                                 msdu,
                                 1,
                                 false);
    return 0;
}
