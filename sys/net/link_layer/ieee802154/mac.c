#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "random.h"
#include "isrpipe.h"
#include "bhp/event.h"
#include "net/ieee802154/radio.h"
#include "net/ieee802154/mac.h"
#include "net/ieee802154/mac_internal.h"
#include "net/ieee802154/submac.h"

#include "event/thread.h"
extern void auto_init_event_thread(void);

#ifdef MODULE_CC2538_RF
#include "cc2538_rf.h"
#endif

#ifdef MODULE_ESP_IEEE802154
#include "esp_ieee802154_hal.h"
#endif

#ifdef MODULE_NRF802154
#include "nrf802154.h"
#endif

#ifdef MODULE_SOCKET_ZEP
#include "socket_zep.h"
#include "socket_zep_params.h"
#else
#define SOCKET_ZEP_MAX  0
#endif

#define RADIOS_NUMOF IS_USED(MODULE_CC2538_RF) + \
                     IS_USED(MODULE_NRF802154) + \
                     SOCKET_ZEP_MAX + \
                     IS_USED(MODULE_MRF24J40) + \
                     IS_USED(MODULE_KW2XRF) + \
                     IS_USED(MODULE_ESP_IEEE802154)


#ifdef MODULE_KW2XRF
#include "kw2xrf.h"
#include "kw2xrf_params.h"
#define KW2XRF_NUM   ARRAY_SIZE(kw2xrf_params)
static kw2xrf_t kw2xrf_dev[KW2XRF_NUM];
static bhp_event_t kw2xrf_bhp[KW2XRF_NUM];
#endif

#ifdef MODULE_MRF24J40
#include "mrf24j40.h"
#include "mrf24j40_params.h"
#define MRF24J40_NUM    ARRAY_SIZE(mrf24j40_params)
static mrf24j40_t mrf24j40_dev[MRF24J40_NUM];
static bhp_event_t mrf24j40_bhp[MRF24J40_NUM];
#endif

void _hal_init_dev(ieee802154_mac_t *mac, ieee802154_dev_type_t dev_type)
{
    if (IS_USED(MODULE_EVENT_THREAD)) {
        auto_init_event_thread();
    }

    ieee802154_dev_t *radio = NULL;
    bool ok = false;

    (void)radio;

    if (RADIOS_NUMOF == 0) {
        puts("Radio is either not supported or not present");
        assert(false);
    }

    switch (dev_type) {

        case IEEE802154_DEV_TYPE_CC2538_RF:
#if IS_USED(MODULE_CC2538_RF)
            if ((radio = cb(IEEE802154_DEV_TYPE_CC2538_RF, opaque))) {
                cc2538_rf_hal_setup(radio);
                cc2538_init();
                ok = true;
            }
#else
            puts("CC2538_RF selected but MODULE_CC2538_RF not compiled in");
#endif
            break;

        case IEEE802154_DEV_TYPE_ESP_IEEE802154:
#if IS_USED(MODULE_ESP_IEEE802154)
            if ((radio = cb(IEEE802154_DEV_TYPE_ESP_IEEE802154, opaque))) {
                esp_ieee802154_setup(radio);
                esp_ieee802154_init();
                ok = true;
            }
#else
            puts("ESP_IEEE802154 selected but MODULE_ESP_IEEE802154 not compiled in");
#endif
            break;

        case IEEE802154_DEV_TYPE_NRF802154:
#if IS_USED(MODULE_NRF802154)
            if ((radio = cb(IEEE802154_DEV_TYPE_NRF802154, opaque))) {
                nrf802154_hal_setup(radio);
                nrf802154_init();
                ok = true;
            }
#else
            puts("NRF802154 selected but MODULE_NRF802154 not compiled in");
#endif
            break;

        case IEEE802154_DEV_TYPE_KW2XRF:
#if IS_USED(MODULE_KW2XRF)
            if ((radio = &mac->submac.dev)) {
                for (unsigned i = 0; i < KW2XRF_NUM; i++) {
                    const kw2xrf_params_t *p = &kw2xrf_params[i];
                    bhp_event_init(&kw2xrf_bhp[i], EVENT_PRIO_HIGHEST,
                                   &kw2xrf_radio_hal_irq_handler, radio);
                    kw2xrf_init(&kw2xrf_dev[i], p, radio, bhp_event_isr_cb, &kw2xrf_bhp[i]);
                    break; /* init one */
                }
                ok = true;
            }
#else
            puts("KW2XRF selected but MODULE_KW2XRF not compiled in");
#endif
            break;

        case IEEE802154_DEV_TYPE_SOCKET_ZEP:
#if IS_USED(MODULE_SOCKET_ZEP)
        {
            static socket_zep_t _socket_zeps[SOCKET_ZEP_MAX];

            if ((radio = &mac->submac.dev)) {
                socket_zep_hal_setup(&_socket_zeps[0], radio);
                socket_zep_setup(&_socket_zeps[0], &socket_zep_params[0]);
                ok = true;
            }
        }
#else
            puts("SOCKET_ZEP selected but MODULE_SOCKET_ZEP not compiled in");
#endif
            break;

        case IEEE802154_DEV_TYPE_MRF24J40:
#if IS_USED(MODULE_MRF24J40)
            if ((radio = cb(IEEE802154_DEV_TYPE_MRF24J40, opaque))) {
                for (unsigned i = 0; i < MRF24J40_NUM; i++) {
                    const mrf24j40_params_t *p = &mrf24j40_params[i];
                    bhp_event_init(&mrf24j40_bhp[i], EVENT_PRIO_HIGHEST,
                                   &mrf24j40_radio_irq_handler, radio);
                    mrf24j40_init(&mrf24j40_dev[i], p, radio, bhp_event_isr_cb, &mrf24j40_bhp[i]);
                    break; /* init one */
                }
                ok = true;
            }
#else
            puts("MRF24J40 selected but MODULE_MRF24J40 not compiled in");
#endif
            break;

        default:
            puts("Unknown/invalid radio type");
            break;
    }

    if (!ok) {
        puts("Requested radio type not supported/compiled-in or not present");
        assert(false);
    }
}

typedef enum {
    IEEE802154_PIB_ACC_RW,
    IEEE802154_PIB_ACC_RO
} ieee802154_pib_access_t;

typedef struct {
    ieee802154_pib_type_t type;
    ieee802154_pib_access_t access;

    uint16_t offset;
    uint16_t size;

    ieee802154_pib_value_t def;
    ieee802154_pib_value_t min;
    ieee802154_pib_value_t max;
} ieee802154_pib_attr_entry_t;

#define IEEE802154_PIB_OFF(field)   ((uint16_t)offsetof(ieee802154_pib_t, field))
#define IEEE802154_PIB_SIZE(field)  ((uint16_t)sizeof(((ieee802154_pib_t *)0)->field))

static const ieee802154_pib_attr_entry_t ieee802154_pib_attr[IEEE802154_PIB_ATTR_COUNT] = {
    [IEEE802154_PIB_AOA_ENABLE] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(AOA_ENABLE), .size = IEEE802154_PIB_SIZE(AOA_ENABLE),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_AUTO_REQUEST] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(AUTO_REQUEST), .size = IEEE802154_PIB_SIZE(AUTO_REQUEST),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_BATT_LIFE_EXT] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(BATT_LIFE_EXT), .size = IEEE802154_PIB_SIZE(BATT_LIFE_EXT),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_BATT_LIFE_EXT_PERIODS] = {
        .type = IEEE802154_PIB_TYPE_U16, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(BATT_LIFE_EXT_PERIODS),
        .size = IEEE802154_PIB_SIZE(BATT_LIFE_EXT_PERIODS),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 6 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 41 }
    },

    [IEEE802154_PIB_BEACON_ORDER] = {
        .type = IEEE802154_PIB_TYPE_U8, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(BEACON_ORDER), .size = IEEE802154_PIB_SIZE(BEACON_ORDER),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 15 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 15 }
    },

    [IEEE802154_PIB_BEACON_PAYLOAD] = {
        .type = IEEE802154_PIB_TYPE_BYTES, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(BEACON_PAYLOAD), .size = IEEE802154_PIB_SIZE(BEACON_PAYLOAD),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BYTES,
                                         .v.bytes = { .ptr = NULL, .len = 0 } },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BYTES,
                                         .v.bytes = { .ptr = NULL, .len = 0 } },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BYTES,
                                         .v.bytes = { .ptr = NULL, .len = 0 } }
    },

    [IEEE802154_PIB_BSN] = {
        .type = IEEE802154_PIB_TYPE_U8, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(BSN), .size = IEEE802154_PIB_SIZE(BSN),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0xFF }
    },

    [IEEE802154_PIB_COORD_EXTENDED_ADDRESS] = {
        .type = IEEE802154_PIB_TYPE_EUI64, .access = IEEE802154_PIB_ACC_RO,
        .offset = IEEE802154_PIB_OFF(COORD_EXTENDED_ADDRESS),
        .size = IEEE802154_PIB_SIZE(COORD_EXTENDED_ADDRESS),
        .def = { .type = IEEE802154_PIB_TYPE_EUI64,
                 .v.ext_addr = { .uint8 = { 0, 0, 0, 0, 0, 0, 0, 0 } } },
        .min = { .type = IEEE802154_PIB_TYPE_EUI64,
                 .v.ext_addr = { .uint8 = { 0, 0, 0, 0, 0, 0, 0, 0 } } },
        .max = { .type = IEEE802154_PIB_TYPE_EUI64,
                 .v.ext_addr = { .uint8 = { 0, 0, 0, 0, 0, 0, 0, 0 } } }

    },

    [IEEE802154_PIB_COORD_SHORT_ADDRESS] = {
        .type = IEEE802154_PIB_TYPE_NUI16, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(COORD_SHORT_ADDRESS),
        .size = IEEE802154_PIB_SIZE(COORD_SHORT_ADDRESS),
        .def = { .type = IEEE802154_PIB_TYPE_NUI16,
                 .v.short_addr = { .u8 = { 0xFF, 0xFF } } },
        .min = { .type = IEEE802154_PIB_TYPE_NUI16,
                 .v.short_addr = { .u8 = { 0x00, 0x00 } } },
        .max = { .type = IEEE802154_PIB_TYPE_NUI16,
                 .v.short_addr = { .u8 = { 0xFF, 0xFF } } }
    },

    [IEEE802154_PIB_DSN] = {
        .type = IEEE802154_PIB_TYPE_U8, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(DSN), .size = IEEE802154_PIB_SIZE(DSN),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 }, // set random in init
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0xFF }
    },

    [IEEE802154_PIB_EXTENDED_ADDRESS] = {
        .type = IEEE802154_PIB_TYPE_EUI64, .access = IEEE802154_PIB_ACC_RO,
        .offset = IEEE802154_PIB_OFF(EXTENDED_ADDRESS),
        .size = IEEE802154_PIB_SIZE(EXTENDED_ADDRESS),
        .def = { .type = IEEE802154_PIB_TYPE_EUI64,
                 .v.ext_addr = { .uint8 = { 0, 0, 0, 0, 0, 0, 0, 0 } } },
        .min = { .type = IEEE802154_PIB_TYPE_EUI64,
                 .v.ext_addr = { .uint8 = { 0, 0, 0, 0, 0, 0, 0, 0 } } },
        .max = { .type = IEEE802154_PIB_TYPE_EUI64,
                 .v.ext_addr = { .uint8 = { 0, 0, 0, 0, 0, 0, 0, 0 } } }
    },

    [IEEE802154_PIB_FCS_TYPE] = {
        .type = IEEE802154_PIB_TYPE_U8, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(FCS_TYPE), .size = IEEE802154_PIB_SIZE(FCS_TYPE),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 1 }
    },

    [IEEE802154_PIB_GROUP_RX_MODE] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(GROUP_RX_MODE), .size = IEEE802154_PIB_SIZE(GROUP_RX_MODE),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }

    },

    [IEEE802154_PIB_GTS_PERMIT] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(GTS_PERMIT), .size = IEEE802154_PIB_SIZE(GTS_PERMIT),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_IMPLICIT_BROADCAST] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(IMPLICIT_BROADCAST),
        .size = IEEE802154_PIB_SIZE(IMPLICIT_BROADCAST),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_LIFS_PERIOD] = {
        .type = IEEE802154_PIB_TYPE_U16, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(LIFS_PERIOD), .size = IEEE802154_PIB_SIZE(LIFS_PERIOD),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0x0 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0xFFFF }
    },

    [IEEE802154_PIB_MAX_BE] = {
        .type = IEEE802154_PIB_TYPE_U8, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(MAX_BE), .size = IEEE802154_PIB_SIZE(MAX_BE),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 5 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 3 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 8 }
    },

    [IEEE802154_PIB_MAX_CSMA_BACKOFFS] = {
        .type = IEEE802154_PIB_TYPE_U8, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(MAX_CSMA_BACKOFFS),
        .size = IEEE802154_PIB_SIZE(MAX_CSMA_BACKOFFS),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 4 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 5 }
    },

    [IEEE802154_PIB_NOTIFY_ALL_BEACONS] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(NOTIFY_ALL_BEACONS),
        .size = IEEE802154_PIB_SIZE(NOTIFY_ALL_BEACONS),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_MIN_BE] = {
        .type = IEEE802154_PIB_TYPE_U8, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(MIN_BE), .size = IEEE802154_PIB_SIZE(MIN_BE),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 3 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 8 }
    },

    [IEEE802154_PIB_PAN_ID] = {
        .type = IEEE802154_PIB_TYPE_U16, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(PAN_ID), .size = IEEE802154_PIB_SIZE(PAN_ID),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0xFFFFU},//CONFIG_IEEE802154_DEFAULT_PANID },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0xFFFF }
    },

    [IEEE802154_PIB_RESPONSE_WAIT_TIME] = {
        .type = IEEE802154_PIB_TYPE_U8, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(RESPONSE_WAIT_TIME),
        .size = IEEE802154_PIB_SIZE(RESPONSE_WAIT_TIME),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 32 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 2 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 64 }
    },

    [IEEE802154_PIB_RX_ON_WHEN_IDLE] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(RX_ON_WHEN_IDLE), .size = IEEE802154_PIB_SIZE(RX_ON_WHEN_IDLE),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_SECURITY_ENABLED] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(SECURITY_ENABLED),
        .size = IEEE802154_PIB_SIZE(SECURITY_ENABLED),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_SHORT_ADDR] = {
        .type = IEEE802154_PIB_TYPE_NUI16, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(SHORT_ADDR), .size = IEEE802154_PIB_SIZE(SHORT_ADDR),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_NUI16,
                                         .v.short_addr = { .u8 = { 0xFF, 0xFF } } },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_NUI16,
                                         .v.short_addr = { .u8 = { 0x00, 0x00 } } },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_NUI16,
                                         .v.short_addr = { .u8 = { 0xFF, 0xFF } } }
    },

    [IEEE802154_PIB_SIFS_PERIOD] = {
        .type = IEEE802154_PIB_TYPE_U16, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(SIFS_PERIOD), .size = IEEE802154_PIB_SIZE(SIFS_PERIOD),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0x0 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0xFFFF }
    },

    [IEEE802154_PIB_SYNC_SYMBOL_OFFSET] = {
        .type = IEEE802154_PIB_TYPE_U16, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(SYNC_SYMBOL_OFFSET),
        .size = IEEE802154_PIB_SIZE(SYNC_SYMBOL_OFFSET),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0x0 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0xFFFF }
    },

    [IEEE802154_PIB_TIMESTAMP_SUPPORTED] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(TIMESTAMP_SUPPORTED),
        .size = IEEE802154_PIB_SIZE(TIMESTAMP_SUPPORTED),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_TRANSACTION_PERSISTENCE_TIME] = {
        .type = IEEE802154_PIB_TYPE_U16, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(TRANSACTION_PERSISTENCE_TIME),
        .size = IEEE802154_PIB_SIZE(TRANSACTION_PERSISTENCE_TIME),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0x01F4 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0xFFFF }
    },

    [IEEE802154_PIB_UNIT_BACKOFF_PERIOD] = {
        .type = IEEE802154_PIB_TYPE_U16, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(UNIT_BACKOFF_PERIOD),
        .size = IEEE802154_PIB_SIZE(UNIT_BACKOFF_PERIOD),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0x0 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0xFFFF }
    },
};

#undef IEEE802154_PIB_OFF
#undef IEEE802154_PIB_SIZE

static inline uint8_t rand_u8(void)
{
    return (uint8_t)random_uint32_range(0x00u, 0xFFu);
}

static inline uint8_t *ieee802154_pib_ptr_from_mac(ieee802154_mac_t *mac,
                                                   const ieee802154_pib_attr_entry_t *e)
{
    ieee802154_pib_t *p = &mac->pib;
    return (uint8_t *)((uint8_t *)p + (ptrdiff_t)e->offset);
}

static inline const uint8_t *ieee802154_pib_ptr_const_from_mac(const ieee802154_mac_t *mac,
                                                               const ieee802154_pib_attr_entry_t *e)
{
    const ieee802154_pib_t *p = &mac->pib;
    return (const uint8_t *)((const uint8_t *)p + (ptrdiff_t)e->offset);
}

static inline bool _pib_can_write(ieee802154_pib_access_t a)
{
    return (a == IEEE802154_PIB_ACC_RW);
}

ieee802154_pib_res_t ieee802154_mac_mlme_set(ieee802154_mac_t *mac,
                                             ieee802154_pib_attr_t attr,
                                             const ieee802154_pib_value_t *in)
{
    const ieee802154_pib_attr_entry_t *e = &ieee802154_pib_attr[attr];

    if (in->type != e->type) {
        return IEEE802154_PIB_ERR_TYPE;
    }

    uint8_t *dst = ieee802154_pib_ptr_from_mac(mac, e);

    switch (e->type) {
    case IEEE802154_PIB_TYPE_BOOL:
        if (e->size != sizeof(bool)) {
            return IEEE802154_PIB_ERR_SIZE;
        }
        memcpy(dst, &in->v.b, sizeof(in->v.b));
        return IEEE802154_PIB_OK;

    case IEEE802154_PIB_TYPE_U8:
        if (e->size != sizeof(uint8_t)) {
            return IEEE802154_PIB_ERR_SIZE;
        }
        memcpy(dst, &in->v.u8, sizeof(in->v.u8));
        return IEEE802154_PIB_OK;

    case IEEE802154_PIB_TYPE_U16:
        if (e->size != sizeof(uint16_t)) {
            return IEEE802154_PIB_ERR_SIZE;
        }
        memcpy(dst, &in->v.u16, sizeof(in->v.u16)); /* alignment-safe */
        return IEEE802154_PIB_OK;

    case IEEE802154_PIB_TYPE_EUI64:
        if (e->size != sizeof(eui64_t)) {
            return IEEE802154_PIB_ERR_SIZE;
        }
        memcpy(dst, &in->v.ext_addr, sizeof(in->v.ext_addr));
        return IEEE802154_PIB_OK;

    case IEEE802154_PIB_TYPE_NUI16:
        if (e->size != 2) {
            return IEEE802154_PIB_ERR_SIZE;
        }
        memcpy(dst, &in->v.short_addr, sizeof(in->v.short_addr)); /* safe even if unaligned */
        return IEEE802154_PIB_OK;

    case IEEE802154_PIB_TYPE_BYTES:
        if (e->size != sizeof(ieee802154_octets_t)) {
            return IEEE802154_PIB_ERR_SIZE;
        }
        if (in->v.bytes.len != 0 && in->v.bytes.ptr == NULL) {
            return IEEE802154_PIB_ERR_BAD_ARGS;
        }
        memcpy(dst, &in->v.bytes, sizeof(in->v.bytes));
        return IEEE802154_PIB_OK;

    default:
        return IEEE802154_PIB_ERR_TYPE;
    }
}

ieee802154_pib_res_t ieee802154_mac_mlme_get(const ieee802154_mac_t *mac,
                                             ieee802154_pib_attr_t attr,
                                             ieee802154_pib_value_t *out)
{
    const ieee802154_pib_attr_entry_t *e = &ieee802154_pib_attr[attr];

    const uint8_t *src = ieee802154_pib_ptr_const_from_mac(mac, e);
    out->type = e->type;

    switch (e->type) {
    case IEEE802154_PIB_TYPE_BOOL:
        if (e->size != sizeof(bool)) return IEEE802154_PIB_ERR_SIZE;
        memcpy(&out->v.b, src, sizeof(out->v.b));
        return IEEE802154_PIB_OK;

    case IEEE802154_PIB_TYPE_U8:
        if (e->size != sizeof(uint8_t)) return IEEE802154_PIB_ERR_SIZE;
        memcpy(&out->v.u8, src, sizeof(out->v.u8));
        return IEEE802154_PIB_OK;

    case IEEE802154_PIB_TYPE_U16:
        if (e->size != sizeof(uint16_t)) return IEEE802154_PIB_ERR_SIZE;
        memcpy(&out->v.u16, src, sizeof(out->v.u16));
        return IEEE802154_PIB_OK;

    case IEEE802154_PIB_TYPE_EUI64:
        if (e->size != sizeof(eui64_t)) return IEEE802154_PIB_ERR_SIZE;
        memcpy(&out->v.ext_addr, src, sizeof(out->v.ext_addr));
        return IEEE802154_PIB_OK;

    case IEEE802154_PIB_TYPE_NUI16:
        if (e->size != 2) return IEEE802154_PIB_ERR_SIZE;
        memcpy(&out->v.short_addr, src, sizeof(out->v.short_addr));
        return IEEE802154_PIB_OK;

    case IEEE802154_PIB_TYPE_BYTES:
        if (e->size != sizeof(ieee802154_octets_t)) return IEEE802154_PIB_ERR_SIZE;
        memcpy(&out->v.bytes, src, sizeof(out->v.bytes));
        return IEEE802154_PIB_OK;

    default:
        return IEEE802154_PIB_ERR_TYPE;
    }
}


int ieee802154_mac_init(ieee802154_mac_t *mac,
                        const ieee802154_mac_cbs_t *cbs)
{
    if (!mac || !cbs) {
        return -EINVAL;
    }

    memset(mac, 0, sizeof(*mac));
    mac->cbs = *cbs;
    for (unsigned i = 0; i < (unsigned)IEEE802154_PIB_ATTR_COUNT; i++) {
        const ieee802154_pib_attr_entry_t *e = &ieee802154_pib_attr[i];

        if (e->def.type != e->type) {
            continue;
        }

        (void)ieee802154_mac_mlme_set(mac, i, &e->def);
    }

    ieee802154_pib_value_t v;

    v.type = IEEE802154_PIB_TYPE_U8;
    v.v.u8 = rand_u8();
    (void)ieee802154_mac_mlme_set(mac, IEEE802154_PIB_BSN, &v);

    v.v.u8 = rand_u8();
    (void)ieee802154_mac_mlme_set(mac, IEEE802154_PIB_DSN, &v);

    _hal_init_dev(mac, IEEE802154_DEV_TYPE_KW2XRF);

    return 0;
}

int ieee802154_mac_start(ieee802154_mac_t *mac)
{
    if (!mac) {
        return -EINVAL;
    }

    ieee802154_mac_submac_attach(mac);

    ieee802154_mac_radio_attach(mac);

    /* init isrpipe */
    isrpipe_init(&mac->evpipe, mac->evpipe_buf, sizeof(mac->evpipe_buf));

    /* init tx ring */
    mac->tx_head = 0;
    mac->tx_tail = 0;
    mac->tx_cnt  = 0;
    mac->tx_busy = false;

    /* start MAC thread*/
    mac->pid = thread_create(mac->stack, sizeof(mac->stack),
                             IEEE802154_MAC_PRIO,
                             THREAD_CREATE_STACKTEST,
                             ieee802154_mac_thread, mac, "ieee802154-mac");
    if (mac->pid <= KERNEL_PID_UNDEF) {
        return -EAGAIN;
    }

    msg_t init_msg = { .type = _MAC_MSG_INIT };

    msg_t reply;
    msg_send_receive(&init_msg, &reply, mac->pid);
    return (int)reply.content.value;
}

int ieee802154_mac_mlme_start(ieee802154_mac_t *mac, uint16_t channel){
    int res = ieee802154_set_channel_number(&mac->submac, channel);
    ieee802154_pib_value_t value;
    ieee802154_mac_mlme_get(mac, IEEE802154_PIB_PAN_ID, &value);
    res |=  ieee802154_set_panid(&mac->submac, &value.v.u16 );
    return res;
}

static inline uint8_t _addr_len_from_mode(ieee802154_addr_mode_t mode)
{
    switch (mode) {
    case IEEE802154_ADDR_MODE_NONE:  return 0;
    case IEEE802154_ADDR_MODE_SHORT: return IEEE802154_SHORT_ADDRESS_LEN;
    case IEEE802154_ADDR_MODE_EXTENDED:  return IEEE802154_LONG_ADDRESS_LEN;
    default:                    return 0;
    }
}

static inline bool _txq_full(const ieee802154_mac_t *mac)
{
    return mac->tx_cnt >= IEEE802154_MAC_TXQ_LEN;
}

int ieee802154_mcps_data_request(ieee802154_mac_t *mac,
                                 ieee802154_addr_mode_t src_mode,
                                 ieee802154_addr_mode_t dst_mode,
                                 uint16_t dst_panid,
                                 const void *dst_addr,
                                 ieee802154_octets_t msdu,
                                 uint8_t msdu_handle,
                                 bool ack_req)
{
    if (!mac) {
        return -EINVAL;
    }

    /* Validate address modes */
    const uint8_t src_len = _addr_len_from_mode(src_mode);
    const uint8_t dst_len = _addr_len_from_mode(dst_mode);

    if ((dst_len && dst_addr == NULL) || (dst_mode != IEEE802154_ADDR_MODE_NONE && dst_len == 0)) {
        return -EINVAL;
    }
    if (src_mode != IEEE802154_ADDR_MODE_NONE && src_len == 0) {
        return -EINVAL;
    }

    /* No heap: MSDU pointer is borrowed. We must at least validate length. */
    if (msdu.len > IEEE802154_FRAME_LEN_MAX) { /* 127, but your HAL excludes FCS */
        return -EMSGSIZE;
    }

    /* Enqueue into TX ring */
    if (_txq_full(mac)) {
        return -ENOBUFS;
    }

    ieee802154_mac_tx_desc_t *d = &mac->tx_queue[mac->tx_tail];
    memset(d, 0, sizeof(*d));
    d->in_use = true;
    d->handle = msdu_handle;
    d->msdu = msdu;

    /* Determine src pointer based on src_mode */
    const void *src = NULL;
    if (src_mode == IEEE802154_ADDR_MODE_SHORT) {
        src = &mac->submac.short_addr;
    }
    else if (src_mode == IEEE802154_ADDR_MODE_EXTENDED) {
        src = &mac->submac.ext_addr;
    }
    else { /* NONE */
        src = NULL;
    }

    le_uint16_t src_pan = byteorder_btols(byteorder_htons(mac->submac.panid));
    le_uint16_t dst_pan = byteorder_btols(byteorder_htons(dst_panid));

    /* Flags */
    uint8_t flags = IEEE802154_FCF_TYPE_DATA;
    if (ack_req) {
        flags |= IEEE802154_FCF_ACK_REQ;
    }

    ieee802154_pib_value_t dsn;
    ieee802154_mac_mlme_get(mac, IEEE802154_PIB_DSN, &dsn);
    /* Build header into the descriptor’s persistent buffer */
    printf("src_pan(le)= %02x%02x  dst_pan(le)= %02x%02x\n",
       src_pan.u8[0], src_pan.u8[1], dst_pan.u8[0], dst_pan.u8[1]);

    int mhr_len = ieee802154_set_frame_hdr(d->mhr,
                                          src, src_len,
                                          dst_addr, dst_len,
                                          src_pan, dst_pan,
                                          flags,
                                          dsn.v.u8);
    if (mhr_len < 0 || mhr_len > (int)sizeof(d->mhr)) {
        d->in_use = false;
        return -EINVAL;
    }
    ieee802154_pib_value_t dsn_new = {.type = IEEE802154_PIB_TYPE_U8, .v.u8 = ++dsn.v.u8};
    ieee802154_mac_mlme_set(mac, IEEE802154_PIB_DSN, &dsn_new);
    d->mhr_len = (uint8_t)mhr_len;

    /* Commit into ring */
    mac->tx_tail = (uint8_t)((mac->tx_tail + 1) % IEEE802154_MAC_TXQ_LEN);
    mac->tx_cnt++;

    /* Ask MAC thread to try sending */
    ieee802154_mac_post_ev(mac, IEEE802154_MAC_EV_TX_KICK);

    return 0;
}
