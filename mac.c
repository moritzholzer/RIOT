#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>

#include "random.h"
#include "net/ieee802154/radio.h"
#include "net/ieee802154/mac.h"

typedef struct {
    ieee802154_pib_type_t   type;
    ieee802154_pib_access_t access;

    uint16_t offset;        // offsetof(ieee802154_pib_t, FIELD)
    uint16_t size;          // sizeof(field) (0 for BYTES if borrowed-pointer design)
    int16_t  len_offset;    // offsetof(..., FIELD_LEN) for BYTES, -1 otherwise

    ieee802154_pib_value_t def;
    ieee802154_pib_value_t min;
    ieee802154_pib_value_t max;
} ieee802154_pib_attr_entry_t;

#define IEEE802154_PIB_OFF(field)   ((uint16_t)offsetof(ieee802154_pib_t, field))
#define IEEE802154_PIB_SIZE(field)  ((uint16_t)sizeof(((ieee802154_pib_t*)0)->field))

static const ieee802154_pib_attr_entry_t ieee802154_pib_attr[IEEE802154_PIB_ATTR_COUNT] = {
    [IEEE802154_PIB_AOA_ENABLE] = {
        .type=IEEE802154_PIB_TYPE_BOOL, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(AOA_ENABLE), .size=IEEE802154_PIB_SIZE(AOA_ENABLE), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_BOOL, .v.b=false }
    },

    [IEEE802154_PIB_AUTO_REQUEST] = {
        .type=IEEE802154_PIB_TYPE_BOOL, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(AUTO_REQUEST), .size=IEEE802154_PIB_SIZE(AUTO_REQUEST), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_BOOL, .v.b=true },
        .min=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_BOOL, .v.b=false },
        .max=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_BOOL, .v.b=true  }
    },

    [IEEE802154_PIB_BATT_LIFE_EXT] = {
        .type=IEEE802154_PIB_TYPE_BOOL, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(BATT_LIFE_EXT), .size=IEEE802154_PIB_SIZE(BATT_LIFE_EXT), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_BOOL, .v.b=false }
    },

    [IEEE802154_PIB_BATT_LIFE_EXT_PERIODS] = {
        .type=IEEE802154_PIB_TYPE_U16, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(BATT_LIFE_EXT_PERIODS), .size=IEEE802154_PIB_SIZE(BATT_LIFE_EXT_PERIODS), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U16, .v.u16=6 },
        .min=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U16, .v.u16=0 },
        .max=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U16, .v.u16=41}
    },

    [IEEE802154_PIB_BEACON_ORDER] = {
        .type=IEEE802154_PIB_TYPE_U8, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(BEACON_ORDER), .size=IEEE802154_PIB_SIZE(BEACON_ORDER), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=15 },
        .min=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=0 },
        .max=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=15 }
    },

    [IEEE802154_PIB_BEACON_PAYLOAD] = {
        .type=IEEE802154_PIB_TYPE_BYTES, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(BEACON_PAYLOAD), .size=0,
        .len_offset=(int16_t)IEEE802154_PIB_OFF(BEACON_PAYLOAD_LEN),
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_BYTES, .v.bytes={ .ptr=NULL, .len=0 } }
    },

    [IEEE802154_PIB_BSN] = {
        .type=IEEE802154_PIB_TYPE_U8, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(BSN), .size=IEEE802154_PIB_SIZE(BSN), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=0 }, // set random in init
        .min=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=0 },
        .max=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=0xFF }
    },

    [IEEE802154_PIB_COORD_EXTENDED_ADDRESS] = {
        .type=IEEE802154_PIB_TYPE_EUI64, .access=IEEE802154_PIB_ACC_RO,
        .offset=IEEE802154_PIB_OFF(COORD_EXTENDED_ADDRESS), .size=IEEE802154_PIB_SIZE(COORD_EXTENDED_ADDRESS), .len_offset=-1
    },

    [IEEE802154_PIB_COORD_SHORT_ADDRESS] = {
        .type=IEEE802154_PIB_TYPE_NUI16, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(COORD_SHORT_ADDRESS), .size=IEEE802154_PIB_SIZE(COORD_SHORT_ADDRESS), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_NUI16, .v.short_addr=(network_uint16_t){0xFFFFu} },
        .min=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_NUI16, .v.short_addr=(network_uint16_t){0} },
        .max=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_NUI16, .v.short_addr=(network_uint16_t){0xFFFFu} }
    },

    [IEEE802154_PIB_DSN] = {
        .type=IEEE802154_PIB_TYPE_U8, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(DSN), .size=IEEE802154_PIB_SIZE(DSN), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=0 }, // set random in init
        .min=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=0 },
        .max=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=0xFF }
    },

    [IEEE802154_PIB_EXTENDED_ADDRESS] = {
        .type=IEEE802154_PIB_TYPE_EUI64, .access=IEEE802154_PIB_ACC_RO,
        .offset=IEEE802154_PIB_OFF(EXTENDED_ADDRESS), .size=IEEE802154_PIB_SIZE(EXTENDED_ADDRESS), .len_offset=-1
    },

    [IEEE802154_PIB_FCS_TYPE] = {
        .type=IEEE802154_PIB_TYPE_U8, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(FCS_TYPE), .size=IEEE802154_PIB_SIZE(FCS_TYPE), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=0 },
        .min=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=0 },
        .max=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=1 }
    },

    [IEEE802154_PIB_GROUP_RX_MODE] = {
        .type=IEEE802154_PIB_TYPE_BOOL, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(GROUP_RX_MODE), .size=IEEE802154_PIB_SIZE(GROUP_RX_MODE), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_BOOL, .v.b=false }
    },

    [IEEE802154_PIB_GTS_PERMIT] = {
        .type=IEEE802154_PIB_TYPE_BOOL, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(GTS_PERMIT), .size=IEEE802154_PIB_SIZE(GTS_PERMIT), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_BOOL, .v.b=false }
    },

    [IEEE802154_PIB_IMPLICIT_BROADCAST] = {
        .type=IEEE802154_PIB_TYPE_BOOL, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(IMPLICIT_BROADCAST), .size=IEEE802154_PIB_SIZE(IMPLICIT_BROADCAST), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_BOOL, .v.b=true }
    },

    [IEEE802154_PIB_LIFS_PERIOD] = {
        .type=IEEE802154_PIB_TYPE_U16, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(LIFS_PERIOD), .size=IEEE802154_PIB_SIZE(LIFS_PERIOD), .len_offset=-1
    },

    [IEEE802154_PIB_MAX_BE] = {
        .type=IEEE802154_PIB_TYPE_U8, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(MAX_BE), .size=IEEE802154_PIB_SIZE(MAX_BE), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=5 },
        .min=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=3 },
        .max=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=8 }
    },

    [IEEE802154_PIB_MAX_CSMA_BACKOFFS] = {
        .type=IEEE802154_PIB_TYPE_U8, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(MAX_CSMA_BACKOFFS), .size=IEEE802154_PIB_SIZE(MAX_CSMA_BACKOFFS), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=4 },
        .min=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=0 },
        .max=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=5 }
    },

    [IEEE802154_PIB_NOTIFY_ALL_BEACONS] = {
        .type=IEEE802154_PIB_TYPE_BOOL, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(NOTIFY_ALL_BEACONS), .size=IEEE802154_PIB_SIZE(NOTIFY_ALL_BEACONS), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_BOOL, .v.b=false }
    },

    [IEEE802154_PIB_MIN_BE] = {
        .type=IEEE802154_PIB_TYPE_U8, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(MIN_BE), .size=IEEE802154_PIB_SIZE(MIN_BE), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=3 },
        .min=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=0 },
        .max=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=8 }
    },

    [IEEE802154_PIB_PAN_ID] = {
        .type=IEEE802154_PIB_TYPE_U16, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(PAN_ID), .size=IEEE802154_PIB_SIZE(PAN_ID), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U16, .v.u16=0xFFFF },
        .min=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U16, .v.u16=0 },
        .max=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U16, .v.u16=0xFFFF }
    },

    [IEEE802154_PIB_RESPONSE_WAIT_TIME] = {
        .type=IEEE802154_PIB_TYPE_U8, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(RESPONSE_WAIT_TIME), .size=IEEE802154_PIB_SIZE(RESPONSE_WAIT_TIME), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=32 },
        .min=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=2 },
        .max=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U8, .v.u8=64 }
    },

    [IEEE802154_PIB_RX_ON_WHEN_IDLE] = {
        .type=IEEE802154_PIB_TYPE_BOOL, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(RX_ON_WHEN_IDLE), .size=IEEE802154_PIB_SIZE(RX_ON_WHEN_IDLE), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_BOOL, .v.b=false }
    },

    [IEEE802154_PIB_SECURITY_ENABLED] = {
        .type=IEEE802154_PIB_TYPE_BOOL, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(SECURITY_ENABLED), .size=IEEE802154_PIB_SIZE(SECURITY_ENABLED), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_BOOL, .v.b=false }
    },

    [IEEE802154_PIB_SHORT_ADDR] = {
        .type=IEEE802154_PIB_TYPE_NUI16, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(SHORT_ADDR), .size=IEEE802154_PIB_SIZE(SHORT_ADDR), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_NUI16, .v.short_addr=(network_uint16_t){0xFFFFu} },
        .min=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_NUI16, .v.short_addr=(network_uint16_t){0} },
        .max=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_NUI16, .v.short_addr=(network_uint16_t){0xFFFFu} }
    },

    [IEEE802154_PIB_SIFS_PERIOD] = {
        .type=IEEE802154_PIB_TYPE_U16, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(SIFS_PERIOD), .size=IEEE802154_PIB_SIZE(SIFS_PERIOD), .len_offset=-1
    },

    [IEEE802154_PIB_SYNC_SYMBOL_OFFSET] = {
        .type=IEEE802154_PIB_TYPE_U16, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(SYNC_SYMBOL_OFFSET), .size=IEEE802154_PIB_SIZE(SYNC_SYMBOL_OFFSET), .len_offset=-1
    },

    [IEEE802154_PIB_TYPEIMESTAMP_SUPPORTED] = {
        .type=IEEE802154_PIB_TYPE_BOOL, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(TIMESTAMP_SUPPORTED), .size=IEEE802154_PIB_SIZE(TIMESTAMP_SUPPORTED), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_BOOL, .v.b=false }
    },

    [IEEE802154_PIB_TYPERANSACTION_PERSISTENCE_TIME] = {
        .type=IEEE802154_PIB_TYPE_U16, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(TRANSACTION_PERSISTENCE_TIME), .size=IEEE802154_PIB_SIZE(TRANSACTION_PERSISTENCE_TIME), .len_offset=-1,
        .def=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U16, .v.u16=0x01F4 },
        .min=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U16, .v.u16=0 },
        .max=(ieee802154_pib_value_t){ .type=IEEE802154_PIB_TYPE_U16, .v.u16=0xFFFF }
    },

    [IEEE802154_PIB_UNIT_BACKOFF_PERIOD] = {
        .type=IEEE802154_PIB_TYPE_U16, .access=IEEE802154_PIB_ACC_RW,
        .offset=IEEE802154_PIB_OFF(UNIT_BACKOFF_PERIOD), .size=IEEE802154_PIB_SIZE(UNIT_BACKOFF_PERIOD), .len_offset=-1
    },
};

#undef IEEE802154_PIB_OFF
#undef IEEE802154_PIB_SIZE

static inline uint8_t rand_u8(void) {
    return (uint8_t)random_uint32_range(0x00u, 0xFFu);
}

static inline void *ieee802154_pib_ptr(ieee802154_pib_t *p,
                                       const ieee802154_pib_attr_entry_t *e)
{
    return (void *)((uint8_t *)p + (size_t)e->offset);
}

static inline size_t *ieee802154_pib_len_ptr(ieee802154_pib_t *p,
                                             const ieee802154_pib_attr_entry_t *e)
{
    if (e->len_offset < 0) return NULL;
    return (size_t *)((uint8_t *)p + (size_t)e->len_offset);
}

void ieee802154_pib_init(ieee802154_pib_t *pib)
{
    if (!p) return;

    for (unsigned i = 0; i < (unsigned)IEEE802154_PIB_ATTR_COUNT; i++) {
        const ieee802154_pib_attr_entry_t *e = &ieee802154_pib_attr[i];

        if (e->def.type != e->type) {
            continue;
        }

        void *dst = ieee802154_pib_ptr(p, e);

        switch (e->type) {
            case IEEE802154_PIB_T_BOOL:
                *(bool *)dst = e->def.v.b;
                break;

            case IEEE802154_PIB_T_U8:
                *(uint8_t *)dst = e->def.v.u8;
                break;

            case IEEE802154_PIB_T_U16:
                *(uint16_t *)dst = e->def.v.u16;
                break;

            case IEEE802154_PIB_T_EUI64:
                *(eui64_t *)dst = e->def.v.ext_addr;
                break;

            case IEEE802154_PIB_T_NUI16:
                *(network_uint16_t *)dst = e->def.v.short_addr;
                break;

            case IEEE802154_PIB_T_BYTES: {
                *(const uint8_t **)dst = e->def.v.bytes.ptr;

                size_t *lp = ieee802154_pib_len_ptr(pib, e);
                if (lp) *lp = e->def.v.bytes.len;
                break;
            }
        }
    }

    pib->BSN = rand_u8();
    pib->DSN = rand_u8();
}

