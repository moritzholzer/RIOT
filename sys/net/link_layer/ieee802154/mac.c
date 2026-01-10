#include <stdint.h>
#include <stddef.h>
#include <stdbool.h>
#include <string.h>

#include "random.h"
#include "net/ieee802154/radio.h"
#include "net/ieee802154/mac.h"

typedef enum {
    IEEE802154_PIB_ACC_RW,
    IEEE802154_PIB_ACC_RO
} ieee802154_pib_access_t;

typedef struct {
    ieee802154_pib_type_t type;
    ieee802154_pib_access_t access;

    uint16_t offset;
    uint16_t size;
    int16_t len_offset;

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
        .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_AUTO_REQUEST] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(AUTO_REQUEST), .size = IEEE802154_PIB_SIZE(AUTO_REQUEST),
        .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_BATT_LIFE_EXT] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(BATT_LIFE_EXT), .size = IEEE802154_PIB_SIZE(BATT_LIFE_EXT),
        .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_BATT_LIFE_EXT_PERIODS] = {
        .type = IEEE802154_PIB_TYPE_U16, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(BATT_LIFE_EXT_PERIODS),
        .size = IEEE802154_PIB_SIZE(BATT_LIFE_EXT_PERIODS), .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 6 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 41 }
    },

    [IEEE802154_PIB_BEACON_ORDER] = {
        .type = IEEE802154_PIB_TYPE_U8, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(BEACON_ORDER), .size = IEEE802154_PIB_SIZE(BEACON_ORDER),
        .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 15 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 15 }
    },

    [IEEE802154_PIB_BEACON_PAYLOAD] = {
        .type = IEEE802154_PIB_TYPE_BYTES, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(BEACON_PAYLOAD), .size = IEEE802154_PIB_SIZE(BEACON_PAYLOAD),
        .len_offset = (int16_t)IEEE802154_PIB_OFF(BEACON_PAYLOAD_LEN),
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BYTES,
                                         .v.bytes = { .ptr = NULL, .len = 0 } },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BYTES,
                                         .v.bytes = { .ptr = NULL, .len = 0 } },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BYTES,
                                         .v.bytes = { .ptr = NULL, .len = 0 } }
    },

    [IEEE802154_PIB_BSN] = {
        .type = IEEE802154_PIB_TYPE_U8, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(BSN), .size = IEEE802154_PIB_SIZE(BSN), .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0xFF }
    },

    [IEEE802154_PIB_COORD_EXTENDED_ADDRESS] = {
        .type = IEEE802154_PIB_TYPE_EUI64, .access = IEEE802154_PIB_ACC_RO,
        .offset = IEEE802154_PIB_OFF(COORD_EXTENDED_ADDRESS),
        .size = IEEE802154_PIB_SIZE(COORD_EXTENDED_ADDRESS), .len_offset = -1,
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
        .size = IEEE802154_PIB_SIZE(COORD_SHORT_ADDRESS), .len_offset = -1,
        .def = { .type = IEEE802154_PIB_TYPE_NUI16,
                 .v.short_addr = { .u8 = { 0xFF, 0xFF } } },
        .min = { .type = IEEE802154_PIB_TYPE_NUI16,
                 .v.short_addr = { .u8 = { 0x00, 0x00 } } },
        .max = { .type = IEEE802154_PIB_TYPE_NUI16,
                 .v.short_addr = { .u8 = { 0xFF, 0xFF } } }
    },

    [IEEE802154_PIB_DSN] = {
        .type = IEEE802154_PIB_TYPE_U8, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(DSN), .size = IEEE802154_PIB_SIZE(DSN), .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 }, // set random in init
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0xFF }
    },

    [IEEE802154_PIB_EXTENDED_ADDRESS] = {
        .type = IEEE802154_PIB_TYPE_EUI64, .access = IEEE802154_PIB_ACC_RO,
        .offset = IEEE802154_PIB_OFF(EXTENDED_ADDRESS),
        .size = IEEE802154_PIB_SIZE(EXTENDED_ADDRESS), .len_offset = -1,
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
        .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 1 }
    },

    [IEEE802154_PIB_GROUP_RX_MODE] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(GROUP_RX_MODE), .size = IEEE802154_PIB_SIZE(GROUP_RX_MODE),
        .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }

    },

    [IEEE802154_PIB_GTS_PERMIT] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(GTS_PERMIT), .size = IEEE802154_PIB_SIZE(GTS_PERMIT),
        .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_IMPLICIT_BROADCAST] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(IMPLICIT_BROADCAST),
        .size = IEEE802154_PIB_SIZE(IMPLICIT_BROADCAST), .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_LIFS_PERIOD] = {
        .type = IEEE802154_PIB_TYPE_U16, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(LIFS_PERIOD), .size = IEEE802154_PIB_SIZE(LIFS_PERIOD),
        .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0x0 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0xFFFF }
    },

    [IEEE802154_PIB_MAX_BE] = {
        .type = IEEE802154_PIB_TYPE_U8, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(MAX_BE), .size = IEEE802154_PIB_SIZE(MAX_BE), .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 5 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 3 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 8 }
    },

    [IEEE802154_PIB_MAX_CSMA_BACKOFFS] = {
        .type = IEEE802154_PIB_TYPE_U8, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(MAX_CSMA_BACKOFFS),
        .size = IEEE802154_PIB_SIZE(MAX_CSMA_BACKOFFS), .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 4 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 5 }
    },

    [IEEE802154_PIB_NOTIFY_ALL_BEACONS] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(NOTIFY_ALL_BEACONS),
        .size = IEEE802154_PIB_SIZE(NOTIFY_ALL_BEACONS), .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_MIN_BE] = {
        .type = IEEE802154_PIB_TYPE_U8, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(MIN_BE), .size = IEEE802154_PIB_SIZE(MIN_BE), .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 3 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 8 }
    },

    [IEEE802154_PIB_PAN_ID] = {
        .type = IEEE802154_PIB_TYPE_U16, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(PAN_ID), .size = IEEE802154_PIB_SIZE(PAN_ID), .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0xFFFF },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0xFFFF }
    },

    [IEEE802154_PIB_RESPONSE_WAIT_TIME] = {
        .type = IEEE802154_PIB_TYPE_U8, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(RESPONSE_WAIT_TIME),
        .size = IEEE802154_PIB_SIZE(RESPONSE_WAIT_TIME), .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 32 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 2 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U8, .v.u8 = 64 }
    },

    [IEEE802154_PIB_RX_ON_WHEN_IDLE] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(RX_ON_WHEN_IDLE), .size = IEEE802154_PIB_SIZE(RX_ON_WHEN_IDLE),
        .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_SECURITY_ENABLED] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(SECURITY_ENABLED),
        .size = IEEE802154_PIB_SIZE(SECURITY_ENABLED), .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_SHORT_ADDR] = {
        .type = IEEE802154_PIB_TYPE_NUI16, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(SHORT_ADDR), .size = IEEE802154_PIB_SIZE(SHORT_ADDR),
        .len_offset = -1,
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
        .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0x0 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0xFFFF }
    },

    [IEEE802154_PIB_SYNC_SYMBOL_OFFSET] = {
        .type = IEEE802154_PIB_TYPE_U16, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(SYNC_SYMBOL_OFFSET),
        .size = IEEE802154_PIB_SIZE(SYNC_SYMBOL_OFFSET), .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0x0 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0xFFFF }
    },

    [IEEE802154_PIB_TIMESTAMP_SUPPORTED] = {
        .type = IEEE802154_PIB_TYPE_BOOL, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(TIMESTAMP_SUPPORTED),
        .size = IEEE802154_PIB_SIZE(TIMESTAMP_SUPPORTED), .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = false },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_BOOL, .v.b = true  }
    },

    [IEEE802154_PIB_TRANSACTION_PERSISTENCE_TIME] = {
        .type = IEEE802154_PIB_TYPE_U16, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(TRANSACTION_PERSISTENCE_TIME),
        .size = IEEE802154_PIB_SIZE(TRANSACTION_PERSISTENCE_TIME), .len_offset = -1,
        .def = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0x01F4 },
        .min = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0 },
        .max = (ieee802154_pib_value_t){ .type = IEEE802154_PIB_TYPE_U16, .v.u16 = 0xFFFF }
    },

    [IEEE802154_PIB_UNIT_BACKOFF_PERIOD] = {
        .type = IEEE802154_PIB_TYPE_U16, .access = IEEE802154_PIB_ACC_RW,
        .offset = IEEE802154_PIB_OFF(UNIT_BACKOFF_PERIOD),
        .size = IEEE802154_PIB_SIZE(UNIT_BACKOFF_PERIOD), .len_offset = -1,
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

static inline uint8_t *ieee802154_pib_ptr(ieee802154_pib_t *p,
                                          const ieee802154_pib_attr_entry_t *e)
{
    return ((uint8_t *)p + (size_t)e->offset);
}

static inline const uint8_t *ieee802154_pib_ptr_const(const ieee802154_pib_t *p,
                                                      const ieee802154_pib_attr_entry_t *e)
{
    return ((const uint8_t *)p + (size_t)e->offset);
}

static inline void ieee802154_pib_len_store_i16(ieee802154_pib_t *p,
                                                const ieee802154_pib_attr_entry_t *e,
                                                int16_t len)
{
    if (e->len_offset < 0) {
        return;
    }
    uint8_t *addr = (uint8_t *)p + (size_t)e->len_offset;
    memcpy(addr, &len, sizeof(len));
}

static inline int16_t ieee802154_65535pib_len_load_i16(const ieee802154_pib_t *p,
                                                  const ieee802154_pib_attr_entry_t *e)
{
    if (e->len_offset < 0) {
        return 0;
    }
    int16_t len = 0;
    const uint8_t *addr = (const uint8_t *)p + (size_t)e->len_offset;
    memcpy(&len, addr, sizeof(len));
    return len;
}

static inline bool _pib_can_write(ieee802154_pib_access_t a)
{
    return (a == IEEE802154_PIB_ACC_RW);
}

ieee802154_pib_res_t ieee802154_mac_mlme_set(ieee802154_pib_t *pib,
                                              ieee802154_pib_attr_t attr,
                                              const ieee802154_pib_value_t *in)
{
    const ieee802154_pib_attr_entry_t *e = &ieee802154_pib_attr[attr];

    if (in->type != e->type) {
        return IEEE802154_PIB_ERR_TYPE;
    }

    uint8_t *dst = ieee802154_pib_ptr(pib, e);

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

    case IEEE802154_PIB_TYPE_NUI16: {
        if (e->size != 2) {
            return IEEE802154_PIB_ERR_SIZE;
        }
        memcpy(dst, &in->v.short_addr, sizeof(in->v.short_addr)); /* safe even if unaligned */
        return IEEE802154_PIB_OK;
    }

    case IEEE802154_PIB_TYPE_BYTES: {
        if (e->len_offset < 0) {
            return IEEE802154_PIB_ERR_BAD_ARGS;
        }
        if (e->size != sizeof(const uint8_t *)) {
            return IEEE802154_PIB_ERR_SIZE;
        }

        const uint8_t *ptr = in->v.bytes.ptr;
        memcpy(dst, &ptr, sizeof(ptr));
        ieee802154_pib_len_store_i16(pib, e, (int16_t)in->v.bytes.len);
        return IEEE802154_PIB_OK;
    }

    default:
        return IEEE802154_PIB_ERR_TYPE;
    }
}

ieee802154_pib_res_t ieee802154_mac_mlme_get(const ieee802154_pib_t *pib,
                                              ieee802154_pib_attr_t attr,
                                              ieee802154_pib_value_t *out)
{
    const ieee802154_pib_attr_entry_t *e = &ieee802154_pib_attr[attr];

    const uint8_t *src = ieee802154_pib_ptr_const(pib, e);
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
        /* PIB memory stores 2 big-endian bytes. Return as network_uint16_t. */
        if (e->size != 2) return IEEE802154_PIB_ERR_SIZE;
        memcpy(&out->v.short_addr, src, sizeof(out->v.short_addr));
        return IEEE802154_PIB_OK;

    case IEEE802154_PIB_TYPE_BYTES:
        if (e->len_offset < 0) return IEEE802154_PIB_ERR_BAD_ARGS;
        if (e->size != sizeof(const uint8_t *)) return IEEE802154_PIB_ERR_SIZE;

        memcpy(&out->v.bytes.ptr, src, sizeof(out->v.bytes.ptr));
        out->v.bytes.len = (size_t)ieee802154_65535pib_len_load_i16(pib, e);
        return IEEE802154_PIB_OK;

    default:
        return IEEE802154_PIB_ERR_TYPE;
    }
}

void ieee802154_pib_init(ieee802154_pib_t *pib)
{
    for (unsigned i = 0; i < (unsigned)IEEE802154_PIB_ATTR_COUNT; i++) {
        const ieee802154_pib_attr_entry_t *e = &ieee802154_pib_attr[i];

        if (e->def.type != e->type) {
            continue;
        }

        (void)ieee802154_mac_mlme_set(pib, i, &e->def);
    }

    ieee802154_pib_value_t v;

    v.type = IEEE802154_PIB_TYPE_U8;
    v.v.u8 = rand_u8();
    (void)ieee802154_mac_mlme_set(pib, IEEE802154_PIB_BSN, &v);

    v.v.u8 = rand_u8();
    (void)ieee802154_mac_mlme_set(pib, IEEE802154_PIB_DSN, &v);
}
