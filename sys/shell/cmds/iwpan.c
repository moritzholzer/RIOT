/*
 * Copyright (C) 2026
 *
 * This file is subject to the terms and conditions of the GNU Lesser
 * General Public License v2.1. See the file LICENSE in the top level
 * directory for more details.
 */

/**
 * @ingroup     sys_shell_commands
 * @{
 *
 * @file
 * @brief       Shell commands for IEEE 802.15.4 MAC (mac.h)
 *
 * @}
 */

#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include "byteorder.h"
#include "container.h"
#include "shell.h"
#include "ztimer.h"
#include "net/ieee802154.h"
#include "net/gnrc/netif/ieee802154_mac.h"
#include "net/gnrc/netif.h"
#include "net/netif.h"
#include "net/netopt.h"
#include "net/l2util.h"
#include "net/ieee802154/mac.h"

#ifndef GNRC_NETIF_IEEE802154_MAC_SCAN_MAX_CH
#define GNRC_NETIF_IEEE802154_MAC_SCAN_MAX_CH  (16U)
#endif

static uint16_t _scan_channels[GNRC_NETIF_IEEE802154_MAC_SCAN_MAX_CH];
static ieee802154_scan_result_t _scan_results[GNRC_NETIF_IEEE802154_MAC_SCAN_MAX_CH];
static size_t _scan_results_used;
static ieee802154_mlme_scan_req_t _scan_req;

static gnrc_netif_ieee802154_mac_dev_t *_get_mdev(const char *id_str,
                                                  gnrc_netif_t **out_netif)
{
    char *end = NULL;
    unsigned long id = strtoul(id_str, &end, 0);
    if ((end == NULL) || (*end != '\0')) {
        return NULL;
    }
    gnrc_netif_t *netif = gnrc_netif_get_by_pid((kernel_pid_t)id);
    if (!netif || !netif->dev) {
        return NULL;
    }
    if (out_netif) {
        *out_netif = netif;
    }
    return container_of(netif->dev, gnrc_netif_ieee802154_mac_dev_t, netdev);
}

static void _set_rx_on_when_idle(ieee802154_mac_t *mac, bool enable)
{
    ieee802154_pib_value_t v = {
        .type = IEEE802154_PIB_TYPE_BOOL,
        .v.b = enable,
    };
    ieee802154_mac_mlme_set_request(mac, IEEE802154_PIB_RX_ON_WHEN_IDLE, &v);
}

static int _iwpan_scan_cmd(ieee802154_mac_t *mac, int argc, char **argv)
{
    if (argc < 3) {
        puts("Usage: iwpan <if_id> scan [active|passive|ed] <duration_us> <ch1> [ch2 ...]\n");
        return 1;
    }

    ieee802154_scan_type_t type = IEEE802154_SCAN_ACTIVE;
    int argi = 1;
    if (strcmp(argv[argi], "active") == 0) {
        type = IEEE802154_SCAN_ACTIVE;
        argi++;
    }
    else if ((strcmp(argv[argi], "passive") == 0) || (strcmp(argv[argi], "ed") == 0)) {
        puts("Only active scan is supported currently\n");
        return 1;
    }

    if ((argc - argi) < 2) {
        puts("Usage: iwpan <if_id> scan [active] <duration_us> <ch1> [ch2 ...]\n");
        return 1;
    }

    uint32_t duration = (uint32_t)atoi(argv[argi]);
    int channel_count = argc - (argi + 1);
    if (channel_count > (int)(sizeof(_scan_channels) / sizeof(_scan_channels[0]))) {
        puts("Error: too many channels\n");
        return 1;
    }

    for (int i = 0; i < channel_count; i++) {
        _scan_channels[i] = (uint16_t)atoi(argv[i + argi + 1]);
    }

    _scan_results_used = 0;
    _scan_req.channels = _scan_channels;
    _scan_req.channel_count = (uint8_t)channel_count;
    _scan_req.results = _scan_results;
    _scan_req.results_len = sizeof(_scan_results) / sizeof(_scan_results[0]);
    _scan_req.results_used = &_scan_results_used;
    _scan_req.duration = duration;

    int res = ieee802154_mac_mlme_scan_request(mac, type, &_scan_req);
    if (res < 0) {
        printf("scan request failed: %d (%s)\n", res, strerror(-res));
        return 1;
    }
    return 0;
}

void iwpan_scan_confirm(void *arg, int status, ieee802154_mlme_scan_req_t *req)
{
    (void)arg;
    unsigned results = (unsigned)((req && req->results_used) ? *req->results_used : 0);
    printf("SCAN confirm res=%d (%s), results=%u\n", status, strerror(-status), results);
    puts(" IDX | CH | PANID  | ADDR                    | LQI | RSSI | PAYLOAD");
    puts("-----+----+--------+-------------------------+-----+------+----------------");
    if (!req || !req->results_used || !req->results) {
        return;
    }
    for (size_t i = 0; i < *req->results_used; i++) {
        char addr_str[3 * IEEE802154_LONG_ADDRESS_LEN];
        const ieee802154_scan_result_t *res = &req->results[i];
        if (res->coord_addr.type == IEEE802154_ADDR_MODE_EXTENDED) {
            l2util_addr_to_str(res->coord_addr.v.ext_addr.uint8,
                               IEEE802154_LONG_ADDRESS_LEN, addr_str);
        }
        else if (res->coord_addr.type == IEEE802154_ADDR_MODE_SHORT) {
            snprintf(addr_str, sizeof(addr_str), "0x%04x",
                     byteorder_ntohs(res->coord_addr.v.short_addr));
        }
        else {
            strcpy(addr_str, "none");
        }
        char payload_str[17];
        size_t payload_print = res->beacon_payload_len;
        if (payload_print > (sizeof(payload_str) - 1)) {
            payload_print = sizeof(payload_str) - 1;
        }
        for (size_t j = 0; j < payload_print; j++) {
            unsigned char c = res->beacon_payload[j];
            payload_str[j] = isprint(c) ? (char)c : '.';
        }
        payload_str[payload_print] = '\0';

        printf(" %3u | %2u | 0x%04x | %-20s | %3u | %4u | %-16s\n",
               (unsigned)i, res->channel, res->pan_id,
               addr_str, res->lqi, res->rssi, payload_str);
    }
}

void iwpan_associate_confirm(void *arg, int status, uint16_t short_addr)
{
    (void)arg;
    if (status == IEEE802154_ASSOC_STATUS_SUCCESS) {
        printf("ASSOC confirm res=%d (SUCCESS), short_addr=0x%04x\n",
               status, short_addr);
        return;
    }

    if (status < 0) {
        printf("ASSOC confirm res=%d (%s), short_addr=0x%04x\n",
               status, strerror(-status), short_addr);
        return;
    }

    const char *reason = "UNKNOWN";
    if (status == IEEE802154_ASSOC_STATUS_PAN_AT_CAPACITY) {
        reason = "PAN_AT_CAPACITY";
    }
    else if (status == IEEE802154_ASSOC_STATUS_PAN_ACCESS_DENIED) {
        reason = "PAN_ACCESS_DENIED";
    }
    printf("ASSOC confirm res=%d (%s), short_addr=0x%04x\n",
           status, reason, short_addr);
}

static int _parse_coord_addr(const char *addr_str, ieee802154_addr_t *addr)
{
    if (strchr(addr_str, ':') == NULL) {
        return -1;
    }
    uint8_t buf[IEEE802154_LONG_ADDRESS_LEN];
    size_t len = l2util_addr_from_str(addr_str, buf);
    if (len == IEEE802154_SHORT_ADDRESS_LEN) {
        addr->type = IEEE802154_ADDR_MODE_SHORT;
        addr->v.short_addr.u8[0] = buf[0];
        addr->v.short_addr.u8[1] = buf[1];
        return 0;
    }
    if (len == IEEE802154_LONG_ADDRESS_LEN) {
        addr->type = IEEE802154_ADDR_MODE_EXTENDED;
        memcpy(addr->v.ext_addr.uint8, buf, len);
        return 0;
    }
    return -1;
}

static int _parse_short_addr(const char *addr_str, ieee802154_short_addr_t *addr)
{
    if (strchr(addr_str, ':') == NULL) {
        return -1;
    }
    uint8_t buf[IEEE802154_SHORT_ADDRESS_LEN];
    size_t len = l2util_addr_from_str(addr_str, buf);
    if (len != IEEE802154_SHORT_ADDRESS_LEN) {
        return -1;
    }
    addr->u8[0] = buf[0];
    addr->u8[1] = buf[1];
    return 0;
}

#if IS_USED(MODULE_GNRC_NETIF_IEEE802154_MAC)
static int _iwpan(int argc, char **argv)
{
    if (argc < 3) {
        puts("Usage: iwpan <if_id> scan [active] <duration_us> <ch1> [ch2 ...]\n"
             "       iwpan <if_id> poll <interval_ms|off>\n"
             "       iwpan <if_id> get\n"
             "       iwpan <if_id> set indirect <on|off>\n"
             "       iwpan <if_id> set rx_on_when_idle <on|off>\n"
             "       iwpan <if_id> start <channel> <panid> [short_addr] [payload]\n"
             "       iwpan <if_id> join <channel> <panid> <coord_addr> [capability]\n");
        return 1;
    }
    gnrc_netif_t *netif = NULL;
    gnrc_netif_ieee802154_mac_dev_t *mdev = _get_mdev(argv[1], &netif);
    if (!mdev) {
        puts("invalid interface id or not an IEEE 802.15.4 MAC netif");
        return 1;
    }
    ieee802154_mac_t *mac = &mdev->mac;

    if (strcmp(argv[2], "scan") == 0) {
        return _iwpan_scan_cmd(mac, argc - 2, argv + 2);
    }
    if (strcmp(argv[2], "set") == 0) {
        if (argc < 5) {
            puts("Usage: iwpan <if_id> set indirect <on|off>\n");
            return 1;
        }
        if (strcmp(argv[3], "indirect") == 0) {
            netopt_enable_t en;
            if (strcmp(argv[4], "on") == 0) {
                en = NETOPT_ENABLE;
            }
            else if (strcmp(argv[4], "off") == 0) {
                en = NETOPT_DISABLE;
            }
            else {
                puts("Usage: iwpan <if_id> set indirect <on|off>\n");
                return 1;
            }
            if (netif_set_opt(&netif->netif, NETOPT_TX_INDIRECT, 0,
                              &en, sizeof(en)) < 0) {
                puts("set indirect failed");
                return 1;
            }
            return 0;
        }
        if (strcmp(argv[3], "rx_on_when_idle") == 0) {
            bool enable;
            if (strcmp(argv[4], "on") == 0) {
                enable = true;
            }
            else if (strcmp(argv[4], "off") == 0) {
                enable = false;
            }
            else {
                puts("Usage: iwpan <if_id> set rx_on_when_idle <on|off>\n");
                return 1;
            }
            _set_rx_on_when_idle(mac, enable);
            if (enable && mac->cbs.rx_request) {
                mac->cbs.rx_request(mac);
            }
            return 0;
        }
        puts("Usage: iwpan <if_id> set indirect <on|off>\n"
             "       iwpan <if_id> set rx_on_when_idle <on|off>\n");
        return 1;
    }
    if (strcmp(argv[2], "poll") == 0) {
        if (argc == 3) {
            uint32_t interval = mdev->poll_interval_ms;
            if (interval == 0) {
                puts("poll: off");
            }
            else {
                printf("poll: %u ms\n", (unsigned)interval);
            }
            return 0;
        }
        if (argc < 4) {
            puts("Usage: iwpan <if_id> poll <interval_ms|off>\n");
            return 1;
        }
        if (strcmp(argv[3], "off") == 0) {
            mdev->poll_interval_ms = 0;
            ztimer_remove(ZTIMER_MSEC, &mdev->poll_timer);
            return 0;
        }
        uint32_t interval = (uint32_t)strtoul(argv[3], NULL, 0);
        mdev->poll_interval_ms = interval;
        ztimer_set(ZTIMER_MSEC, &mdev->poll_timer, mdev->poll_interval_ms);
        return 0;
    }
    if (strcmp(argv[2], "get") == 0) {
        ieee802154_pib_value_t panid;
        ieee802154_pib_value_t short_addr;
        ieee802154_mac_mlme_get_request(mac, IEEE802154_PIB_PAN_ID, &panid);
        ieee802154_mac_mlme_get_request(mac, IEEE802154_PIB_SHORT_ADDR, &short_addr);
        printf("panid: 0x%04x\n", panid.v.u16);
        printf("short_addr: 0x%04x\n", byteorder_ntohs(short_addr.v.short_addr));
        printf("channel: %u\n", (unsigned)mac->submac.channel_num);
        return 0;
    }
    if (strcmp(argv[2], "start") == 0) {
        if (argc < 5) {
            puts("Usage: iwpan <if_id> start <channel> <panid> [short_addr] [payload]\n"
                 "  short_addr: 00:01\n");
            return 1;
        }
        uint16_t channel = (uint16_t)strtoul(argv[3], NULL, 0);
        uint16_t panid = (uint16_t)strtoul(argv[4], NULL, 0);
        ieee802154_short_addr_t short_addr = { .u16 = 0x0000 };
        int argi = 5;
        if (argc > argi) {
            if (strchr(argv[argi], ':') != NULL) {
                if (_parse_short_addr(argv[argi], &short_addr) < 0) {
                    puts("start: invalid short address (use 00:01)");
                    return 1;
                }
                argi++;
            }
        }
        ieee802154_pib_value_t v = {
            .type = IEEE802154_PIB_TYPE_U16,
            .v.u16 = panid,
        };
        ieee802154_mac_mlme_set_request(mac, IEEE802154_PIB_PAN_ID, &v);
        ieee802154_pib_value_t sa = {
            .type = IEEE802154_PIB_TYPE_NUI16,
            .v.short_addr = short_addr,
        };
        ieee802154_mac_mlme_set_request(mac, IEEE802154_PIB_SHORT_ADDR, &sa);
        if (argc > argi) {
            size_t len = strlen(argv[argi]);
            if (len > sizeof(mdev->beacon_payload)) {
                puts("start: payload too long");
                return 1;
            }
            memcpy(mdev->beacon_payload, argv[argi], len);
            mdev->beacon_payload_len = len;
            ieee802154_pib_value_t payload = {
                .type = IEEE802154_PIB_TYPE_BYTES,
                .v.bytes = {
                    .ptr = mdev->beacon_payload,
                    .len = len,
                },
            };
            ieee802154_mac_mlme_set_request(mac, IEEE802154_PIB_BEACON_PAYLOAD, &payload);
        }
        int res = ieee802154_mlme_start_request(mac, channel);
        if (res < 0) {
            printf("start failed: %d\n", res);
            return 1;
        }
        return 0;
    }
    if (strcmp(argv[2], "join") == 0) {
        if (argc < 6) {
            puts("Usage: iwpan <if_id> join <channel> <panid> <coord_addr> [capability]\n"
                 "  coord_addr: short (00:01) or long (aa:bb:..:hh)\n");
            return 1;
        }
        uint16_t channel = (uint16_t)strtoul(argv[3], NULL, 0);
        uint16_t panid = (uint16_t)strtoul(argv[4], NULL, 0);
        ieee802154_addr_t coord_addr = { 0 };
        if (_parse_coord_addr(argv[5], &coord_addr) < 0) {
            puts("join: invalid coordinator address (use 00:01 or aa:bb:..:hh)");
            return 1;
        }
        ieee802154_assoc_capability_t cap = { .u8 = 0 };
        cap.bits.rx_on_when_idle = 1;
        cap.bits.allocate_address = 1;
        if (argc >= 7) {
            unsigned long cap_val = strtoul(argv[6], NULL, 0);
            cap.u8 = (uint8_t)cap_val;
        }
        int res = ieee802154_mac_mlme_associate_request(mac, &coord_addr,
                                                        channel, panid, cap);
        if (res < 0) {
            printf("join failed: %d\n", res);
            return 1;
        }
        const void *coord_ptr = NULL;
        if (coord_addr.type == IEEE802154_ADDR_MODE_SHORT) {
            coord_ptr = &coord_addr.v.short_addr;
        }
        else if (coord_addr.type == IEEE802154_ADDR_MODE_EXTENDED) {
            coord_ptr = &coord_addr.v.ext_addr;
        }
        if (coord_ptr) {
            /* Force RX on during association poll window */
            ieee802154_pib_value_t rx_on_prev;
            ieee802154_mac_mlme_get_request(mac, IEEE802154_PIB_RX_ON_WHEN_IDLE, &rx_on_prev);
            _set_rx_on_when_idle(mac, true);
            if (mac->cbs.rx_request) {
                mac->cbs.rx_request(mac);
            }
            int pres = -1;
            for (int attempt = 0; attempt < 5; attempt++) {
                pres = ieee802154_mac_mlme_poll(mac, coord_addr.type, panid, coord_ptr);
                if ((pres != -EBUSY) && (pres != -ENOBUFS)) {
                    break;
                }
                ztimer_sleep(ZTIMER_MSEC, 20);
            }
            if (pres < 0) {
                printf("poll request failed: %d (%s)\n", pres, strerror(-pres));
            }
            /* keep RX on briefly to catch indirect response, then restore */
            ztimer_sleep(ZTIMER_MSEC, 50);
            _set_rx_on_when_idle(mac, rx_on_prev.v.b);
        }
        return 0;
    }
    puts("Usage: iwpan <if_id> scan [active] <duration_us> <ch1> [ch2 ...]\n"
         "       iwpan <if_id> poll <interval_ms|off>\n"
         "       iwpan <if_id> get\n"
         "       iwpan <if_id> set indirect <on|off>\n"
         "       iwpan <if_id> set rx_on_when_idle <on|off>\n"
         "       iwpan <if_id> start <channel> <panid> [short_addr] [payload]\n"
         "         short_addr: 00:01\n"
         "       iwpan <if_id> join <channel> <panid> <coord_addr> [capability]\n"
         "         coord_addr: short (00:01) or long (aa:bb:..:hh)\n");
    return 1;
}

SHELL_COMMAND(iwpan, "IEEE 802.15.4 tools: scan|poll|get|start|join", _iwpan);
#endif
