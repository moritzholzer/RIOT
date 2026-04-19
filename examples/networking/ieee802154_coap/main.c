/*
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <inttypes.h>
#include <stdio.h>
#include <string.h>

#include "net/gcoap.h"
#include "net/gnrc/netapi.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netif/ieee802154_mac.h"
#include "net/ipv6/addr.h"
#include "net/l2util.h"
#include "net/ieee802154.h"
#include "net/ieee802154/mac.h"
#include "net/netopt.h"
#include "net/sock/udp.h"
#include "net/sock/util.h"
#include "od.h"
#include "sema.h"
#include "shell.h"
#include "thread.h"
#include "uri_parser.h"
#include "ztimer.h"
#include "board.h"

#define ENABLE_DEBUG 0
#include "debug.h"

#ifndef CONFIG_URI_MAX
#define CONFIG_URI_MAX      128
#endif

#define SLEEPY_AWAKE_TIMEOUT_MS          300U
#define SLEEPY_ACTIVITY_GUARD_MS         250U

static void _sleepy_note_activity(uint32_t duration_ms);

static void _resp_handler(const gcoap_request_memo_t *memo, coap_pkt_t *pdu,
                          const sock_udp_ep_t *remote)
{
    (void)remote;

    if (memo->state == GCOAP_MEMO_TIMEOUT) {
        (void)pdu;
    }
    else if (memo->state == GCOAP_MEMO_RESP_TRUNC) {
    }
    else if (memo->state != GCOAP_MEMO_RESP) {
    }

    /* signal waiting sender if any */
    sema_post((sema_t *)memo->context);
}

static int _uristr2remote(const char *uri, sock_udp_ep_t *remote,
                          const char **path, char *buf, size_t buf_len)
{
    if (strlen(uri) >= buf_len) {
        DEBUG_PUTS("URI too long");
        return -1;
    }

    uri_parser_result_t urip;
    if (uri_parser_process(&urip, uri, strlen(uri))) {
        DEBUG("'%s' is not a valid URI\n", uri);
        return -1;
    }

    memcpy(buf, urip.host, urip.host_len);
    buf[urip.host_len] = '\0';

    if (urip.port_str_len) {
        strcat(buf, ":");
        strncat(buf, urip.port_str, urip.port_str_len);
        buf[urip.host_len + 1 + urip.port_str_len] = '\0';
    }

    if (sock_udp_name2ep(remote, buf) != 0) {
        DEBUG("Could not resolve address '%s'\n", buf);
        return -1;
    }

    if (remote->port == 0) {
        remote->port = COAP_PORT;
    }

    if (urip.path_len == 0) {
        *path = NULL;
    }
    else {
        *path = urip.path;
    }

    return 0;
}

static ssize_t _ts_handler(coap_pkt_t *pdu, uint8_t *buf, size_t len,
                           coap_request_ctx_t *context)
{
    (void)context;
    _sleepy_note_activity(SLEEPY_ACTIVITY_GUARD_MS);

    uint32_t now_us = ztimer_now(ZTIMER_USEC);

    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    coap_opt_add_format(pdu, COAP_FORMAT_TEXT);

    char payload[64];
    int plen = snprintf(payload, sizeof(payload), "ztimer_us=%" PRIu32, now_us);
    if (plen < 0) {
        return gcoap_response(pdu, buf, len, COAP_CODE_INTERNAL_SERVER_ERROR);
    }

    size_t hdr_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);
    if (hdr_len + (size_t)plen > len) {
        return gcoap_response(pdu, buf, len, COAP_CODE_INTERNAL_SERVER_ERROR);
    }

    memcpy(pdu->payload, payload, (size_t)plen);
    _sleepy_note_activity(SLEEPY_ACTIVITY_GUARD_MS);
    return (ssize_t)(hdr_len + (size_t)plen);
}

static const coap_resource_t _resources[] = {
    { "/ts", COAP_METHOD_GET, _ts_handler, NULL },
};

static gcoap_listener_t _listener = {
    .resources = _resources,
    .resources_len = ARRAY_SIZE(_resources),
    .next = NULL,
};

static int _cmd_coap(int argc, char **argv)
{
    if (argc < 3 || strcmp(argv[1], "get") != 0) {
        printf("usage: %s get <coap://[addr]/path> [count] [delay_ms]\n", argv[0]);
        return 1;
    }

    const char *uri = argv[2];
    unsigned count = 1;
    unsigned delay_ms = 0;
    if (argc >= 4) {
        count = (unsigned)atoi(argv[3]);
        if (count == 0) {
            count = 1;
        }
    }
    if (argc >= 5) {
        delay_ms = (unsigned)atoi(argv[4]);
    }

    sock_udp_ep_t remote;
    char hostbuf[CONFIG_URI_MAX];
    const char *path = NULL;

    if (_uristr2remote(uri, &remote, &path, hostbuf, sizeof(hostbuf)) != 0) {
        puts("coap: invalid URI");
        return 1;
    }

    sema_t resp_sema;
    sema_create(&resp_sema, 0);

    for (unsigned i = 0; i < count; i++) {
        uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
        coap_pkt_t pdu;

        gcoap_req_init(&pdu, buf, sizeof(buf), COAP_METHOD_GET, path);
        ssize_t len = coap_opt_finish(&pdu, COAP_OPT_FINISH_NONE);

        uint32_t start_us = ztimer_now(ZTIMER_USEC);
        ssize_t sent = gcoap_req_send(buf, len, &remote, NULL,
                                      _resp_handler, &resp_sema,
                                      GCOAP_SOCKET_TYPE_UDP);
        if (sent <= 0) {
            continue;
        }

        int wait_res = sema_wait_timed_ztimer(&resp_sema, ZTIMER_MSEC, 2000);
        uint32_t end_us = ztimer_now(ZTIMER_USEC);
        if (wait_res < 0) {
        }
        else {
            uint32_t rtt_us = end_us - start_us;
            printf("%u,%" PRIu32 "\n", i + 1, rtt_us);
        }

        if (delay_ms) {
            ztimer_sleep(ZTIMER_MSEC, delay_ms);
        }
    }

    sema_destroy(&resp_sema);
    return 0;
}

static kernel_pid_t _sleepy_pid = KERNEL_PID_UNDEF;
static volatile bool _sleepy_run = false;
static volatile uint32_t _sleepy_interval_ms = 0;
static volatile kernel_pid_t _sleepy_if_pid = KERNEL_PID_UNDEF;
static volatile uint32_t _sleepy_awake_until_ms = 0;
static char _sleepy_stack[THREAD_STACKSIZE_DEFAULT];

void _sleepy_note_activity(uint32_t duration_ms)
{
    uint32_t deadline = ztimer_now(ZTIMER_MSEC) + duration_ms;
    if ((int32_t)(deadline - _sleepy_awake_until_ms) > 0) {
        _sleepy_awake_until_ms = deadline;
    }
}

static void _sleepy_wait_awake_window(uint32_t timeout_ms)
{
    _sleepy_note_activity(timeout_ms);

    while (_sleepy_run) {
        uint32_t now = ztimer_now(ZTIMER_MSEC);
        if ((int32_t)(_sleepy_awake_until_ms - now) <= 0) {
            break;
        }
        /* 10ms sleep because we can't get a finished callback from gcoap */
        ztimer_sleep(ZTIMER_MSEC, 10);
    }
}

static void _sleepy_poll(void)
{
    ieee802154_mac_t *mac = gnrc_netif_ieee802154_mac_get();
    if (mac == NULL) {
        return;
    }

    ieee802154_pib_value_t panid;
    ieee802154_pib_value_t coord_short;
    ieee802154_pib_value_t coord_ext;

    ieee802154_mac_mlme_get_request(mac, IEEE802154_PIB_PAN_ID, &panid);
    ieee802154_mac_mlme_get_request(mac, IEEE802154_PIB_COORD_SHORT_ADDRESS, &coord_short);
    ieee802154_mac_mlme_get_request(mac, IEEE802154_PIB_COORD_EXTENDED_ADDRESS, &coord_ext);

    if (coord_short.v.short_addr.u16 != 0xffff) {
        (void)ieee802154_mac_mlme_poll(mac, IEEE802154_ADDR_MODE_SHORT,
                                       panid.v.u16, &coord_short.v.short_addr);
    }
    else {
        (void)ieee802154_mac_mlme_poll(mac, IEEE802154_ADDR_MODE_EXTENDED,
                                       panid.v.u16, &coord_ext.v.ext_addr);
    }
}

static void *_sleepy_thread(void *arg)
{
    (void)arg;

    while (_sleepy_run) {
        netopt_state_t sleep_state = NETOPT_STATE_OFF;
        (void)gnrc_netapi_set(_sleepy_if_pid, NETOPT_STATE, 0,
                              &sleep_state, sizeof(sleep_state));

        ztimer_sleep(ZTIMER_MSEC, _sleepy_interval_ms);
        if (!_sleepy_run) {
            break;
        }

        netopt_state_t idle_state = NETOPT_STATE_IDLE;
        (void)gnrc_netapi_set(_sleepy_if_pid, NETOPT_STATE, 0,
                              &idle_state, sizeof(idle_state));

        _sleepy_poll();
        _sleepy_wait_awake_window(SLEEPY_AWAKE_TIMEOUT_MS);
    }

    return NULL;
}

static int _cmd_duty(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "stop") == 0) {
        _sleepy_run = false;
        if (_sleepy_if_pid != KERNEL_PID_UNDEF) {
            netopt_state_t idle_state = NETOPT_STATE_IDLE;
            (void)gnrc_netapi_set(_sleepy_if_pid, NETOPT_STATE, 0,
                                  &idle_state, sizeof(idle_state));
        }
        return 0;
    }

    if (argc < 2 || argc > 3) {
        printf("usage: %s <interval_ms> [iface_pid]\n", argv[0]);
        return 1;
    }

    char *end = NULL;
    unsigned long interval = strtoul(argv[1], &end, 10);
    if (end == argv[1] || *end != '\0') {
        return 1;
    }

    gnrc_netif_t *netif = NULL;
    if (argc == 3) {
        kernel_pid_t pid = (kernel_pid_t)atoi(argv[2]);
        netif = gnrc_netif_get_by_pid(pid);
    }
    else {
        netif = gnrc_netif_iter(NULL);
    }

    if (netif == NULL) {
        return 1;
    }

    _sleepy_interval_ms = (uint32_t)interval;
    _sleepy_if_pid = netif->pid;
    _sleepy_run = true;

    if (_sleepy_pid == KERNEL_PID_UNDEF) {
        _sleepy_pid = thread_create(_sleepy_stack, sizeof(_sleepy_stack),
                                    THREAD_PRIORITY_MAIN - 1, 0,
                                    _sleepy_thread, NULL, "sleepy");
        if (_sleepy_pid <= KERNEL_PID_UNDEF) {
            _sleepy_pid = KERNEL_PID_UNDEF;
            _sleepy_run = false;
            return 1;
        }
    }

    return 0;
}

static const shell_command_t _commands[] = {
    { "coap", "coap get <coap://[addr]/path>", _cmd_coap },
    { "duty", "duty <interval_ms> [iface_pid] | duty stop", _cmd_duty },
    { NULL, NULL, NULL }
};

static void _auto_add_link_local(void)
{
    for (gnrc_netif_t *netif = gnrc_netif_iter(NULL); netif;
         netif = gnrc_netif_iter(netif)) {
        if (!(netif->flags & GNRC_NETIF_FLAGS_HAS_L2ADDR)) {
            continue;
        }

        eui64_t iid;
        uint8_t lladdr[GNRC_NETIF_L2ADDR_MAXLEN];
        size_t lladdr_len = netif->l2addr_len;
        int res = -ENOTSUP;

        if (lladdr_len > sizeof(lladdr)) {
            continue;
        }
        if (lladdr_len > 0) {
            memcpy(lladdr, netif->l2addr, lladdr_len);
        }

        if (netif->dev && netif->dev->driver) {
            /* prefer long address if available */
            res = netif->dev->driver->get(netif->dev, NETOPT_ADDRESS_LONG,
                                          lladdr, sizeof(lladdr));
            if (res == (int)IEEE802154_LONG_ADDRESS_LEN) {
                lladdr_len = IEEE802154_LONG_ADDRESS_LEN;
            }
        }

        if (lladdr_len == 0) {
            continue;
        }

        if (l2util_ipv6_iid_from_addr(netif->device_type, lladdr,
                                      lladdr_len, &iid) < 0) {
            continue;
        }

        ipv6_addr_t ll;
        ipv6_addr_set_link_local_prefix(&ll);
        ipv6_addr_set_aiid(&ll, iid.uint8);
        (void)gnrc_netif_ipv6_addr_add(netif, &ll, 64, 0);
    }
}

int main(void)
{
    gcoap_register_listener(&_listener);
    _auto_add_link_local();
    char line_buf[SHELL_DEFAULT_BUFSIZE];
    shell_run(_commands, line_buf, SHELL_DEFAULT_BUFSIZE);
    return 0;
}
