/*
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <inttypes.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "net/gcoap.h"
#include "net/gnrc/pktbuf.h"
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

#define SLEEPY_AWAKE_TIMEOUT_MS          20U
#define SLEEPY_ACTIVITY_GUARD_MS         50U
#define SLEEPY_OFF_RETRY_DELAY_MS        10U
#define SLEEPY_OFF_RETRIES               20U
#define COAP_RESPONSE_WAIT_MS            (CONFIG_GCOAP_NON_TIMEOUT_MSEC + 1000U)

static void _sleepy_note_activity(uint32_t duration_ms);

typedef struct {
    sema_t done;
    unsigned seq;
    uint16_t msg_id;
    bool response;
} coap_req_ctx_t;

typedef struct {
    gnrc_netif_t *netif;
    netopt_enable_t tx_indirect;
    bool valid;
} tx_indirect_state_t;

static int _tx_indirect_set(tx_indirect_state_t *state, bool enable)
{
    state->valid = false;
    state->netif = gnrc_netif_iter(NULL);

    if (state->netif == NULL) {
        return -ENODEV;
    }

    int res = gnrc_netapi_get(state->netif->pid, NETOPT_TX_INDIRECT, 0,
                              &state->tx_indirect, sizeof(state->tx_indirect));
    if (res < 0) {
        return res;
    }

    netopt_enable_t value = enable ? NETOPT_ENABLE : NETOPT_DISABLE;
    res = gnrc_netapi_set(state->netif->pid, NETOPT_TX_INDIRECT, 0,
                          &value, sizeof(value));
    if (res < 0) {
        return res;
    }

    state->valid = true;
    printf("coap: TX_INDIRECT %s on iface %" PRIkernel_pid "\n",
           enable ? "on" : "off", state->netif->pid);
    return 0;
}

static void _tx_indirect_restore(const tx_indirect_state_t *state)
{
    if (!state->valid) {
        return;
    }

    (void)gnrc_netapi_set(state->netif->pid, NETOPT_TX_INDIRECT, 0,
                          &state->tx_indirect, sizeof(state->tx_indirect));
}

static void _resp_handler(const gcoap_request_memo_t *memo, coap_pkt_t *pdu,
                          const sock_udp_ep_t *remote)
{
    (void)remote;
    coap_req_ctx_t *ctx = memo->context;

    if (memo->state == GCOAP_MEMO_TIMEOUT) {
        if (ctx) {
            printf("coap: timeout seq=%u msg ID %u\n",
                   ctx->seq, ctx->msg_id);
        }
        else {
            printf("coap: timeout for msg ID %u\n", coap_get_id(pdu));
        }
    }
    else if (memo->state == GCOAP_MEMO_RESP_TRUNC) {
        puts("coap: warning, incomplete response");
    }
    else if (memo->state != GCOAP_MEMO_RESP) {
        puts("coap: error in response");
    }
    else {
        if (ctx) {
            ctx->response = true;
        }

        char *class_str = (coap_get_code_class(pdu) == COAP_CLASS_SUCCESS)
                          ? "Success" : "Error";
        if (ctx) {
            printf("coap: response seq=%u msg ID %u %s, code %1u.%02u",
                   ctx->seq, ctx->msg_id, class_str,
                   coap_get_code_class(pdu), coap_get_code_detail(pdu));
        }
        else {
            printf("coap: response %s, code %1u.%02u",
                   class_str, coap_get_code_class(pdu),
                   coap_get_code_detail(pdu));
        }

        if (pdu->payload_len) {
            unsigned content_type = coap_get_content_type(pdu);

            if (content_type == COAP_FORMAT_TEXT ||
                content_type == COAP_FORMAT_LINK ||
                coap_get_code_class(pdu) == COAP_CLASS_CLIENT_FAILURE ||
                coap_get_code_class(pdu) == COAP_CLASS_SERVER_FAILURE) {
                printf(", %u bytes\n%.*s\n", (unsigned)pdu->payload_len,
                       (int)pdu->payload_len, (char *)pdu->payload);
            }
            else {
                printf(", %u bytes\n", (unsigned)pdu->payload_len);
                od_hex_dump(pdu->payload, pdu->payload_len, OD_WIDTH_DEFAULT);
            }
        }
        else {
            puts(", empty payload");
        }
    }

    /* signal waiting sender if any */
    if (ctx) {
        sema_post(&ctx->done);
    }
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
    uint16_t msg_id = coap_get_id(pdu);
    printf("coap: received GET /ts msg ID %u at %" PRIu32 " us\n",
           msg_id, now_us);

    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    coap_opt_add_format(pdu, COAP_FORMAT_TEXT);

    char payload[64];
    int plen = snprintf(payload, sizeof(payload), "ztimer_us=%" PRIu32, now_us);
    if (plen < 0) {
        ssize_t res = gcoap_response(pdu, buf, len,
                                     COAP_CODE_INTERNAL_SERVER_ERROR);
        printf("coap: response error msg ID %u res=%d\n", msg_id, (int)res);
        return res;
    }

    size_t hdr_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);
    if (hdr_len + (size_t)plen > len) {
        ssize_t res = gcoap_response(pdu, buf, len,
                                     COAP_CODE_INTERNAL_SERVER_ERROR);
        printf("coap: response error msg ID %u res=%d\n", msg_id, (int)res);
        return res;
    }

    memcpy(pdu->payload, payload, (size_t)plen);
    _sleepy_note_activity(SLEEPY_ACTIVITY_GUARD_MS);
    ssize_t res = (ssize_t)(hdr_len + (size_t)plen);
    printf("coap: response prepared msg ID %u len=%d\n", msg_id, (int)res);
    return res;
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
        printf("usage: %s get [-i] <coap://[addr]/path> [count] [delay_ms]\n", argv[0]);
        return 1;
    }

    int arg_idx = 2;
    bool indirect = false;
    if (strcmp(argv[arg_idx], "-i") == 0) {
        indirect = true;
        arg_idx++;
    }

    if (argc <= arg_idx) {
        printf("usage: %s get [-i] <coap://[addr]/path> [count] [delay_ms]\n", argv[0]);
        return 1;
    }

    const char *uri = argv[arg_idx++];
    unsigned count = 1;
    unsigned delay_ms = 0;
    if (argc > arg_idx) {
        count = (unsigned)atoi(argv[arg_idx++]);
        if (count == 0) {
            count = 1;
        }
    }
    if (argc > arg_idx) {
        delay_ms = (unsigned)atoi(argv[arg_idx++]);
    }
    if (argc > arg_idx) {
        printf("usage: %s get [-i] <coap://[addr]/path> [count] [delay_ms]\n", argv[0]);
        return 1;
    }

    sock_udp_ep_t remote;
    char hostbuf[CONFIG_URI_MAX];
    const char *path = NULL;

    if (_uristr2remote(uri, &remote, &path, hostbuf, sizeof(hostbuf)) != 0) {
        puts("coap: invalid URI");
        return 1;
    }

    coap_req_ctx_t req_ctx;
    tx_indirect_state_t tx_indirect;

    sema_create(&req_ctx.done, 0);
    if (indirect) {
        int res = _tx_indirect_set(&tx_indirect, true);
        if (res < 0) {
            printf("coap: failed to enable indirect TX: %d\n", res);
            sema_destroy(&req_ctx.done);
            return 1;
        }
    }
    else {
        tx_indirect.valid = false;
    }

    bool send_failure_diag_printed = false;
    for (unsigned i = 0; i < count; i++) {
        uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
        coap_pkt_t pdu;
        req_ctx.response = false;

        int init_res = gcoap_req_init(&pdu, buf, sizeof(buf),
                                      COAP_METHOD_GET, path);
        if (init_res < 0) {
            printf("coap: request init failed: %d\n", init_res);
            continue;
        }
        ssize_t len = coap_opt_finish(&pdu, COAP_OPT_FINISH_NONE);
        if (len < 0) {
            printf("coap: request build failed: %d\n", (int)len);
            continue;
        }

        req_ctx.seq = i + 1;
        req_ctx.msg_id = coap_get_id(&pdu);
        uint32_t start_us = ztimer_now(ZTIMER_USEC);
        printf("coap: send seq=%u msg ID %u, %" PRIuSIZE " bytes\n",
               req_ctx.seq, req_ctx.msg_id, (size_t)len);
        ssize_t sent = gcoap_req_send(buf, len, &remote, NULL,
                                      _resp_handler, &req_ctx,
                                      GCOAP_SOCKET_TYPE_UDP);

        if (sent <= 0) {
            printf("coap: send failed seq=%u msg ID %u: %d, open requests: %u\n",
                   req_ctx.seq, req_ctx.msg_id, (int)sent,
                   (unsigned)gcoap_op_state());
            if (!send_failure_diag_printed) {
                gnrc_pktbuf_stats();
                send_failure_diag_printed = true;
            }
            continue;
        }

        int wait_res = sema_wait_timed_ztimer(&req_ctx.done, ZTIMER_MSEC,
                                              COAP_RESPONSE_WAIT_MS);
        uint32_t end_us = ztimer_now(ZTIMER_USEC);
        if (wait_res < 0) {
            printf("coap: no callback before local wait timeout seq=%u msg ID %u\n",
                   req_ctx.seq, req_ctx.msg_id);
        }
        else if (req_ctx.response) {
            uint32_t rtt_us = end_us - start_us;
            printf("%u,%" PRIu32 "\n", i + 1, rtt_us);
        }
        else {
            printf("coap: no response seq=%u msg ID %u\n",
                   req_ctx.seq, req_ctx.msg_id);
        }

        if (delay_ms) {
            ztimer_sleep(ZTIMER_MSEC, delay_ms);
        }
    }

    _tx_indirect_restore(&tx_indirect);
    sema_destroy(&req_ctx.done);
    return 0;
}

static kernel_pid_t _sleepy_pid = KERNEL_PID_UNDEF;
static volatile bool _sleepy_run = false;
static volatile uint32_t _sleepy_interval_ms = 0;
static volatile kernel_pid_t _sleepy_if_pid = KERNEL_PID_UNDEF;
static volatile uint32_t _sleepy_awake_until_ms = 0;
static volatile bool _sleepy_poll_interval_valid = false;
static volatile uint32_t _sleepy_poll_interval_ms = 0;
static char _sleepy_stack[THREAD_STACKSIZE_DEFAULT];

static int _sleepy_set_state(kernel_pid_t pid, netopt_state_t state)
{
    if (pid == KERNEL_PID_UNDEF) {
        gnrc_netif_t *netif = gnrc_netif_iter(NULL);
        if (netif == NULL) {
            return -ENODEV;
        }
        pid = netif->pid;
    }

    return gnrc_netapi_set(pid, NETOPT_STATE, 0,
                           &state, sizeof(state));
}

static int _sleepy_set_idle(kernel_pid_t pid)
{
    return _sleepy_set_state(pid, NETOPT_STATE_IDLE);
}

static int _sleepy_set_idle_retry(kernel_pid_t pid)
{
    int res = -EBUSY;

    for (unsigned i = 0; i <= SLEEPY_OFF_RETRIES; i++) {
        res = _sleepy_set_idle(pid);
        if (res >= 0) {
            return res;
        }
        if (res != -EBUSY) {
            return res;
        }
        ztimer_sleep(ZTIMER_MSEC, SLEEPY_OFF_RETRY_DELAY_MS);
    }

    return res;
}

static int _sleepy_set_off(kernel_pid_t pid)
{
    int res = -EBUSY;

    for (unsigned i = 0; i <= SLEEPY_OFF_RETRIES; i++) {
        res = _sleepy_set_state(pid, NETOPT_STATE_OFF);
        if (res >= 0) {
            return res;
        }
        if (res != -EBUSY) {
            return res;
        }
        ztimer_sleep(ZTIMER_MSEC, SLEEPY_OFF_RETRY_DELAY_MS);
    }

    return res;
}

static void _sleepy_disable_periodic_poll(kernel_pid_t pid)
{
    uint32_t interval;

    if (_sleepy_poll_interval_valid) {
        return;
    }
    if (gnrc_netapi_get(pid, NETOPT_POLL_INTERVAL, 0,
                        &interval, sizeof(interval)) < 0) {
        return;
    }

    _sleepy_poll_interval_ms = interval;
    interval = 0;
    if (gnrc_netapi_set(pid, NETOPT_POLL_INTERVAL, 0,
                        &interval, sizeof(interval)) >= 0) {
        _sleepy_poll_interval_valid = true;
    }
}

static void _sleepy_restore_periodic_poll(kernel_pid_t pid)
{
    if (!_sleepy_poll_interval_valid || (pid == KERNEL_PID_UNDEF)) {
        return;
    }

    uint32_t interval = _sleepy_poll_interval_ms;
    if (gnrc_netapi_set(pid, NETOPT_POLL_INTERVAL, 0,
                        &interval, sizeof(interval)) >= 0) {
        _sleepy_poll_interval_valid = false;
    }
}

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

    if (_sleepy_set_idle_retry(_sleepy_if_pid) >= 0) {
        _sleepy_wait_awake_window(SLEEPY_AWAKE_TIMEOUT_MS);
    }

    while (_sleepy_run) {
        if (_sleepy_set_off(_sleepy_if_pid) < 0) {
            _sleepy_wait_awake_window(SLEEPY_ACTIVITY_GUARD_MS);
            continue;
        }

        ztimer_sleep(ZTIMER_MSEC, _sleepy_interval_ms);
        if (!_sleepy_run) {
            (void)_sleepy_set_idle_retry(_sleepy_if_pid);
            break;
        }

        if (_sleepy_set_idle_retry(_sleepy_if_pid) < 0) {
            ztimer_sleep(ZTIMER_MSEC, SLEEPY_OFF_RETRY_DELAY_MS);
            continue;
        }

        _sleepy_poll();
        _sleepy_wait_awake_window(SLEEPY_AWAKE_TIMEOUT_MS);
    }

    (void)_sleepy_set_idle_retry(_sleepy_if_pid);
    _sleepy_restore_periodic_poll(_sleepy_if_pid);
    _sleepy_pid = KERNEL_PID_UNDEF;
    return NULL;
}

static int _cmd_duty(int argc, char **argv)
{
    if (argc == 2 && strcmp(argv[1], "stop") == 0) {
        _sleepy_run = false;
        int res = _sleepy_set_idle_retry(_sleepy_if_pid);
        if (res < 0) {
            printf("duty: stop failed to set idle: %d\n", res);
            return 1;
        }
        _sleepy_restore_periodic_poll(_sleepy_if_pid);
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
    _sleepy_disable_periodic_poll(_sleepy_if_pid);
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

static int _cmd_indirect(int argc, char **argv)
{
    if (argc < 2 || argc > 3 ||
        (strcmp(argv[1], "on") != 0 && strcmp(argv[1], "off") != 0)) {
        printf("usage: %s on|off [iface_pid]\n", argv[0]);
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

    netopt_enable_t value = (strcmp(argv[1], "on") == 0)
                            ? NETOPT_ENABLE : NETOPT_DISABLE;
    int res = gnrc_netapi_set(netif->pid, NETOPT_TX_INDIRECT, 0,
                              &value, sizeof(value));
    if (res < 0) {
        printf("indirect: failed: %d\n", res);
        return 1;
    }

    return 0;
}

static const shell_command_t _commands[] = {
    { "coap", "coap get [-i] <coap://[addr]/path>", _cmd_coap },
    { "duty", "duty <interval_ms> [iface_pid] | duty stop", _cmd_duty },
    { "indirect", "indirect on|off [iface_pid]", _cmd_indirect },
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
