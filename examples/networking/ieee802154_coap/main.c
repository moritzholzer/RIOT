/*
 * SPDX-License-Identifier: LGPL-2.1-only
 */

#include <inttypes.h>
#include <errno.h>
#include <math.h>
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
#include "random.h"
#include "sema.h"
#include "shell.h"
#include "msg.h"
#include "thread.h"
#include "uri_parser.h"
#include "ztimer.h"
#include "board.h"

#define ENABLE_DEBUG 0
#include "debug.h"

extern volatile uint32_t gnrc_netif_ieee802154_mac_trace_id;

#ifndef CONFIG_URI_MAX
#define CONFIG_URI_MAX      128
#endif

#define SLEEPY_AWAKE_TIMEOUT_MS          50U
#define SLEEPY_ACTIVE_WINDOW_MS          80U
#define SLEEPY_ACTIVITY_GUARD_MS         SLEEPY_ACTIVE_WINDOW_MS
#define SLEEPY_WAKE_SETTLE_MS            20U
#define SLEEPY_OFF_RETRY_DELAY_MS        10U
#define SLEEPY_OFF_RETRIES               20U
#define COAP_RESPONSE_WAIT_MS            (CONFIG_GCOAP_NON_TIMEOUT_MSEC + 1000U)
#define POISSON_MAX_IN_FLIGHT            1U
#define POISSON_GCOAP_SEND_OPEN_LIMIT    1U
#define MAIN_QUEUE_SIZE                  (256U)

static void _sleepy_note_activity(uint32_t duration_ms);
static msg_t _main_msg_queue[MAIN_QUEUE_SIZE];

typedef struct {
    sema_t *done;
    uint8_t *buf;
    unsigned seq;
    uint16_t msg_id;
    uint32_t trace_id;
    bool response;
    bool sent;
    bool timeout;
    bool send_failed;
    bool error;
    bool async;
    bool completed;
    uint32_t start_us;
} coap_req_ctx_t;

typedef struct {
    volatile bool active;
    char uri[CONFIG_URI_MAX];
    unsigned requested;
    unsigned seq;
    unsigned responses;
    unsigned timeouts;
    unsigned send_failed;
    sema_t done;
} duty_rtt_state_t;

typedef struct {
    gnrc_netif_t *netif;
    netopt_enable_t tx_indirect;
    bool valid;
} tx_indirect_state_t;

static duty_rtt_state_t _duty_rtt;

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

static void _free_req_buf(coap_req_ctx_t *ctx)
{
    if (ctx && ctx->buf) {
        free(ctx->buf);
        ctx->buf = NULL;
    }
}

static void _resp_handler(const gcoap_request_memo_t *memo, coap_pkt_t *pdu,
                          const sock_udp_ep_t *remote)
{
    (void)remote;
    coap_req_ctx_t *ctx = memo->context;

    if (memo->state == GCOAP_MEMO_TIMEOUT) {
        if (ctx) {
            ctx->timeout = true;
            printf("coap: timeout seq=%u msg ID %u trace=%" PRIu32 "\n",
                   ctx->seq, ctx->msg_id, ctx->trace_id);
        }
        else {
            printf("coap: timeout for msg ID %u\n", coap_get_id(pdu));
        }
    }
    else if (memo->state == GCOAP_MEMO_RESP_TRUNC) {
        if (ctx) {
            ctx->error = true;
        }
        puts("coap: warning, incomplete response");
    }
    else if (memo->state != GCOAP_MEMO_RESP) {
        if (ctx) {
            ctx->error = true;
        }
        puts("coap: error in response");
    }
    else {
        if (ctx) {
            ctx->response = true;
        }

        char *class_str = (coap_get_code_class(pdu) == COAP_CLASS_SUCCESS)
                          ? "Success" : "Error";
        if (ctx) {
            printf("coap: response seq=%u msg ID %u trace=%" PRIu32 " %s, code %1u.%02u",
                   ctx->seq, ctx->msg_id, ctx->trace_id, class_str,
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

    if (ctx && ctx->async && memo->state == GCOAP_MEMO_RESP) {
        uint32_t rtt_us = ztimer_now(ZTIMER_USEC) - ctx->start_us;
        printf("%u,%u,%" PRIu32 "\n", ctx->seq, ctx->msg_id, rtt_us);
    }

    /* signal waiting sender if any */
    if (ctx && !ctx->completed) {
        ctx->completed = true;
        _free_req_buf(ctx);
        if (ctx->done) {
            sema_post(ctx->done);
        }
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

    gcoap_resp_init(pdu, buf, len, COAP_CODE_CONTENT);
    coap_opt_add_format(pdu, COAP_FORMAT_TEXT);

    char payload[64];
    int plen = snprintf(payload, sizeof(payload), "ztimer_us=%" PRIu32, now_us);
    if (plen < 0) {
        ssize_t res = gcoap_response(pdu, buf, len,
                                     COAP_CODE_INTERNAL_SERVER_ERROR);
        return res;
    }

    size_t hdr_len = coap_opt_finish(pdu, COAP_OPT_FINISH_PAYLOAD);
    if (hdr_len + (size_t)plen > len) {
        ssize_t res = gcoap_response(pdu, buf, len,
                                     COAP_CODE_INTERNAL_SERVER_ERROR);
        return res;
    }

    memcpy(pdu->payload, payload, (size_t)plen);
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

static uint32_t _exp_delay_ms(uint32_t mean_ms)
{
    if (mean_ms == 0) {
        return 0;
    }

    /* Inverse-transform sampling for Exp(lambda=1/mean_ms). Clamp away
       from 0 so log() stays finite and each interval is independent. */
    double u = ((double)random_uint32() + 1.0) / ((double)UINT32_MAX + 2.0);
    double sample_ms = -(double)mean_ms * log(u);

    if (sample_ms >= (double)UINT32_MAX) {
        return UINT32_MAX;
    }

    return (uint32_t)sample_ms;
}

static void _sleep_ms_jitter(uint32_t mean_ms)
{
    uint32_t delay_ms = _exp_delay_ms(mean_ms);

    if (delay_ms > 0) {
        ztimer_sleep(ZTIMER_MSEC, delay_ms);
    }
}

static int _wait_req_done(sema_t *done, uint32_t timeout_ms)
{
    uint32_t start_ms = ztimer_now(ZTIMER_MSEC);

    while ((uint32_t)(ztimer_now(ZTIMER_MSEC) - start_ms) < timeout_ms) {
        int res = sema_try_wait(done);
        if (res == 0) {
            return 0;
        }
        if (res == -ECANCELED) {
            return res;
        }
        ztimer_sleep(ZTIMER_MSEC, 10);
    }

    return -ETIMEDOUT;
}

static unsigned _drain_req_done(sema_t *done, unsigned drained_count,
                                unsigned sent_count)
{
    while (drained_count < sent_count) {
        if (sema_try_wait(done) != 0) {
            break;
        }
        drained_count++;
    }
    return drained_count;
}

static int _run_coap_get_series(const char *uri, unsigned count, bool indirect,
                                uint32_t start_jitter_ms, uint32_t request_jitter_ms)
{
    sock_udp_ep_t remote;
    char hostbuf[CONFIG_URI_MAX];
    const char *path = NULL;

    if (_uristr2remote(uri, &remote, &path, hostbuf, sizeof(hostbuf)) != 0) {
        puts("coap: invalid URI");
        return 1;
    }

    coap_req_ctx_t req_ctx;
    tx_indirect_state_t tx_indirect;
    sema_t done;

    sema_create(&done, 0);
    req_ctx.done = &done;
    req_ctx.buf = NULL;
    req_ctx.trace_id = 0;
    req_ctx.async = false;
    req_ctx.completed = false;
    if (indirect) {
        int res = _tx_indirect_set(&tx_indirect, true);
        if (res < 0) {
            printf("coap: failed to enable indirect TX: %d\n", res);
            sema_destroy(&done);
            return 1;
        }
    }
    else {
        tx_indirect.valid = false;
    }

    _sleep_ms_jitter(start_jitter_ms);

    for (unsigned i = 0; i < count; i++) {
        uint8_t buf[CONFIG_GCOAP_PDU_BUF_SIZE];
        coap_pkt_t pdu;
        req_ctx.response = false;
        req_ctx.completed = false;

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
        req_ctx.start_us = ztimer_now(ZTIMER_USEC);
        printf("coap: send seq=%u msg ID %u, %" PRIuSIZE " bytes\n",
               req_ctx.seq, req_ctx.msg_id, (size_t)len);
        ssize_t sent = gcoap_req_send(buf, len, &remote, NULL,
                                      _resp_handler, &req_ctx,
                                      GCOAP_SOCKET_TYPE_UDP);

        if (sent <= 0) {
            printf("coap: send failed seq=%u msg ID %u: %d, open requests: %u\n",
                   req_ctx.seq, req_ctx.msg_id, (int)sent,
                   (unsigned)gcoap_op_state());
            if (indirect) {
                printf("coap: aborting at seq=%u msg ID %u due to lower-layer backpressure\n",
                       req_ctx.seq, req_ctx.msg_id);
                break;
            }
            continue;
        }

        int wait_res = _wait_req_done(&done, COAP_RESPONSE_WAIT_MS);
        uint32_t end_us = ztimer_now(ZTIMER_USEC);
        if (wait_res < 0) {
            printf("coap: no callback before local wait timeout seq=%u msg ID %u\n",
                   req_ctx.seq, req_ctx.msg_id);
        }
        else if (req_ctx.response) {
            uint32_t rtt_us = end_us - req_ctx.start_us;
            printf("%u,%u,%" PRIu32 "\n", req_ctx.seq, req_ctx.msg_id, rtt_us);
        }
        else {
            printf("coap: no response seq=%u msg ID %u\n",
                   req_ctx.seq, req_ctx.msg_id);
        }

        _sleep_ms_jitter(request_jitter_ms);
    }

    _tx_indirect_restore(&tx_indirect);
    sema_destroy(&done);
    return 0;
}

static int _run_coap_get_poisson(const char *uri, unsigned count, bool indirect,
                                 uint32_t mean_interval_ms)
{
    sock_udp_ep_t remote;
    char hostbuf[CONFIG_URI_MAX];
    const char *path = NULL;

    if (_uristr2remote(uri, &remote, &path, hostbuf, sizeof(hostbuf)) != 0) {
        puts("coap: invalid URI");
        return 1;
    }

    coap_req_ctx_t *req_ctx = calloc(count, sizeof(*req_ctx));
    if (req_ctx == NULL) {
        puts("coap: no memory for poisson request contexts");
        return 1;
    }
    for (unsigned i = 0; i < count; i++) {
        req_ctx[i].seq = i + 1;
        req_ctx[i].trace_id = i + 1;
    }

    tx_indirect_state_t tx_indirect;
    sema_t *done = malloc(sizeof(*done));
    unsigned sent_count = 0;
    unsigned drained_count = 0;
    bool leaked_state = false;
    bool stop_sending = false;

    if (done == NULL) {
        puts("coap: no memory for poisson semaphore");
        free(req_ctx);
        return 1;
    }

    sema_create(done, 0);
    if (indirect) {
        int res = _tx_indirect_set(&tx_indirect, true);
        if (res < 0) {
            printf("coap: failed to enable indirect TX: %d\n", res);
            sema_destroy(done);
            free(done);
            free(req_ctx);
            return 1;
        }
    }
    else {
        tx_indirect.valid = false;
    }

    _sleep_ms_jitter(mean_interval_ms);

    for (unsigned i = 0; i < count; i++) {
        coap_pkt_t pdu;
        coap_req_ctx_t *ctx = &req_ctx[i];

        while ((unsigned)gcoap_op_state() > POISSON_GCOAP_SEND_OPEN_LIMIT) {
            int wait_res = _wait_req_done(done, COAP_RESPONSE_WAIT_MS);
            if (wait_res < 0) {
                puts("coap: poisson wait_before_send timed out");
                leaked_state = true;
                stop_sending = true;
                break;
            }
            drained_count++;
            drained_count = _drain_req_done(done, drained_count, sent_count);
        }

        if (stop_sending) {
            break;
        }

        ctx->buf = malloc(CONFIG_GCOAP_PDU_BUF_SIZE);
        if (ctx->buf == NULL) {
            puts("coap: no memory for poisson request buffer");
            ctx->send_failed = true;
            ctx->completed = true;
            _sleep_ms_jitter(mean_interval_ms);
            continue;
        }

        int init_res = gcoap_req_init(&pdu, ctx->buf, CONFIG_GCOAP_PDU_BUF_SIZE,
                                      COAP_METHOD_GET, path);
        if (init_res < 0) {
            printf("coap: request init failed: %d\n", init_res);
            ctx->send_failed = true;
            ctx->completed = true;
            _free_req_buf(ctx);
            _sleep_ms_jitter(mean_interval_ms);
            continue;
        }
        ssize_t len = coap_opt_finish(&pdu, COAP_OPT_FINISH_NONE);
        if (len < 0) {
            printf("coap: request build failed: %d\n", (int)len);
            ctx->send_failed = true;
            ctx->completed = true;
            _free_req_buf(ctx);
            _sleep_ms_jitter(mean_interval_ms);
            continue;
        }

        ctx->done = done;
        ctx->msg_id = coap_get_id(&pdu);
        ctx->response = false;
        ctx->sent = false;
        ctx->timeout = false;
        ctx->send_failed = false;
        ctx->error = false;
        ctx->async = true;
        ctx->completed = false;
        ctx->start_us = ztimer_now(ZTIMER_USEC);

        printf("coap: poisson send seq=%u msg ID %u trace=%" PRIu32 ", %" PRIuSIZE " bytes\n",
               ctx->seq, ctx->msg_id, ctx->trace_id, (size_t)len);
        gnrc_netif_ieee802154_mac_trace_id = ctx->trace_id;
        ssize_t sent = gcoap_req_send(ctx->buf, len, &remote, NULL,
                                      _resp_handler, ctx,
                                      GCOAP_SOCKET_TYPE_UDP);
        gnrc_netif_ieee802154_mac_trace_id = 0;

        if (sent <= 0) {
            printf("coap: send failed seq=%u msg ID %u trace=%" PRIu32 ": %d, open requests: %u\n",
                   ctx->seq, ctx->msg_id, ctx->trace_id, (int)sent,
                   (unsigned)gcoap_op_state());
            ctx->send_failed = true;
            ctx->completed = true;
            _free_req_buf(ctx);
            if (indirect) {
                printf("coap: aborting at seq=%u msg ID %u trace=%" PRIu32 " due to lower-layer backpressure\n",
                       ctx->seq, ctx->msg_id, ctx->trace_id);
                break;
            }
        }
        else {
            ctx->sent = true;
            sent_count++;
        }

        while (((sent_count - drained_count) >= POISSON_MAX_IN_FLIGHT) ||
               ((unsigned)gcoap_op_state() >= POISSON_MAX_IN_FLIGHT)) {
            int wait_res = _wait_req_done(done, COAP_RESPONSE_WAIT_MS);
            if (wait_res < 0) {
                puts("coap: poisson in-flight wait timed out");
                leaked_state = true;
                stop_sending = true;
                break;
            }
            drained_count++;
            drained_count = _drain_req_done(done, drained_count, sent_count);
        }

        if (stop_sending) {
            break;
        }

        _sleep_ms_jitter(mean_interval_ms);
    }

    while (!stop_sending && (drained_count < sent_count)) {
        int wait_res = _wait_req_done(done, COAP_RESPONSE_WAIT_MS);
        if (wait_res < 0) {
            puts("coap: poisson wait timed out");
            leaked_state = true;
            stop_sending = true;
            break;
        }
        drained_count++;
        drained_count = _drain_req_done(done, drained_count, sent_count);
    }

    _tx_indirect_restore(&tx_indirect);
    unsigned completed_count = 0;
    unsigned response_count = 0;
    unsigned timeout_count = 0;
    unsigned send_failed_count = 0;
    unsigned error_count = 0;
    unsigned unresolved_count = 0;
    unsigned missing_count = 0;
    for (unsigned i = 0; i < count; i++) {
        if (req_ctx[i].completed) {
            _free_req_buf(&req_ctx[i]);
            completed_count++;
        }
        else if (req_ctx[i].sent) {
            unresolved_count++;
        }
        if (req_ctx[i].response) {
            response_count++;
        }
        if (req_ctx[i].timeout) {
            timeout_count++;
        }
        if (req_ctx[i].send_failed) {
            send_failed_count++;
        }
        if (req_ctx[i].error) {
            error_count++;
        }
        if (!req_ctx[i].response) {
            missing_count++;
        }
    }
    if (unresolved_count > 0) {
        leaked_state = true;
    }

    if (missing_count > 0) {
        for (unsigned i = 0; i < count; i++) {
            if (req_ctx[i].response) {
                continue;
            }
            const char *reason = "not_sent";
            if (req_ctx[i].timeout) {
                reason = "timeout";
            }
            else if (req_ctx[i].send_failed) {
                reason = "send_failed";
            }
            else if (req_ctx[i].error) {
                reason = "error";
            }
            else if (req_ctx[i].sent && !req_ctx[i].completed) {
                reason = "unresolved";
            }
            printf("coap: poisson missing seq=%u msg ID %u trace=%" PRIu32 " reason=%s\n",
                   req_ctx[i].seq, req_ctx[i].msg_id, req_ctx[i].trace_id, reason);
        }
    }
    printf("coap: poisson done requested=%u sent=%u completed=%u responses=%u "
           "timeouts=%u send_failed=%u errors=%u unresolved=%u missing=%u\n",
           count, sent_count, completed_count, response_count, timeout_count,
           send_failed_count, error_count, unresolved_count, missing_count);
    if (!leaked_state) {
        sema_destroy(done);
        free(done);
        free(req_ctx);
    }
    return 0;
}

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

    return _run_coap_get_series(uri, count, indirect, 0, delay_ms);
}

static kernel_pid_t _sleepy_pid = KERNEL_PID_UNDEF;
static volatile bool _sleepy_run = false;
static volatile uint32_t _sleepy_interval_ms = 0;
static volatile kernel_pid_t _sleepy_if_pid = KERNEL_PID_UNDEF;
static volatile uint32_t _sleepy_awake_until_ms = 0;
static volatile uint32_t _sleepy_awake_started_ms = 0;
static volatile uint32_t _sleepy_poll_count = 0;
static volatile uint32_t _sleepy_last_poll_ms = 0;
static volatile int _sleepy_last_poll_res = 0;
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
    uint32_t deadline = _sleepy_awake_started_ms + duration_ms;
    if ((int32_t)(deadline - _sleepy_awake_until_ms) > 0) {
        _sleepy_awake_until_ms = deadline;
    }
}

static void _sleepy_wait_awake_window(uint32_t timeout_ms)
{
    _sleepy_awake_started_ms = ztimer_now(ZTIMER_MSEC);
    _sleepy_awake_until_ms = _sleepy_awake_started_ms + timeout_ms;

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
    int res = -ENODEV;
    _sleepy_poll_count++;
    _sleepy_last_poll_ms = ztimer_now(ZTIMER_MSEC);

    ieee802154_mac_t *mac = gnrc_netif_ieee802154_mac_get();
    if (mac == NULL) {
        _sleepy_last_poll_res = res;
        return;
    }

    ieee802154_pib_value_t panid;
    ieee802154_pib_value_t coord_short;
    ieee802154_pib_value_t coord_ext;

    ieee802154_mac_mlme_get_request(mac, IEEE802154_PIB_PAN_ID, &panid);
    ieee802154_mac_mlme_get_request(mac, IEEE802154_PIB_COORD_SHORT_ADDRESS, &coord_short);
    ieee802154_mac_mlme_get_request(mac, IEEE802154_PIB_COORD_EXTENDED_ADDRESS, &coord_ext);

    if (coord_short.v.short_addr.u16 != 0xffff) {
        res = ieee802154_mac_mlme_poll(mac, IEEE802154_ADDR_MODE_SHORT,
                                        panid.v.u16, &coord_short.v.short_addr);
    }
    else {
        res = ieee802154_mac_mlme_poll(mac, IEEE802154_ADDR_MODE_EXTENDED,
                                        panid.v.u16, &coord_ext.v.ext_addr);
    }
    _sleepy_last_poll_res = res;
}

static void *_sleepy_thread(void *arg)
{
    (void)arg;

    if (_sleepy_set_idle_retry(_sleepy_if_pid) >= 0) {
        _sleepy_wait_awake_window(SLEEPY_AWAKE_TIMEOUT_MS);
    }

    while (_sleepy_run) {
        if (_sleepy_set_off(_sleepy_if_pid) < 0) {
            ztimer_sleep(ZTIMER_MSEC,SLEEPY_ACTIVITY_GUARD_MS);
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

        ztimer_sleep(ZTIMER_MSEC, SLEEPY_WAKE_SETTLE_MS);
        _sleepy_poll();
    }

    (void)_sleepy_set_idle_retry(_sleepy_if_pid);
    _sleepy_restore_periodic_poll(_sleepy_if_pid);
    _sleepy_pid = KERNEL_PID_UNDEF;
    return NULL;
}

static int _cmd_duty(int argc, char **argv)
{

    if (argc >= 5 && argc <= 6 && strcmp(argv[1], "rtt") == 0) {
        char *end = NULL;
        unsigned long interval = strtoul(argv[2], &end, 10);
        if (end == argv[2] || *end != '\0') {
            return 1;
        }

        const char *uri = argv[3];
        unsigned count = (unsigned)atoi(argv[4]);
        if (count == 0) {
            count = 1;
        }

        gnrc_netif_t *netif = NULL;
        if (argc == 6) {
            kernel_pid_t pid = (kernel_pid_t)atoi(argv[5]);
            netif = gnrc_netif_get_by_pid(pid);
        }
        else {
            netif = gnrc_netif_iter(NULL);
        }
        if (netif == NULL) {
            return 1;
        }

        memset(&_duty_rtt, 0, sizeof(_duty_rtt));
        strncpy(_duty_rtt.uri, uri, sizeof(_duty_rtt.uri) - 1);
        _duty_rtt.requested = count;

        if (interval == 0) {
            _sleepy_if_pid = netif->pid;
            (void)_sleepy_set_idle_retry(_sleepy_if_pid);
            return 0;
        }

        sema_create(&_duty_rtt.done, 0);
        _duty_rtt.active = true;

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
                _duty_rtt.active = false;
                sema_destroy(&_duty_rtt.done);
                return 1;
            }
        }

        uint32_t timeout_ms = count * ((uint32_t)interval + COAP_RESPONSE_WAIT_MS +
                                       SLEEPY_ACTIVE_WINDOW_MS + 100U);
        int wait_res = _wait_req_done(&_duty_rtt.done, timeout_ms);
        if (wait_res < 0) {
            _duty_rtt.active = false;
        }

        _sleepy_run = false;
        (void)_sleepy_set_idle_retry(_sleepy_if_pid);
        _sleepy_restore_periodic_poll(_sleepy_if_pid);

        unsigned completed = _duty_rtt.responses + _duty_rtt.timeouts +
                             _duty_rtt.send_failed;
        unsigned missing = count - _duty_rtt.responses;
        printf("coap: duty rtt done requested=%u completed=%u responses=%u "
               "timeouts=%u send_failed=%u missing=%u\n",
               count, completed, _duty_rtt.responses, _duty_rtt.timeouts,
               _duty_rtt.send_failed, missing);
        sema_destroy(&_duty_rtt.done);
        return wait_res < 0 ? 1 : 0;
    }

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
        printf("usage: %s <interval_ms> [iface_pid] | %s rtt <interval_ms> <coap://[addr]/path> <count> [iface_pid]\n",
               argv[0], argv[0]);
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

static int _cmd_rtt(int argc, char **argv)
{
    if (argc < 5 || argc > 6) {
        printf("usage: %s [-i] <coap://[addr]/path> <count> <start_jitter_max_ms> <request_jitter_max_ms>\n",
               argv[0]);
        return 1;
    }

    int arg_idx = 1;
    bool indirect = false;
    if (strcmp(argv[arg_idx], "-i") == 0) {
        indirect = true;
        arg_idx++;
    }

    if ((argc - arg_idx) != 4) {
        printf("usage: %s [-i] <coap://[addr]/path> <count> <start_jitter_max_ms> <request_jitter_max_ms>\n",
               argv[0]);
        return 1;
    }

    const char *uri = argv[arg_idx++];
    unsigned count = (unsigned)atoi(argv[arg_idx++]);
    uint32_t start_jitter_ms = (uint32_t)strtoul(argv[arg_idx++], NULL, 10);
    uint32_t request_jitter_ms = (uint32_t)strtoul(argv[arg_idx++], NULL, 10);

    if (count == 0) {
        count = 1;
    }

    int res = _run_coap_get_series(uri, count, indirect,
                                   start_jitter_ms, request_jitter_ms);
    puts("coap: rtt done");
    return res;
}

static int _cmd_poisson(int argc, char **argv)
{
    if (argc < 4 || argc > 5) {
        printf("usage: %s [-i] <coap://[addr]/path> <count> <mean_interval_ms>\n",
               argv[0]);
        return 1;
    }

    int arg_idx = 1;
    bool indirect = false;
    if (strcmp(argv[arg_idx], "-i") == 0) {
        indirect = true;
        arg_idx++;
    }

    if ((argc - arg_idx) != 3) {
        printf("usage: %s [-i] <coap://[addr]/path> <count> <mean_interval_ms>\n",
               argv[0]);
        return 1;
    }

    const char *uri = argv[arg_idx++];
    unsigned count = (unsigned)atoi(argv[arg_idx++]);
    uint32_t mean_interval_ms = (uint32_t)strtoul(argv[arg_idx++], NULL, 10);

    if (count == 0) {
        count = 1;
    }

    return _run_coap_get_poisson(uri, count, indirect, mean_interval_ms);
}

static const shell_command_t _commands[] = {
    { "coap", "coap get [-i] <coap://[addr]/path>", _cmd_coap },
    { "rtt", "rtt [-i] <coap://[addr]/path> <count> <start_jitter_max_ms> <request_jitter_max_ms>", _cmd_rtt },
    { "poisson", "poisson [-i] <coap://[addr]/path> <count> <mean_interval_ms>", _cmd_poisson },
    { "duty", "duty <interval_ms> [iface_pid] | duty rtt <interval_ms> <coap://[addr]/path> <count> [iface_pid] | duty stop", _cmd_duty },
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

#define COAP_SHELL_BUFSIZE 256

int main(void)
{
    gcoap_register_listener(&_listener);
    _auto_add_link_local();
    msg_init_queue(_main_msg_queue, MAIN_QUEUE_SIZE);
    char line_buf[COAP_SHELL_BUFSIZE];
    shell_run(_commands, line_buf, COAP_SHELL_BUFSIZE);
    while (1){
        puts("test\n");
        ztimer_sleep(ZTIMER_MSEC, 1000);
    }
    return 0;
}
