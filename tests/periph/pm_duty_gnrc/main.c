/*
 * SPDX-FileCopyrightText: 2026
 * SPDX-License-Identifier: LGPL-2.1-only
 */

/**
 * @ingroup     tests
 * @{
 *
 * @file
 * @brief       Duty-cycling test using RTC wake + GNRC IEEE802154 MAC
 *
 * @}
 */

#include <time.h>

#include "board.h"
#include "periph/pm.h"
#include "pm_layered.h"
#include "periph/rtc.h"

#include "net/netopt.h"
#include "net/gnrc/netif.h"
#include "net/gnrc/netapi.h"

#include "ztimer.h"

#ifndef DUTY_ACTIVE_MS
#define DUTY_ACTIVE_MS (100U)
#endif

#ifndef DUTY_SLEEP_S
#define DUTY_SLEEP_S   (5U)
#endif

#ifndef DUTY_PM_MODE
#define DUTY_PM_MODE   (1)
#endif

static volatile uint8_t _rtc_fired = 0;

static void _rtc_cb(void *arg)
{
    (void)arg;
    _rtc_fired = 1;
}

static void _set_netif_state(netopt_state_t state)
{
    gnrc_netif_t *netif = NULL;

    while ((netif = gnrc_netif_iter(netif))) {
        gnrc_netapi_opt_t opt = {
            .opt = NETOPT_STATE,
            .context = 0,
            .data = &state,
            .data_len = sizeof(state),
        };
        gnrc_netif_set_from_netdev(netif, &opt);
    }
}

static void _schedule_rtc_alarm(unsigned sleep_s)
{
    struct tm now = {
        .tm_year = 120, /* 2020 */
        .tm_mon = 0,
        .tm_mday = 1,
    };

    if (rtc_get_time(&now) != 0) {
        (void)rtc_set_time(&now);
    }

    rtc_clear_alarm();
    now.tm_sec += sleep_s;
    (void)rtc_set_alarm(&now, _rtc_cb, NULL);
}

int main(void)
{
    /* Keep the chosen PM mode blocked except during the sleep window. */
    pm_block(DUTY_PM_MODE);
    LED0_OFF;

    rtc_init();
    struct tm boot = {
        .tm_year = 120, /* 2020 */
        .tm_mon = 0,
        .tm_mday = 1,
    };
    (void)rtc_set_time(&boot);

    for (unsigned i = 0; i < 6; i++) {
        LED0_TOGGLE;
        ztimer_sleep(ZTIMER_MSEC, 150);
    }

    while (1) {
        /* Active window: bring radios up (RX on) and do any work. */
        _set_netif_state(NETOPT_STATE_IDLE);
        LED0_TOGGLE;
#if DUTY_ACTIVE_MS > 0
        ztimer_sleep(ZTIMER_MSEC, DUTY_ACTIVE_MS);
#endif

        /* Sleep window: put radios to sleep and enter low-power mode. */
        _set_netif_state(NETOPT_STATE_OFF);
        _schedule_rtc_alarm(DUTY_SLEEP_S);
        _rtc_fired = 0;
        LED0_TOGGLE;

        pm_unblock(DUTY_PM_MODE);
        pm_set(DUTY_PM_MODE);
        pm_block(DUTY_PM_MODE);

        /* Toggle LED on every RTC wakeup. */
        if (_rtc_fired) {
            LED0_TOGGLE;
        }
    }

    return 0;
}
