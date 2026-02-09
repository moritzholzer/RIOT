Expected result
===============
The device repeatedly cycles between an active window (radio RX on) and a
sleep window. The RTC alarm wakes the CPU from the configured power mode. The
IEEE 802.15.4 MAC is provided by GNRC.

How it works
============
- Active window: set all GNRC netifs to `NETOPT_STATE_IDLE` (RX on), wait for
  `DUTY_ACTIVE_MS` milliseconds.
- Sleep window: set all GNRC netifs to `NETOPT_STATE_SLEEP`, arm the RTC alarm,
  then enter `pm_set(DUTY_PM_MODE)`.

Notes
=====
- The app intentionally avoids the shell to reduce PM blockers.
- If deeper modes are still blocked, check runtime blockers with
  `tests/periph/pm` on the same board.
- `DUTY_PM_MODE` defaults to `PM_NUM_MODES - 2` (e.g., STOP on Kinetis).
  Override if your board cannot wake from that mode.

Build & flash
=============
```
BOARD=pba-d-01-kw2x make -C tests/periph/pm_duty_gnrc flash
```

Configuration
=============
You can override defaults at build time:
```
BOARD=pba-d-01-kw2x make -C tests/periph/pm_duty_gnrc \
  CFLAGS="-DDUTY_ACTIVE_MS=100 -DDUTY_SLEEP_S=900 -DDUTY_PM_MODE=2"
```
