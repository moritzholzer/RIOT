BOARD ?= pba-d-01-kw2x

include ../Makefile.periph_common

FEATURES_OPTIONAL += periph_rtc

# GNRC + IEEE 802.15.4 MAC stack
USEMODULE += gnrc
USEMODULE += auto_init_gnrc_netif
USEMODULE += gnrc_netif_ieee802154_mac
USEMODULE += ieee802154_mac
USEMODULE += ieee802154_submac
USEMODULE += netdev_ieee802154
USEMODULE += event_thread
USEMODULE += random
USEMODULE += netdev_default

# Power management
USEMODULE += pm_layered

# ISR stack default on Cortex-M is small; GNRC + radio IRQs can overflow it.
CFLAGS += -DISR_STACKSIZE=2048

# avoid running Kconfig by default
SHOULD_RUN_KCONFIG ?=

include $(RIOTBASE)/Makefile.include

# Optional: override defaults at build time
# CFLAGS += -DDUTY_ACTIVE_MS=100 -DDUTY_SLEEP_S=900 -DDUTY_PM_MODE=2
