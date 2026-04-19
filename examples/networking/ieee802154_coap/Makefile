# CoAP over IEEE802.15.4 (GNRC + gcoap) example

APPLICATION = ieee802154_coap

RIOTBASE ?= $(CURDIR)/../../..

# IEEE802.15.4 netdev auto init
USEMODULE += netdev_default

# Use IEEE 802.15.4 emulation on native
ifneq (,$(filter native%,$(BOARD)))
  USEMODULE += socket_zep
  USE_ZEP = 1
endif

# GNRC IPv6/6LoWPAN stack
USEMODULE += auto_init_gnrc_netif
USEMODULE += gnrc_ipv6_default
# Ensure IEEE802.15.4 netdev helpers are available for IPv6/6LoWPAN init
#USEMODULE += netdev_ieee802154

# CoAP
USEMODULE += gcoap

# Shell + helpers
USEMODULE += shell
USEMODULE += shell_cmds_default
USEMODULE += stdin
USEMODULE += uri_parser
USEMODULE += netutils
USEMODULE += fmt
USEMODULE += od
USEMODULE += ps
USEMODULE += ztimer_msec
USEMODULE += ztimer_usec
USEMODULE += sema

DEVELHELP ?= 1

include $(RIOTBASE)/Makefile.include

# Increase resend buffers for blockwise follow-up requests
#ifndef CONFIG_KCONFIG_MODULE_GCOAP
#GCOAP_RESEND_BUFS_MAX ?= 2
#CFLAGS += -DCONFIG_GCOAP_RESEND_BUFS_MAX=$(GCOAP_RESEND_BUFS_MAX)
#endif
