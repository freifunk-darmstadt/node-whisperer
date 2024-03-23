CC ?= gcc
CFLAGS_common ?= -Wall -Wextra -Werror -std=c99 -g
LDFLAGS_common ?= 

LDFLAGS:=-lubox -lubus -lblobmsg_json -lgluonutil -luci $(shell pkg-config --libs libnl-tiny) $(shell $(PKG_CONFIG) --libs libbatadv) $(shell pkg-config --libs json-c)
CFLAGS:=$(shell pkg-config --cflags libnl-tiny) $(shell $(PKG_CONFIG) --cflags libbatadv) $(shell pkg-config --cflags json-c)

LDFLAGS_MONITOR:=$(shell pkg-config --libs libnl-genl-3.0) -DBUILD_MONITOR
CFLAGS_MONITOR:=$(shell pkg-config --cflags libnl-genl-3.0)

all:
	$(CC) $(CFLAGS) -D_GNU_SOURCE -o gluon-diagnostic main.c util.c information.c log.c ubus.c interface.c batadv.c $(LDFLAGS)

monitor:
	$(CC) $(CFLAGS_MONITOR) -o monitor monitor.c log.c util.c ieee80211.c information.c $(LDFLAGS_MONITOR) 
