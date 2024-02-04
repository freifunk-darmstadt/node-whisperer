CC ?= gcc
CFLAGS_common ?= -Wall -Wextra -Werror -std=c99 -g
LDFLAGS_common ?= 

LDFLAGS:=-lubox -lubus -lblobmsg_json
CFLAGS:=$(shell pkg-config --cflags libnl-tiny)

all:
	$(CC) $(CFLAGS) $(LDFLAGS) -D_GNU_SOURCE -o gluon-diagnostic main.c util.c information.c log.c ubus.c interface.c