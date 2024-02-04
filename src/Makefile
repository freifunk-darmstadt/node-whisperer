CC ?= gcc
CFLAGS_common ?= -Wall -Wextra -Werror -std=c99 -g

all:
	$(CC) $(CFLAGS_common) -D_GNU_SOURCE -o gluon-diagnostic main.c util.c information.c log.c