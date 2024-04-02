#pragma once

#include "node-whisperer.h"

struct nw {
	struct ubus_context *ubus_ctx;
	struct uloop_timeout update_timeout;

	struct {
		uint8_t *buf;
		size_t len;  /* Content Length*/
		size_t size; /* Buffer Size */
	} output;

	struct {
		uint64_t update_count;
	} statistics;
};