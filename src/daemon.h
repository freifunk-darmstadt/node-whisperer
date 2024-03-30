#pragma once

#include "node-whisperer.h"

struct nw {
	struct ubus_context *ubus_ctx;
	struct uloop_timeout update_timeout;
};