#pragma once

#include "gluon-diagnostic.h"

struct gluon_diagnostic {
	struct ubus_context *ubus_ctx;
	struct uloop_timeout update_timeout;
};