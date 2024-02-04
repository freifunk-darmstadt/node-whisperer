#pragma once

#include "gluon-diagnostic.h"

struct gluon_diagnostic_interface {
	struct list_head list;

	struct {
		int id;
		char *name;
		struct ubus_subscriber subscriber;
	} ubus;
};

int gluon_diagnostic_interface_remove(struct ubus_context *ctx,
				      struct gluon_diagnostic_interface *iface);

int gluon_diagnostic_interface_add(struct ubus_context *ctx, int id, const char *name);