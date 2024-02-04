#include "gluon-diagnostic.h"

static const struct ubus_method gluon_diagnostic_methods[] = {
	/* Empty */
};

static struct ubus_object_type gluon_diagnostic_obj_type =
	UBUS_OBJECT_TYPE("gluon_diagnostic", gluon_diagnostic_methods);

struct ubus_object gluon_diagnostic_obj = {
	.name = "gluon_diagnostic",
	.type = &gluon_diagnostic_obj_type,
	.methods = gluon_diagnostic_methods,
	.n_methods = ARRAY_SIZE(gluon_diagnostic_methods),
};

static void gluon_diagnostic_ubus_event_handler(struct ubus_context *ctx,
						struct ubus_event_handler *ev,
						const char *type,
						struct blob_attr *msg)
{
	static const struct blobmsg_policy policy[2] = {
		{ .name = "id", .type = BLOBMSG_TYPE_INT32 },
		{ .name = "path", .type = BLOBMSG_TYPE_STRING },
	};
	struct blob_attr *tb[2];

	blobmsg_parse(policy, 2, tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[1])
		return;

	gluon_diagnostic_interface_add(ctx, blobmsg_get_u32(tb[0]), blobmsg_data(tb[1]));
}

static void gluon_diagnostic_register_events(struct ubus_context *ctx)
{
	static struct ubus_event_handler handler = {
		.cb = gluon_diagnostic_ubus_event_handler
	};

	ubus_register_event_handler(ctx, &handler, "ubus.object.add");
}

static void gluon_diagnostic_ubus_list_cb(struct ubus_context *ctx,
					  struct ubus_object_data *obj,
					  void *priv)
{
	gluon_diagnostic_interface_add(ctx, obj->id, obj->path);
}

void gluon_diagnostic_ubus_init(struct ubus_context *ctx)
{
	ubus_add_object(ctx, &gluon_diagnostic_obj);
	gluon_diagnostic_register_events(ctx);
	ubus_lookup(ctx, "hostapd.*", gluon_diagnostic_ubus_list_cb, NULL);
}