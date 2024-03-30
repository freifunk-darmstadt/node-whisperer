#include "node-whisperer.h"

static const struct ubus_method nw_methods[] = {
	/* Empty */
};

static struct ubus_object_type nw_obj_type =
	UBUS_OBJECT_TYPE("node_whisperer", nw_methods);

struct ubus_object nw_obj = {
	.name = "node_whisperer",
	.type = &nw_obj_type,
	.methods = nw_methods,
	.n_methods = ARRAY_SIZE(nw_methods),
};

static void nw_ubus_event_handler(struct ubus_context *ctx,
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

	nw_interface_add(ctx, blobmsg_get_u32(tb[0]), blobmsg_data(tb[1]));
}

static void nw_register_events(struct ubus_context *ctx)
{
	static struct ubus_event_handler handler = {
		.cb = nw_ubus_event_handler
	};

	ubus_register_event_handler(ctx, &handler, "ubus.object.add");
}

static void nw_ubus_list_cb(struct ubus_context *ctx,
					  struct ubus_object_data *obj,
					  void *priv)
{
	nw_interface_add(ctx, obj->id, obj->path);
}

void nw_ubus_init(struct ubus_context *ctx)
{
	ubus_add_object(ctx, &nw_obj);
	nw_register_events(ctx);
	ubus_lookup(ctx, "hostapd.*", nw_ubus_list_cb, NULL);
}