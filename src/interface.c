#include "gluon-diagnostic.h"

static LIST_HEAD(gluon_diagnostic_interfaces);
static struct blob_buf b;

static int gluon_diagnostic_interface_handle_event(struct ubus_context *ctx,
						   struct ubus_object *obj,
						   struct ubus_request_data *req,
						   const char *method,
						   struct blob_attr *msg)
{
	/* Nothing to handle, we are here for the removal */
	return 0;
}

static void gluon_diagnostic_interface_handle_remove(struct ubus_context *ctx,
						     struct ubus_subscriber *s,
						     uint32_t id)
{
	struct gluon_diagnostic_interface *iface;
	iface = container_of(s, struct gluon_diagnostic_interface, ubus.subscriber);

	gluon_diagnostic_interface_remove(ctx, iface);
}

int gluon_diagnostic_interface_update(struct ubus_context *ctx, char *vendor_elements)
{
	struct gluon_diagnostic_interface *iface;

	blob_buf_init(&b, 0);
	blobmsg_add_string(&b, "vendor_elements", vendor_elements);

	list_for_each_entry(iface, &gluon_diagnostic_interfaces, list) {
		log_debug("Sending vendor elements to id=%d name=%s", iface->ubus.id, iface->ubus.name);
		ubus_invoke(ctx, iface->ubus.id, "set_vendor_elements", b.head, NULL, NULL, 1000);
	}
}

int gluon_diagnostic_interface_remove(struct ubus_context *ctx,
				      struct gluon_diagnostic_interface *iface)
{
	log_info("Removing interface %s", iface->ubus.name);

	ubus_unregister_subscriber(ctx, &iface->ubus.subscriber);
	list_del(&iface->list);
	free(iface->ubus.name);
	free(iface);
	return 0;
}

int gluon_diagnostic_interface_add(struct ubus_context *ctx, int id, const char *name)
{
	struct gluon_diagnostic_interface *iface;

	iface = calloc(sizeof(*iface), 1);
	if (!iface) {
		log_error("Failed to allocate memory for interface %s", name);
		return -ENOMEM;
	}

	iface->ubus.id = id;
	iface->ubus.name = strdup(name);
	if (!iface->ubus.name) {
		log_error("Failed to allocate memory for interface %s", name);
		free(iface);
		return -ENOMEM;
	}

	/* Add to node-list */
	INIT_LIST_HEAD(&iface->list);
	list_add(&iface->list, &gluon_diagnostic_interfaces);

	/* Subscribe to node removal */
	iface->ubus.subscriber.cb = gluon_diagnostic_interface_handle_event;
	iface->ubus.subscriber.remove_cb = gluon_diagnostic_interface_handle_remove;
	ubus_register_subscriber(ctx, &iface->ubus.subscriber);

	log_info("Registered interface %s", iface->ubus.name);

	return 0;
}
