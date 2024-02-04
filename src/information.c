#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include "util.h"
#include "information.h"

int gluon_beacon_diagnostic_information_hostname(uint8_t *buffer, size_t buffer_size) {
	int ret;

	ret = gethostname((char *)buffer, buffer_size);
	if (ret) {
		return ret;
	}

	return strlen((char *)buffer);
}

int gluon_beacon_diagnostic_information_node_id(uint8_t *buffer, size_t buffer_size) {
	char *node_id_ascii;
	size_t node_id_ascii_len;
	int ret;

	/* len_out = ETH_ALEN */
	if (buffer_size < 6) {
		return -1;
	}

	ret = gd_read_file("/lib/gluon/core/sysconfig/node_id", &node_id_ascii, &node_id_ascii_len);
	if (ret) {
		return ret;
	}

	if (node_id_ascii_len < 18) {
		free(node_id_ascii);
		return -1;
	}

	ret = gd_parse_mac_address_ascii(node_id_ascii, buffer);
	free(node_id_ascii);
	if (ret < 0) {
		return -1;
	}

	return 6;
}

struct gluon_beacon_information_source information_sources[] = {
	{
		.name = "hostname",
		.type = 0,
		.collect = gluon_beacon_diagnostic_information_hostname,
	},
	{
		.name = "node_id",
		.type = 1,
		.collect = gluon_beacon_diagnostic_information_node_id,
	},
	{
		.name = NULL,
		.type = 0,
		.collect = NULL,
	},
};
