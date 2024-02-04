#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <stddef.h>
#include "util.h"
#include "information.h"

#define HOSTNAME_PATH "/home/dbauer/test"
#define BEACON_BUFFER_SIZE 512

struct gluon_beacon_information {
	struct {
		uint8_t *buf;
		size_t len;  /* Content Length*/
		size_t size; /* Buffer Size */
	} output;
};

struct gluon_beacon_information gbi = {};
extern struct gluon_beacon_information_source information_sources[];

int create_vendor_element_buf() {
	uint8_t *element_length;

	/* Free buffer if it exists*/
	if (gbi.output.buf) {
		free(gbi.output.buf);
	}

	/* Allocate Buffer and Init sizes */
	gbi.output.buf = calloc(BEACON_BUFFER_SIZE, 1);
	if (!gbi.output.buf) {
		return -1;
	}
	gbi.output.size = BEACON_BUFFER_SIZE;
	gbi.output.len = 0;

	/* Tag-Type(1) + Teg-Length(1) + OUI(3) + type(1) + {data} */
	gbi.output.len = 1 + 1 + 3 + 1;

	/* Header */
	gbi.output.buf[0] = 0xDD;
	gbi.output.buf[1] = 0x00; /* Set Later! */
	/* OUI */
	gbi.output.buf[2] = 0x00;
	gbi.output.buf[3] = 0x20;
	gbi.output.buf[4] = 0x91;
	/* OUI-Type */
	gbi.output.buf[5] = 0x04;

	/* Length now matches content. Make sure to update on each new information! */
	
	/* Loop through all information-sources */
	for (int i = 0; information_sources[i].name; i++) {
		/* Check if we have space for T + L + {data} */
		if (gbi.output.len + 3 > gbi.output.size) {
			break;
		}

		/* Set T and L placeholder */
		gbi.output.buf[gbi.output.len] = information_sources[i].type;
		gbi.output.buf[gbi.output.len + 1] = 0x00;

		/* Save for later */
		element_length = &gbi.output.buf[gbi.output.len + 1];

		/* Collect Information */
		int ret = information_sources[i].collect(&gbi.output.buf[gbi.output.len + 2], gbi.output.size - gbi.output.len - 2);
		if (ret == 0) {
			/* No Information available */
			continue;
		} else if (ret < 0) {
			/* Error */
			return ret;
		}

		/* Update Length of Field*/
		*element_length = ret;

		/* Update total Length */
		gbi.output.len += ret + 2;
	}

	/* Set Length */
	gbi.output.buf[1] = gbi.output.len - 2;

	return 0;
}

int buffer_to_hexstring(uint8_t *buf, size_t len, uint8_t *hexstring) {
	for (size_t i = 0; i < len; i++) {
		sprintf((char *)&hexstring[i * 2], "%02x", buf[i]);
	}
	return 0;
}

int main(int argc, char *argv[]) {
	create_vendor_element_buf();
	
	/* Allocate output buffer */
	size_t buf_len = gbi.output.len * 2 + 1;
	uint8_t *buf_hex = malloc(buf_len);
	
	buffer_to_hexstring(gbi.output.buf, gbi.output.len, buf_hex);

	if (argc > 1) {
		/* Set in ubus for each radio */
		for (int i = 1; i < argc; i++) {
			/* Ugly */
			char ubus_cmd_buf[2048] = {};
			if (snprintf(ubus_cmd_buf, 2048, "ubus call hostapd.%s set_vendor_elements '{\"vendor_elements\": \"%s\"}'", argv[i], buf_hex) < 0) {
				printf("Error: Could not create ubus command!\n");
				continue;
			}
			printf("Set %s to %s / %s\n", argv[i], buf_hex, ubus_cmd_buf);
			system(ubus_cmd_buf);
		}
	}

	return 0;
}
