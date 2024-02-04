#pragma once

#include <stdint.h>
#include <stddef.h>

struct gluon_beacon_information_source {
	char *name;
	uint8_t type;
	uint32_t fixed_size;
	int (*collect)(uint8_t *buffer, size_t buffer_size);
	int (*parse)(uint8_t *buffer, size_t buffer_size);
};
