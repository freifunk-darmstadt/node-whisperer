#pragma once

#include <stdint.h>
#include <stddef.h>

struct nw_information_source {
	char *name;
	uint8_t type;
	uint32_t fixed_size;
	uint8_t enabled;
	int (*collect)(uint8_t *buffer, size_t buffer_size);
	int (*parse)(const uint8_t *ie_buf, size_t ie_len);
};
