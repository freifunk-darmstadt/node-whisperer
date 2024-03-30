#pragma once

#include <stdint.h>

struct nw_batadv_neighbor_stats {
	uint16_t originator_count;
	uint16_t neighbor_count;
	struct {
		int connected;
		int tq;
	} vpn;
};

int nw_get_batadv_neighbor_stats(struct nw_batadv_neighbor_stats *stats);
int nw_get_batadv_clients();
