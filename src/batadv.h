#pragma once

struct gluon_diagnostic_batadv_neighbor_stats {
	int originator_count;
	struct {
		int connected;
		int tq;
	} vpn;
};

int gluon_diagnostic_get_batadv_neighbor_stats(struct gluon_diagnostic_batadv_neighbor_stats *stats);
