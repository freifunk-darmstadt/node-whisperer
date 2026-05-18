/* SPDX-FileCopyrightText: 2016-2019, Matthias Schiffer <mschiffer@universe-factory.net> */
/* SPDX-FileCopyrightText: 2023, David Bauer <mail@david-bauer.net> */
/* SPDX-License-Identifier: BSD-2-Clause */

#include <batadv-genl.h>

#include <netlink/netlink.h>
#include <netlink/genl/genl.h>

#include <errno.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <net/if.h>

#include "batadv.h"
#include "log.h"

struct neigh_netlink_opts {
	int originator_count;
	struct batadv_nlquery_opts query_opts;
	struct nw_batadv_neighbor_stats *stats;
};

struct clients_netlink_opts {
	size_t clients;
	struct batadv_nlquery_opts query_opts;
};

static const enum batadv_nl_attrs parse_orig_list_mandatory[] = {
	BATADV_ATTR_ORIG_ADDRESS,
	BATADV_ATTR_NEIGH_ADDRESS,
	BATADV_ATTR_TQ,
	BATADV_ATTR_HARD_IFINDEX,
	BATADV_ATTR_LAST_SEEN_MSECS,
};

static const enum batadv_nl_attrs parse_orig_v_list_mandatory[] = {
	BATADV_ATTR_ORIG_ADDRESS,
	BATADV_ATTR_NEIGH_ADDRESS,
	BATADV_ATTR_THROUGHPUT,
	BATADV_ATTR_HARD_IFINDEX,
	BATADV_ATTR_LAST_SEEN_MSECS,
};

static const enum batadv_nl_attrs clients_mandatory[] = {
	BATADV_ATTR_TT_FLAGS,
	BATADV_ATTR_LAST_SEEN_MSECS,
};

static int parse_orig_list_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct batadv_nlquery_opts *query_opts = arg;
	struct genlmsghdr *ghdr;
	struct neigh_netlink_opts *opts;
	char ifname[IF_NAMESIZE];
	uint32_t hardif;
	uint8_t tq;
	char *orig, *dest;

	opts = batadv_container_of(query_opts, struct neigh_netlink_opts,
				   query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_ORIGINATORS)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_genl_policy))
		return NL_OK;

	if (batadv_genl_missing_attrs(attrs, parse_orig_list_mandatory,
				      BATADV_ARRAY_SIZE(parse_orig_list_mandatory)))
		return NL_OK;
	
	hardif = nla_get_u32(attrs[BATADV_ATTR_HARD_IFINDEX]);
	orig = nla_data(attrs[BATADV_ATTR_ORIG_ADDRESS]);
	dest = nla_data(attrs[BATADV_ATTR_NEIGH_ADDRESS]);

	if (if_indextoname(hardif, ifname) == NULL)
		return NL_OK;

	opts->stats->originator_count++;
	if (memcmp(orig, dest, 6) != 0)
		return NL_OK;

	opts->stats->neighbor_count++;
	if (!strncmp(ifname, "mesh-vpn", strlen(ifname))) {
		opts->stats->vpn.tq = nla_get_u8(attrs[BATADV_ATTR_TQ]);
		opts->stats->vpn.connected = 1;
	}

	return NL_OK;
}

static uint8_t gluonutil_get_pseudo_tq(uint32_t throughput)
{
	if (throughput >= 54000)
		return 255;

	if (throughput < 417)
		return 0;

	return (uint8_t)((1.42459274279287898080 * log2(throughput) - 12.39555493934044793479) * 25.5);
}

// Batman V - count originators only; neighbor/VPN detection uses BATADV_CMD_GET_NEIGHBORS
static int parse_orig_v_list_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct batadv_nlquery_opts *query_opts = arg;
	struct genlmsghdr *ghdr;
	struct neigh_netlink_opts *opts;

	opts = batadv_container_of(query_opts, struct neigh_netlink_opts,
							   query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_ORIGINATORS)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
				  genlmsg_len(ghdr), batadv_genl_policy))
		return NL_OK;

	if (batadv_genl_missing_attrs(attrs, parse_orig_v_list_mandatory,
								  BATADV_ARRAY_SIZE(parse_orig_v_list_mandatory)))
		return NL_OK;

	opts->stats->originator_count++;
	return NL_OK;
}

// Batman V
static const enum batadv_nl_attrs parse_neigh_list_mandatory[] = {
	BATADV_ATTR_NEIGH_ADDRESS,
	BATADV_ATTR_THROUGHPUT,
	BATADV_ATTR_HARD_IFINDEX,
	BATADV_ATTR_LAST_SEEN_MSECS,
};

// Batman V
static int parse_neigh_list_netlink_cb(struct nl_msg *msg, void *arg) {
	struct nlattr *attrs[BATADV_ATTR_MAX + 1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct batadv_nlquery_opts *query_opts = arg;
	struct genlmsghdr *ghdr;
	struct neigh_netlink_opts *opts;
	char ifname[IF_NAMESIZE];
	uint32_t hardif;
	uint32_t throughput;

	opts = batadv_container_of(query_opts, struct neigh_netlink_opts,
				   query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_NEIGHBORS)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
		      genlmsg_len(ghdr), batadv_genl_policy))
		return NL_OK;

	if (batadv_genl_missing_attrs(attrs, parse_neigh_list_mandatory,
								  BATADV_ARRAY_SIZE(parse_neigh_list_mandatory)))
		return NL_OK;

	throughput = nla_get_u32(attrs[BATADV_ATTR_THROUGHPUT]);
	hardif = nla_get_u32(attrs[BATADV_ATTR_HARD_IFINDEX]);

	if (if_indextoname(hardif, ifname) == NULL)
		return NL_OK;

	opts->stats->neighbor_count++;
	if (!strncmp(ifname, "mesh-vpn", sizeof("mesh-vpn"))) {
		opts->stats->vpn.tq = gluonutil_get_pseudo_tq(throughput);
		opts->stats->vpn.connected = 1;
	}
	return NL_OK;
}

struct get_algoname_netlink_opts {
	char *algoname;
	size_t algoname_len;
	uint8_t found : 1;
	struct batadv_nlquery_opts query_opts;
};

static int get_algoname_netlink_cb(struct nl_msg *msg, void *arg) {
	struct nlattr *attrs[BATADV_ATTR_MAX + 1];
	struct get_algoname_netlink_opts *opts;
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct batadv_nlquery_opts *query_opts = arg;
	static const enum batadv_nl_attrs mandatory[] = {
		BATADV_ATTR_ALGO_NAME,
	};
	struct genlmsghdr *ghdr;
	const char *algoname;

	opts = batadv_container_of(query_opts, struct get_algoname_netlink_opts,
							   query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_MESH)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
				  genlmsg_len(ghdr), batadv_genl_policy)) {
		return NL_OK;
	}

	if (batadv_genl_missing_attrs(attrs, mandatory,
								  BATADV_ARRAY_SIZE(mandatory)))
		return NL_OK;

	algoname = nla_data(attrs[BATADV_ATTR_ALGO_NAME]);

	/* save result */
	strncpy(opts->algoname, algoname, opts->algoname_len);
	if (opts->algoname_len > 0)
		opts->algoname[opts->algoname_len - 1] = '\0';

	opts->found = true;
	opts->query_opts.err = 0;

	return NL_OK;
}

int get_algoname_netlink(char *algoname, size_t algoname_len) {
	struct get_algoname_netlink_opts opts = {
		.algoname = algoname,
		.algoname_len = algoname_len,
		.found = false,
		.query_opts = {
			.err = 0,
		},
	};
	int ret;

	ret = batadv_genl_query("bat0", BATADV_CMD_GET_MESH,
							get_algoname_netlink_cb, 0,
							&opts.query_opts);
	if (ret < 0) {
		log_error("Failed to query batman-adv algorithm name: %d", ret);
		return ret;
	}

	if (!opts.found)
		return -EOPNOTSUPP;

	return 0;
}

int nw_get_batadv_neighbor_stats(struct nw_batadv_neighbor_stats *stats) {
	struct neigh_netlink_opts opts = {
		.query_opts = {
			.err = 0,
		},
		.stats = stats,
	};
	int ret;
	char algoname[256];

	ret = get_algoname_netlink(algoname, sizeof(algoname));
	if (ret < 0) {
		return -1;
	}
	log_debug("Using algoname %s", algoname);

	if (strcmp(algoname, "BATMAN_IV") == 0) {
		ret = batadv_genl_query("bat0", BATADV_CMD_GET_ORIGINATORS,
								parse_orig_list_netlink_cb, NLM_F_DUMP,
								&opts.query_opts);
	}
	else if (strcmp(algoname, "BATMAN_V") == 0) {
		ret = batadv_genl_query("bat0", BATADV_CMD_GET_ORIGINATORS,
								parse_orig_v_list_netlink_cb, NLM_F_DUMP,
								&opts.query_opts);
	} else {
		log_error("Unknown batman-adv algorithm: %s", algoname);
		return -1;
	}

	if (ret < 0) {
		log_error("Failed to query batman-adv originators: %d", ret);
		return -1;
	}

	if (strcmp(algoname, "BATMAN_V") == 0) {
		opts.query_opts.err = 0;
		ret = batadv_genl_query("bat0", BATADV_CMD_GET_NEIGHBORS,
								parse_neigh_list_netlink_cb, NLM_F_DUMP,
								&opts.query_opts);
		if (ret < 0) {
			log_error("Failed to query batman-adv neighbors: %d", ret);
			return -1;
		}
	}

	return 0;
}


static int parse_clients_list_netlink_cb(struct nl_msg *msg, void *arg)
{
	struct nlattr *attrs[BATADV_ATTR_MAX+1];
	struct nlmsghdr *nlh = nlmsg_hdr(msg);
	struct batadv_nlquery_opts *query_opts = arg;
	struct genlmsghdr *ghdr;
	struct clients_netlink_opts *opts;
	uint32_t flags, lastseen;

	opts = batadv_container_of(query_opts, struct clients_netlink_opts,
			query_opts);

	if (!genlmsg_valid_hdr(nlh, 0))
		return NL_OK;

	ghdr = nlmsg_data(nlh);

	if (ghdr->cmd != BATADV_CMD_GET_TRANSTABLE_LOCAL)
		return NL_OK;

	if (nla_parse(attrs, BATADV_ATTR_MAX, genlmsg_attrdata(ghdr, 0),
				genlmsg_len(ghdr), batadv_genl_policy))
		return NL_OK;

	if (batadv_genl_missing_attrs(attrs, clients_mandatory,
				BATADV_ARRAY_SIZE(clients_mandatory)))
		return NL_OK;

	flags = nla_get_u32(attrs[BATADV_ATTR_TT_FLAGS]);

	if (flags & (BATADV_TT_CLIENT_NOPURGE))
		return NL_OK;

	lastseen = nla_get_u32(attrs[BATADV_ATTR_LAST_SEEN_MSECS]);
	if (lastseen > (60 * 1000))
		return NL_OK;

	opts->clients++;

	return NL_OK;
}

int nw_get_batadv_clients() {
	struct clients_netlink_opts opts = {
		.clients = 0,
		.query_opts = {
			.err = 0,
		},
	};
	int ret;

	ret = batadv_genl_query("bat0", BATADV_CMD_GET_TRANSTABLE_LOCAL,
							parse_clients_list_netlink_cb, NLM_F_DUMP,
							&opts.query_opts);
	if (ret < 0) {
		return -1;
	}

	return opts.clients;
}
