/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/minivtun
 */

#ifndef __MINIVTUN_H
#define __MINIVTUN_H

#include "library.h"

extern struct minivtun_config config;
extern struct state_variables state;

/**
* Pseudo route table for binding client side subnets
* to corresponding connected virtual addresses.
*/
struct vt_route {
	struct vt_route *next;
	short af;
	union {
		struct in_addr in;
		struct in6_addr in6;
	} network, gateway;
	int prefix;
};

struct minivtun_config {
	char ifname[40];
	unsigned tun_mtu;
	unsigned tun_qlen;
	const char *crypto_passwd;
	const char *pid_file;
	bool in_background;
	bool tap_mode;

	char crypto_key[CRYPTO_MAX_KEY_SIZE];
	const void *crypto_type;

	/* IPv4 address settings */
	struct in_addr tun_in_local;
	struct in_addr tun_in_peer;
	int tun_in_prefix;

	/* IPv6 address settings */
	struct in6_addr tun_in6_local;
	int tun_in6_prefix;

	/* Dynamic routes for client, or virtual routes for server */
	struct vt_route *vt_routes;

	/* Client only configuration */
	bool wait_dns;
	unsigned exit_after;
	bool dynamic_link;
	unsigned reconnect_timeo;
	unsigned max_droprate;
	unsigned max_rtt;
	unsigned keepalive_interval;
	unsigned health_assess_interval;
	unsigned nr_stats_buckets;
	const char *health_file;
	unsigned vt_metric;
	char vt_table[32];
};

/* Statistics data for health assess */
struct stats_data {
	unsigned total_echo_sent;
	unsigned total_echo_rcvd;
	unsigned long total_rtt_ms;
};

static inline void zero_stats_data(struct stats_data *st)
{
	st->total_echo_sent = 0;
	st->total_echo_rcvd = 0;
	st->total_rtt_ms = 0;
}

/* Status variables during VPN running */
struct state_variables {
	int tunfd;
	int sockfd;

	/* *** Client specific *** */
	struct sockaddr_inx peer_addr;
	__u16 xmit_seq;
	struct timeval last_recv;
	struct timeval last_echo_sent;
	struct timeval last_echo_recv;
	struct timeval last_health_assess;
	bool is_link_ok;
	bool health_based_link_up;

	/* Health assess data */
	bool has_pending_echo;
	__be32 pending_echo_id;
	struct stats_data *stats_buckets;
	unsigned current_bucket;

	/* *** Server specific *** */
	struct sockaddr_inx local_addr;
	struct timeval last_walk;
};

enum {
	MINIVTUN_MSG_ECHO_REQ,
	MINIVTUN_MSG_IPDATA,
	MINIVTUN_MSG_DISCONNECT,
	MINIVTUN_MSG_ECHO_ACK,
};

#define NM_PI_BUFFER_SIZE  (1024 * 8)

struct minivtun_msg {
	struct {
		__u8 opcode;
		__u8 rsv;
		__be16 seq;
		__u8 auth_key[16];
	} __attribute__((packed)) hdr; /* 20 */

	union {
		struct {
			__be16 proto;   /* ETH_P_IP or ETH_P_IPV6 */
			__be16 ip_dlen; /* Total length of IP/IPv6 data */
			char data[NM_PI_BUFFER_SIZE];
		} __attribute__((packed)) ipdata;    /* 4+ */
		struct {
			union {
				struct {
					struct in_addr loc_tun_in;
					struct in6_addr loc_tun_in6;
				};
				struct mac_addr loc_tun_mac;
			};
			__be32 id;
		} __attribute__((packed)) echo; /* 24 */
	};
} __attribute__((packed));

#define MINIVTUN_MSG_BASIC_HLEN  (sizeof(((struct minivtun_msg *)0)->hdr))
#define MINIVTUN_MSG_IPDATA_OFFSET  (offsetof(struct minivtun_msg, ipdata.data))

#define enabled_encryption()  (config.crypto_passwd[0])

static inline void local_to_netmsg(void *in, void **out, size_t *dlen)
{
	if (enabled_encryption()) {
		datagram_encrypt(config.crypto_key, config.crypto_type, in, *out, dlen);
	} else {
		*out = in;
	}
}
static inline void netmsg_to_local(void *in, void **out, size_t *dlen)
{
	if (enabled_encryption()) {
		datagram_decrypt(config.crypto_key, config.crypto_type, in, *out, dlen);
	} else {
		*out = in;
	}
}

int run_client(const char *peer_addr_pair);
int run_server(const char *loc_addr_pair);

#endif /* __MINIVTUN_H */

