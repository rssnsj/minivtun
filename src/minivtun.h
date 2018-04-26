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
	unsigned reconnect_timeo;
	unsigned keepalive_timeo;
	unsigned health_assess_timeo;
	char ifname[40];
	unsigned tun_mtu;
	const char *crypto_passwd;
	const char *pid_file;
	const char *health_file;
	bool in_background;
	bool wait_dns;

	char crypto_key[CRYPTO_MAX_KEY_SIZE];
	const void *crypto_type;
	struct in_addr tun_in_local;
	struct in6_addr tun_in6_local;

	/* Static routes attached to this link when brought up */
	struct vt_route *vt_routes;
	int vt_metric;
	char vt_table[32];
};

/* Status variables during VPN running */
struct state_variables {
	int tunfd;
	int sockfd;

	/* *** Client specific *** */
	struct sockaddr_inx peer_addr;
	__u16 xmit_seq;
	struct timeval last_recv;
	struct timeval last_echo_sent;
	struct timeval last_health_assess;
	bool has_pending_echo;
	__be32 pending_echo_id;
	/* Health assess data */
	unsigned total_echo_sent;
	unsigned total_echo_rcvd;
	unsigned long total_rtt_ms;

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
			struct in_addr loc_tun_in;
			struct in6_addr loc_tun_in6;
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

