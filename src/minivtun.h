/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/minivtun
 */

#ifndef __MINIVTUN_H
#define __MINIVTUN_H

#include "library.h"

extern struct minivtun_config config;

struct minivtun_config {
	unsigned reconnect_timeo;
	unsigned keepalive_timeo;
	const char *pid_file;
	char devname[40];
	unsigned tun_mtu;
	bool in_background;

	AES_KEY encrypt_key;
	AES_KEY decrypt_key;
	const char *crypto_passwd;
	char crypto_passwd_md5sum[16];
	struct in_addr local_tun_in;
	struct in6_addr local_tun_in6;
};

enum {
	MINIVTUN_MSG_KEEPALIVE,
	MINIVTUN_MSG_IPDATA,
	MINIVTUN_MSG_DISCONNECT,
};

#define NM_PI_BUFFER_SIZE  (1024 * 8)

struct minivtun_msg {
	struct {
		__u8 opcode;
		__u8 rsv[3];
		__u8 passwd_md5sum[16];
	}  __attribute__((packed)) hdr;

	union {
		struct {
			__be16 proto;   /* ETH_P_IP or ETH_P_IPV6 */
			__be16 ip_dlen; /* Total length of IP/IPv6 data */
			char data[NM_PI_BUFFER_SIZE];
		} __attribute__((packed)) ipdata;
		struct {
			struct in_addr loc_tun_in;
			struct in6_addr loc_tun_in6;
		} __attribute__((packed)) keepalive;
	};
} __attribute__((packed));

#define MINIVTUN_MSG_BASIC_HLEN (sizeof(((struct minivtun_msg *)0)->hdr))
#define MINIVTUN_MSG_IPDATA_OFFSET (offsetof(struct minivtun_msg, ipdata.data))

static inline void local_to_netmsg(const void *in, void **out, size_t *dlen)
{
	if (config.crypto_passwd) {
		bytes_encrypt(&config.encrypt_key, in, *out, dlen);
	} else {
		*out = (void *)in;
	}
}
static inline void netmsg_to_local(const void *in, void **out, size_t *dlen)
{
	if (config.crypto_passwd) {
		bytes_decrypt(&config.decrypt_key, in, *out, dlen);
	} else {
		*out = (void *)in;
	}
}

int run_client(int tunfd, const char *peer_addr_pair);
int run_server(int tunfd, const char *loc_addr_pair);
int vt_route_add(struct in_addr *network, unsigned prefix, struct in_addr *gateway);

#endif /* __MINIVTUN_H */

