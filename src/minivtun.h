/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/minivtun
 */

#ifndef __MINIVTUN_H
#define __MINIVTUN_H

#include "library.h"

enum {
	MINIVTUN_MSG_NOOP,
	MINIVTUN_MSG_IPDATA,
	MINIVTUN_MSG_DISCONNECT,
};

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
			char data[1024 * 2];
		} __attribute__((packed)) ipdata;
	};
} __attribute__((packed));

#define MINIVTUN_MSG_BASIC_HLEN (sizeof(((struct minivtun_msg *)0)->hdr))
#define MINIVTUN_MSG_IPDATA_OFFSET (offsetof(struct minivtun_msg, ipdata.data))

#define NM_PI_BUFFER_SIZE  (1024 * 3)

extern unsigned g_reconnect_timeo;
extern unsigned g_keepalive_timeo;
extern const char *g_pid_file;
extern char g_devname[];

extern AES_KEY g_encrypt_key;
extern AES_KEY g_decrypt_key;
extern const char *g_crypto_passwd;
extern char g_crypto_passwd_md5sum[];

static inline void local_to_netmsg(const void *in, void **out, size_t *dlen)
{
	if (g_crypto_passwd) {
		bytes_encrypt(&g_encrypt_key, in, *out, dlen);
	} else {
		*out = (void *)in;
	}
}
static inline void netmsg_to_local(const void *in, void **out, size_t *dlen)
{
	if (g_crypto_passwd) {
		bytes_decrypt(&g_decrypt_key, in, *out, dlen);
	} else {
		*out = (void *)in;
	}
}

int run_client(int tunfd, const char *peer_addr_pair);
int run_server(int tunfd, const char *loc_addr_pair);

#endif /* __MINIVTUN_H */

