/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/minivtun
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <assert.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <openssl/evp.h>
#include <openssl/md5.h>

#include "library.h"

struct name_cipher_pair cipher_pairs[] = {
	{ "aes-128", EVP_aes_128_cbc, },
	{ "aes-256", EVP_aes_256_cbc, },
	{ "des", EVP_des_cbc, },
	{ "desx", EVP_desx_cbc, },
	{ "rc4", EVP_rc4, },
	{ NULL, NULL, },
};

const void *get_crypto_type(const char *name)
{
	const EVP_CIPHER *cipher = NULL;
	int i;

	for (i = 0; cipher_pairs[i].name; i++) {
		if (strcasecmp(cipher_pairs[i].name, name) == 0) {
			cipher = ((const EVP_CIPHER *(*)(void))cipher_pairs[i].cipher)();
			break;
		}
	}

	if (cipher) {
		assert(EVP_CIPHER_key_length(cipher) <= CRYPTO_MAX_KEY_SIZE);
		assert(EVP_CIPHER_iv_length(cipher) <= CRYPTO_MAX_BLOCK_SIZE);
		return cipher;
	} else {
		return NULL;
	}
}

static const char crypto_ivec_initdata[CRYPTO_MAX_BLOCK_SIZE] = {
	0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
	0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
	0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
	0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90,
};

#define CRYPTO_DATA_PADDING(data, dlen, bs) \
	do { \
		size_t last_len = *(dlen) % (bs); \
		if (last_len) { \
			size_t padding_len = bs - last_len; \
			memset((char *)data + *(dlen), 0x0, padding_len); \
			*(dlen) += padding_len; \
		} \
	} while(0)

void datagram_encrypt(const void *key, const void *cptype, void *in,
		void *out, size_t *dlen)
{
	size_t iv_len = EVP_CIPHER_iv_length((const EVP_CIPHER *)cptype);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	unsigned char iv[CRYPTO_MAX_KEY_SIZE];
	int outl = 0, outl2 = 0;

	if (iv_len == 0)
		iv_len = 16;

	memcpy(iv, crypto_ivec_initdata, iv_len);
	CRYPTO_DATA_PADDING(in, dlen, iv_len);
	EVP_CIPHER_CTX_init(ctx);
	assert(EVP_EncryptInit_ex(ctx, cptype, NULL, key, iv));
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	assert(EVP_EncryptUpdate(ctx, out, &outl, in, *dlen));
	assert(EVP_EncryptFinal_ex(ctx, (unsigned char *)out + outl, &outl2));
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);

	*dlen = (size_t)(outl + outl2);
}

void datagram_decrypt(const void *key, const void *cptype, void *in,
		void *out, size_t *dlen)
{
	size_t iv_len = EVP_CIPHER_iv_length((const EVP_CIPHER *)cptype);
	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
	unsigned char iv[CRYPTO_MAX_KEY_SIZE];
	int outl = 0, outl2 = 0;

	if (iv_len == 0)
		iv_len = 16;

	memcpy(iv, crypto_ivec_initdata, iv_len);
	CRYPTO_DATA_PADDING(in, dlen, iv_len);
	EVP_CIPHER_CTX_init(ctx);
	assert(EVP_DecryptInit_ex(ctx, cptype, NULL, key, iv));
	EVP_CIPHER_CTX_set_padding(ctx, 0);
	assert(EVP_DecryptUpdate(ctx, out, &outl, in, *dlen));
	assert(EVP_DecryptFinal_ex(ctx, (unsigned char *)out + outl, &outl2));
	EVP_CIPHER_CTX_cleanup(ctx);
	EVP_CIPHER_CTX_free(ctx);

	*dlen = (size_t)(outl + outl2);
}

void fill_with_string_md5sum(const char *in, void *out, size_t outlen)
{
	char *outp = out, *oute = outp + outlen;
	MD5_CTX ctx;

	MD5_Init(&ctx);
	MD5_Update(&ctx, in, strlen(in));
	MD5_Final(out, &ctx);

	/* Fill in remaining buffer with repeated data. */
	for (outp += 16; outp < oute; outp += 16) {
		size_t bs = (oute - outp >= 16) ? 16 : (oute - outp);
		memcpy(outp, out, bs);
	}
}

/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */

int get_sockaddr_inx_pair(const char *pair, struct sockaddr_inx *sa)
{
	struct addrinfo hints, *result;
	char host[51] = "", s_port[10] = "";
	int port = 0, rc;

	/* Only getting an INADDR_ANY address. */
	if (pair == NULL) {
		struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
		sa4->sin_family = AF_INET;
		sa4->sin_addr.s_addr = 0;
		sa4->sin_port = 0;
		return 0;
	}

	if (sscanf(pair, "[%50[^]]]:%d", host, &port) == 2) {
	} else if (sscanf(pair, "%50[^:]:%d", host, &port) == 2) {
	} else {
		/**
		 * Address with a single port number, usually for
		 * local IPv4 listen address.
		 * e.g., "10000" is considered as "0.0.0.0:10000"
		 */
		const char *sp;
		for (sp = pair; *sp; sp++) {
			if (!(*sp >= '0' && *sp <= '9'))
				return -EINVAL;
		}
		sscanf(pair, "%d", &port);
		strcpy(host, "0.0.0.0");
	}
	sprintf(s_port, "%d", port);
	if (port <= 0 || port > 65535)
		return -EINVAL;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;  /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;  /* For wildcard IP address */
	hints.ai_protocol = 0;        /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	if ((rc = getaddrinfo(host, s_port, &hints, &result)))
		return -EAGAIN;

	/* Get the first resolution. */
	memcpy(sa, result->ai_addr, result->ai_addrlen);

	freeaddrinfo(result);
	return 0;
}

int resolve_and_connect(const char *peer_addr_pair, struct sockaddr_inx *peer_addr)
{
	int sockfd, rc;

	if ((rc = get_sockaddr_inx_pair(peer_addr_pair, peer_addr)) < 0)
		return rc;

	if ((sockfd = socket(peer_addr->sa.sa_family, SOCK_DGRAM, IPPROTO_UDP)) < 0) {
		fprintf(stderr, "*** socket() failed: %s.\n", strerror(errno));
		return -1;
	}
	if (connect(sockfd, (struct sockaddr *)peer_addr, sizeof_sockaddr(peer_addr)) < 0) {
		close(sockfd);
		return -EAGAIN;
	}
	set_nonblock(sockfd);

	return sockfd;
}

int tun_alloc(char *dev, bool tap_mode)
{
	int fd = -1, err;
#if defined(__APPLE__) || defined(__FreeBSD__)
	int b_enable = 1, i;

	for (i = 0; i < 8; i++) {
		char dev_path[20];
		sprintf(dev_path, "/dev/tun%d", i);
		if ((fd = open(dev_path, O_RDWR)) >= 0) {
			sprintf(dev, "tun%d", i);
			break;
		}
	}
	if (fd < 0)
		return -EINVAL;
	if ((err = ioctl(fd, TUNSIFHEAD, &b_enable)) < 0) {
		close(fd);
		return err;
	}
#else
	struct ifreq ifr;

	if ((fd = open("/dev/net/tun", O_RDWR)) >= 0) {
	} else if ((fd = open("/dev/tun", O_RDWR)) >= 0) {
	} else {
		return -EINVAL;
	}

	memset(&ifr, 0, sizeof(ifr));
	if (tap_mode) {
		ifr.ifr_flags = IFF_TAP;
	} else {
		ifr.ifr_flags = IFF_TUN;
	}
	if (dev[0])
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if ((err = ioctl(fd, TUNSETIFF, (void *)&ifr)) < 0) {
		close(fd);
		return err;
	}
	strcpy(dev, ifr.ifr_name);
#endif

	return fd;
}

void ip_addr_add_ipv4(const char *ifname, struct in_addr *local,
		struct in_addr *peer, int prefix)
{
	char cmd[256];
	if (is_valid_unicast_in(local) && is_valid_unicast_in(peer)) {
		char s1[64], s2[64];
#if defined(__APPLE__) || defined(__FreeBSD__)
		sprintf(cmd, "ifconfig %s %s %s 2>/dev/null", ifname,
				inet_ntop(AF_INET, local, s1, sizeof(s1)),
				inet_ntop(AF_INET, peer, s2, sizeof(s2)));
#else
		sprintf(cmd, "ip addr add %s peer %s dev %s 2>/dev/null",
				inet_ntop(AF_INET, local, s1, sizeof(s1)),
				inet_ntop(AF_INET, peer, s2, sizeof(s2)),
				ifname);
#endif
		(void)system(cmd);
	} else if (is_valid_unicast_in(local) && prefix > 0) {
		char s1[64];
#if defined(__APPLE__) || defined(__FreeBSD__)
		char s2[64];
		sprintf(cmd, "ifconfig %s %s %s 2>/dev/null", ifname,
				inet_ntop(AF_INET, local, s1, sizeof(s1)),
				inet_ntop(AF_INET, local, s2, sizeof(s2)));
#else
		sprintf(cmd, "ip addr add %s/%d dev %s 2>/dev/null",
				inet_ntop(AF_INET, local, s1, sizeof(s1)),
				prefix, ifname);
#endif
		(void)system(cmd);
	}
}

void ip_addr_add_ipv6(const char *ifname, struct in6_addr *local, int prefix)
{
	char cmd[256];
	if (is_valid_unicast_in6(local) && prefix > 0) {
		char s1[64];
#if defined(__APPLE__) || defined(__FreeBSD__)
		sprintf(cmd, "ifconfig %s inet6 %s/%d 2>/dev/null", ifname,
				inet_ntop(AF_INET6, local, s1, sizeof(s1)), prefix);
#else
		sprintf(cmd, "ip -6 addr add %s/%d dev %s 2>/dev/null",
				inet_ntop(AF_INET6, local, s1, sizeof(s1)),
				prefix, ifname);
#endif
		(void)system(cmd);
	}
}

void ip_link_set_mtu(const char *ifname, unsigned mtu)
{
	char cmd[256];
#if defined(__APPLE__) || defined(__FreeBSD__)
	sprintf(cmd, "ifconfig %s mtu %u", ifname, mtu);
#else
	sprintf(cmd, "ip link set dev %s mtu %u", ifname, mtu);
#endif
	(void)system(cmd);
}

void ip_link_set_updown(const char *ifname, bool up)
{
	char cmd[256];
#if defined(__APPLE__) || defined(__FreeBSD__)
	sprintf(cmd, "ifconfig %s %s", ifname, up ? "up" : "down");
#else
	sprintf(cmd, "ip link set %s %s", ifname, up ? "up" : "down");
#endif
	(void)system(cmd);
}

void ip_route_add_ipvx(const char *ifname, int af, void *network,
		int prefix, int metric, const char *table)
{
	char cmd[256], __net[64] = "", __ip_sfx[40] = "";

	inet_ntop(af, network, __net, sizeof(__net));
	if (table)
		sprintf(__ip_sfx, " table %s", table);
#if defined(__APPLE__) || defined(__FreeBSD__)
	sprintf(cmd, "%s add -net %s/%d %s metric %d",
			af == AF_INET6 ? "route -A inet6" : "route",
			__net, prefix, ifname, metric);
#else
	sprintf(cmd, "%s route add %s/%d dev %s metric %d%s",
			af == AF_INET6 ? "ip -6" : "ip", __net, prefix,
			ifname, metric, __ip_sfx);
#endif
	(void)system(cmd);
}

void do_daemonize(void)
{
	pid_t pid;
	int fd;

	/* Fork off the parent process */
	if ((pid = fork()) < 0) {
		/* Error */
		fprintf(stderr, "*** fork() error: %s.\n", strerror(errno));
		exit(1);
	} else if (pid > 0) {
		/* Let the parent process terminate */
		exit(0);
	}

	/* Do this before child process quits to prevent duplicate printf output */
	if ((fd = open("/dev/null", O_RDWR)) >= 0) {
		dup2(fd, 0);
		dup2(fd, 1);
		dup2(fd, 2);
		if (fd > 2)
			close(fd);
	}

	/* Let the child process become session leader */
	if (setsid() < 0)
		exit(1);

	if ((pid = fork()) < 0) {
		/* Error */
		exit(1);
	} else if (pid > 0) {
		/* Let the parent process terminate */
		exit(0);
	}

	/* OK, set up the grandchild process */
	chdir("/tmp");
}

