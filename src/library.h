/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/minivtun
 */

#ifndef __LIBRARY_H
#define __LIBRARY_H

#include <sys/types.h>
#include <stddef.h>
#include <netdb.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <openssl/aes.h>
#include <openssl/md5.h>

#define __be32 uint32_t
#define __be16 uint16_t
#define __u8 uint8_t

#define bool char
#define true 1
#define false 0

#define container_of(ptr, type, member) ({			\
	const typeof(((type *)0)->member) * __mptr = (ptr);	\
	(type *)((char *)__mptr - offsetof(type, member)); })

/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */

static inline void gen_string_md5sum(void *out, const char *in)
{
	MD5_CTX ctx;
	MD5_Init(&ctx);
	MD5_Update(&ctx, in, strlen(in));
	MD5_Final(out, &ctx);
}

static inline void gen_encrypt_key(AES_KEY *key, const char *passwd)
{
	char md[16];
	gen_string_md5sum(md, passwd);
	AES_set_encrypt_key((void *)md, 128, key);
}

static inline void gen_decrypt_key(AES_KEY *key, const char *passwd)
{
	char md[16];
	gen_string_md5sum(md, passwd);
	AES_set_decrypt_key((void *)&md, 128, key);
}

#define AES_IVEC_INITVAL  { 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, \
		0x78, 0x90, 0xab, 0xcd, 0xef, 0x12, 0x34, 0x56, 0x78, 0x90, }

static inline void bytes_encrypt(AES_KEY *key, const void *in, void *out, size_t *dlen)
{
	unsigned char ivec[AES_BLOCK_SIZE] = AES_IVEC_INITVAL;
	size_t remain = *dlen % AES_BLOCK_SIZE;
	if (remain) {
		size_t padding = AES_BLOCK_SIZE - remain;
		memset((char *)in + *dlen, 0x0, padding);
		*dlen += padding;
	}
	AES_cbc_encrypt(in, out, *dlen, key, (void *)ivec, AES_ENCRYPT);
}

static inline void bytes_decrypt(AES_KEY *key, const void *in, void *out, size_t *dlen)
{
	unsigned char ivec[AES_BLOCK_SIZE] = AES_IVEC_INITVAL;
	size_t remain = *dlen % AES_BLOCK_SIZE;
	if (remain) {
		size_t padding = AES_BLOCK_SIZE - remain;
		memset((char *)in + *dlen, 0x0, padding);
		*dlen += padding;
	}
	AES_cbc_encrypt(in, out, *dlen, key, (void *)ivec, AES_DECRYPT);
}

/* =-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-= */

static inline bool is_valid_unicast_in(struct in_addr *in)
{
	uint32_t a = ntohl(in->s_addr);
	return  ((a & 0xff000000) != 0x00000000) &&
			((a & 0xf0000000) != 0xe0000000);
}

static inline bool is_valid_unicast_in6(struct in6_addr *in6)
{
	uint32_t a0 = ntohl(((__be32 *)in6)[0]);
	return  ((a0 & 0xff000000) != 0x00000000) &&
			((a0 & 0xff000000) != 0xff000000);
}

int v4pair_to_sockaddr(const char *pair, char sep, struct sockaddr_in *addr);

int do_daemonize(void);

static inline int set_nonblock(int sockfd)
{
	if (fcntl(sockfd, F_SETFL, fcntl(sockfd, F_GETFD, 0)|O_NONBLOCK) == -1)
		return -1;
	return 0;
}

static inline void hexdump(void *d, size_t len)
{
	unsigned char *s;
	for (s = d; len; len--, s++)
		printf("%02x ", (unsigned int)*s);
	printf("\n");
}

#endif /* __LIBRARY_H */

