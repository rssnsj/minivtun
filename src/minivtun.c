/*
 * Copyright (c) 2015 Justin Liu
 * Author: Justin Liu <rssnsj@gmail.com>
 * https://github.com/rssnsj/minivtun
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <getopt.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "minivtun.h"

struct minivtun_config config = {
	.keepalive_timeo = 13,
	.reconnect_timeo = 60,
	.devname = "",
	.tun_mtu = 1300,
	.crypto_passwd = "",
	.crypto_type = NULL,
	.pid_file = NULL,
	.in_background = false,
	.wait_dns = false,
};

static struct option long_opts[] = {
	{ "local", required_argument, 0, 'l', },
	{ "remote", required_argument, 0, 'r', },
	{ "resolve", required_argument, 0, 'R', },
	{ "ipv4-addr", required_argument, 0, 'a', },
	{ "ipv6-addr", required_argument, 0, 'A', },
	{ "mtu", required_argument, 0, 'm', },
	{ "keepalive", required_argument, 0, 'k', },
	{ "ifname", required_argument, 0, 'n', },
	{ "pidfile", required_argument, 0, 'p', },
	{ "key", required_argument, 0, 'e', },
	{ "type", required_argument, 0, 't', },
	{ "route", required_argument, 0, 'v', },
	{ "daemon", no_argument, 0, 'd', },
	{ "wait-dns", no_argument, 0, 'w', },
	{ "help", no_argument, 0, 'h', },
	{ 0, 0, 0, 0, },
};

static void print_help(int argc, char *argv[])
{
	int i;

	printf("Mini virtual tunneller in non-standard protocol.\n");
	printf("Usage:\n");
	printf("  %s [options]\n", argv[0]);
	printf("Options:\n");
	printf("  -l, --local <ip:port>               local IP:port for server to listen\n");
	printf("  -r, --remote <host:port>            host:port of server to connect (brace with [] for bare IPv6)\n");
	printf("  -R, --resolve <host:port>           try to resolve a hostname\n");
	printf("  -a, --ipv4-addr <tun_lip/tun_rip>   pointopoint IPv4 pair of the virtual interface\n");
	printf("                  <tun_lip/pfx_len>   IPv4 address/prefix length pair\n");
	printf("  -A, --ipv6-addr <tun_ip6/pfx_len>   IPv6 address/prefix length pair\n");
	printf("  -m, --mtu <mtu>                     set MTU size, default: %u.\n", config.tun_mtu);
	printf("  -k, --keepalive <keepalive_timeo>   interval of keep-alive packets, default: %u\n", config.keepalive_timeo);
	printf("  -n, --ifname <ifname>               virtual interface name\n");
	printf("  -p, --pidfile <pid_file>            PID file of the daemon\n");
	printf("  -e, --key <encryption_key>          shared password for data encryption\n");
	printf("  -t, --type <encryption_type>        encryption type\n");
	printf("  -v, --route <network/prefix=gateway>\n");
	printf("                                      route a network to a client address, can be multiple\n");
	printf("  -w, --wait-dns                      wait for DNS resolve ready after service started.\n");
	printf("  -d, --daemon                        run as daemon process\n");
	printf("  -h, --help                          print this help\n");
	printf("Supported encryption types:\n");
	printf("  ");
	for (i = 0; cipher_pairs[i].name; i++)
		printf("%s, ", cipher_pairs[i].name);
	printf("\n");
}

static int tun_alloc(char *dev)
{
	int fd = -1, err;
#ifdef __APPLE__
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
	ifr.ifr_flags = IFF_TUN;
	if (dev[0])
		strncpy(ifr.ifr_name, dev, IFNAMSIZ);
	if ((err = ioctl(fd, TUNSETIFF, (void *) &ifr)) < 0) {
		close(fd);
		return err;
	}
	strcpy(dev, ifr.ifr_name);
#endif

	return fd;
}

static void parse_virtual_route(const char *arg)
{
	char expr[80], *net, *pfx, *gw;
	struct in_addr network, gateway;
	unsigned prefix = 0;

	strncpy(expr, arg, sizeof(expr));
	expr[sizeof(expr) - 1] = '\0';

	/* 192.168.0.0/16=10.7.0.1 */
	net = expr;
	if ((pfx = strchr(net, '/')) == NULL) {
		fprintf(stderr, "*** Not a valid route expression '%s'.\n", arg);
		exit(1);
	}
	*(pfx++) = '\0';
	if ((gw = strchr(pfx, '=')) == NULL) {
		fprintf(stderr, "*** Not a valid route expression '%s'.\n", arg);
		exit(1);
	}
	*(gw++) = '\0';

	if (!inet_pton(AF_INET, net, &network) ||
		!inet_pton(AF_INET, gw, &gateway) || sscanf(pfx, "%u", &prefix) != 1) {
		fprintf(stderr, "*** Not a valid route expression '%s'.\n", arg);
		exit(1);
	}

	vt_route_add(&network, prefix, &gateway);
}

static int try_resolve_addr_pair(const char *addr_pair)
{
	struct sockaddr_inx inx;
	char s_addr[50] = "";
	int rc;

	if ((rc = get_sockaddr_inx_pair(addr_pair, &inx)) < 0)
		return 1;

	inet_ntop(inx.sa.sa_family, addr_of_sockaddr(&inx), s_addr, sizeof(s_addr));
	printf("[%s]:%u\n", s_addr, ntohs(port_of_sockaddr(&inx)));

	return 0;
}

int main(int argc, char *argv[])
{
	const char *tun_ip_config = NULL, *tun_ip6_config = NULL;
	const char *loc_addr_pair = NULL, *peer_addr_pair = NULL;
	const char *crypto_type = CRYPTO_DEFAULT_ALGORITHM;
	char cmd[128];
	int tunfd, opt;

	while ((opt = getopt_long(argc, argv, "r:l:R:a:A:m:k:n:p:e:t:v:dwh",
			long_opts, NULL)) != -1) {

		switch (opt) {
		case 'l':
			loc_addr_pair = optarg;
			break;
		case 'r':
			peer_addr_pair = optarg;
			break;
		case 'R':
			exit(try_resolve_addr_pair(optarg));
			break;
		case 'a':
			tun_ip_config = optarg;
			break;
		case 'A':
			tun_ip6_config = optarg;
			break;
		case 'm':
			config.tun_mtu = (unsigned)strtoul(optarg, NULL, 10);
			break;
		case 'k':
			config.keepalive_timeo = (unsigned)strtoul(optarg, NULL, 10);
			break;
		case 'n':
			strncpy(config.devname, optarg, sizeof(config.devname) - 1);
			config.devname[sizeof(config.devname) - 1] = '\0';
			break;
		case 'p':
			config.pid_file = optarg;
			break;
		case 'e':
			config.crypto_passwd = optarg;
			break;
		case 't':
			crypto_type = optarg;
			break;
		case 'v':
			parse_virtual_route(optarg);
			break;
		case 'd':
			config.in_background = true;
			break;
		case 'w':
			config.wait_dns = true;
			break;
		case 'h':
			print_help(argc, argv);
			exit(0);
			break;
		case '?':
			exit(1);
		}
	}

	if (strlen(config.devname) == 0)
		strcpy(config.devname, "mv%d");
	if ((tunfd = tun_alloc(config.devname)) < 0) {
		fprintf(stderr, "*** open_tun() failed: %s.\n", strerror(errno));
		exit(1);
	}

	/* Configure IPv4 address for the interface. */
	if (tun_ip_config) {
		char s_lip[20], s_rip[20], *sp;
		struct in_addr vaddr;
		int pfxlen = 0;

		if (!(sp = strchr(tun_ip_config, '/'))) {
			fprintf(stderr, "*** Invalid IPv4 address pair: %s.\n", tun_ip_config);
			exit(1);
		}
		strncpy(s_lip, tun_ip_config, sp - tun_ip_config);
		s_lip[sp - tun_ip_config] = '\0';
		sp++;
		strncpy(s_rip, sp, sizeof(s_rip));
		s_rip[sizeof(s_rip) - 1] = '\0';

		if (!inet_pton(AF_INET, s_lip, &vaddr)) {
			fprintf(stderr, "*** Invalid local IPv4 address: %s.\n", s_lip);
			exit(1);
		}
		config.local_tun_in = vaddr;
		if (inet_pton(AF_INET, s_rip, &vaddr)) {
			struct in_addr __network = { .s_addr = 0 };
#ifdef __APPLE__
			sprintf(cmd, "ifconfig %s %s %s", config.devname, s_lip, s_rip);
#else
			sprintf(cmd, "ifconfig %s %s pointopoint %s", config.devname, s_lip, s_rip);
#endif
			vt_route_add(&__network, 0, &vaddr);
		} else if (sscanf(s_rip, "%d", &pfxlen) == 1 && pfxlen > 0 && pfxlen < 31 ) {
			uint32_t mask = ~((1 << (32 - pfxlen)) - 1);
#ifdef __APPLE__
			uint32_t network = ntohl(vaddr.s_addr) & mask;
			sprintf(s_rip, "%u.%u.%u.%u", network >> 24, (network >> 16) & 0xff,
					(network >> 8) & 0xff, network & 0xff);
			sprintf(cmd, "ifconfig %s %s %s && route add -net %s/%d %s >/dev/null",
					config.devname, s_lip, s_lip, s_rip, pfxlen, s_lip);
#else
			sprintf(s_rip, "%u.%u.%u.%u", mask >> 24, (mask >> 16) & 0xff,
					(mask >> 8) & 0xff, mask & 0xff);
			sprintf(cmd, "ifconfig %s %s netmask %s", config.devname, s_lip, s_rip);
#endif
		} else {
			fprintf(stderr, "*** Not a legal netmask or prefix length: %s.\n",
					s_rip);
			exit(1);
		}
		(void)system(cmd);
	}

	/* Configure IPv6 address if set. */
	if (tun_ip6_config) {
		char s_lip[50], s_pfx[20], *sp;
		struct in6_addr vaddr;
		int pfxlen = 0;

		if (!(sp = strchr(tun_ip6_config, '/'))) {
			fprintf(stderr, "*** Invalid IPv6 address pair: %s.\n", tun_ip6_config);
			exit(1);
		}
		strncpy(s_lip, tun_ip6_config, sp - tun_ip6_config);
		s_lip[sp - tun_ip6_config] = '\0';
		sp++;
		strncpy(s_pfx, sp, sizeof(s_pfx));
		s_pfx[sizeof(s_pfx) - 1] = '\0';

		if (!inet_pton(AF_INET6, s_lip, &vaddr)) {
			fprintf(stderr, "*** Invalid local IPv6 address: %s.\n", s_lip);
			exit(1);
		}
		config.local_tun_in6 = vaddr;
		if (!(sscanf(s_pfx, "%d", &pfxlen) == 1 && pfxlen > 0 && pfxlen <= 128)) {
			fprintf(stderr, "*** Not a legal prefix length: %s.\n", s_pfx);
			exit(1);
		}

#ifdef __APPLE__
		sprintf(cmd, "ifconfig %s inet6 %s/%d", config.devname, s_lip, pfxlen);
#else
		sprintf(cmd, "ifconfig %s add %s/%d", config.devname, s_lip, pfxlen);
#endif
		(void)system(cmd);
	}

	/* Always bring it up with proper MTU size. */
	sprintf(cmd, "ifconfig %s mtu %u; ifconfig %s up", config.devname, config.tun_mtu, config.devname);
	(void)system(cmd);

	if (enabled_encryption()) {
		fill_with_string_md5sum(config.crypto_passwd, config.crypto_key, CRYPTO_MAX_KEY_SIZE);
		if ((config.crypto_type = get_crypto_type(crypto_type)) == NULL) {
			fprintf(stderr, "*** No such encryption type defined: %s.\n", crypto_type);
			exit(1);
		}
	} else {
		memset(config.crypto_key, 0x0, CRYPTO_MAX_KEY_SIZE);
		fprintf(stderr, "*** WARNING: Transmission will not be encrypted.\n");
	}

	if (loc_addr_pair) {
		run_server(tunfd, loc_addr_pair);
	} else if (peer_addr_pair) {
		run_client(tunfd, peer_addr_pair);
	} else {
		fprintf(stderr, "*** No valid local or peer address specified.\n");
		exit(1);
	}

	return 0;
}

