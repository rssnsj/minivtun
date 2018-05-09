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
#include <assert.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "minivtun.h"

struct minivtun_config config = {
	.keepalive_timeo = 7,
	.reconnect_timeo = 45,
	.health_assess_timeo = 100,
	.ifname = "",
	.tun_mtu = 1300,
	.crypto_passwd = "",
	.crypto_type = NULL,
	.pid_file = NULL,
	.health_file = NULL,
	.in_background = false,
	.wait_dns = false,
	.dynamic_link = false,
};

struct state_variables state = {
	.tunfd = -1,
	.sockfd = -1,
};

static void vt_route_add(short af, void *n, int prefix, void *g)
{
	union {
		struct in_addr in;
		struct in6_addr in6;
	} *network = n, *gateway = g;
	struct vt_route *rt;

	rt = malloc(sizeof(struct vt_route));
	memset(rt, 0x0, sizeof(*rt));

	rt->af = af;
	rt->prefix = prefix;
	if (af == AF_INET) {
		rt->network.in = network->in;
		rt->network.in.s_addr &= prefix ? htonl(~((1 << (32 - prefix)) - 1)) : 0;
		rt->gateway.in = gateway->in;
	} else if (af == AF_INET6) {
		int i;
		rt->network.in6 = network->in6;
		if (prefix < 128) {
			rt->network.in6.s6_addr[prefix / 8] &= ~((1 << (8 - prefix % 8)) - 1);
			for (i = prefix / 8 + 1; i < 16; i++)
				rt->network.in6.s6_addr[i] &= 0x00;
		}
		rt->gateway.in6 = gateway->in6;
	} else {
		assert(0);
	}

	/* Append to the list */
	rt->next = config.vt_routes;
	config.vt_routes = rt;
}

static void parse_virtual_route(const char *arg)
{
	char expr[80], *net, *pfx, *gw;
	short af = 0;
	int prefix = -1;
	union {
		struct in_addr in;
		struct in6_addr in6;
	} network, gateway;

	strncpy(expr, arg, sizeof(expr));
	expr[sizeof(expr) - 1] = '\0';

	/* Has gateway or not */
	if ((gw = strchr(expr, '=')))
		*(gw++) = '\0';

	/* Network or single IP/IPv6 address */
	net = expr;
	if ((pfx = strchr(net, '/'))) {
		*(pfx++) = '\0';
		prefix = strtol(pfx, NULL, 10);
		if (errno != ERANGE && prefix >= 0 && prefix <= 32 &&
			inet_pton(AF_INET, net, &network)) {
			/* 192.168.0.0/16=10.7.7.1 */
			af = AF_INET;
		} else if (errno != ERANGE && prefix >= 0 && prefix <= 128 &&
			inet_pton(AF_INET6, net, &network)) {
			/* 2001:470:f9f2:ffff::/64=2001:470:f9f2::1 */
			af = AF_INET6;
		} else {
			fprintf(stderr, "*** Not a valid route expression '%s'.\n", arg);
			exit(1);
		}
	} else {
		if (inet_pton(AF_INET, net, &network)) {
			/* 192.168.0.1=10.7.7.1 */
			af = AF_INET;
			prefix = 32;
		} else if (inet_pton(AF_INET6, net, &network)) {
			/* 2001:470:f9f2:ffff::1=2001:470:f9f2::1 */
			af = AF_INET6;
			prefix = 128;
		} else {
			fprintf(stderr, "*** Not a valid route expression '%s'.\n", arg);
			exit(1);
		}
	}

	/* Has gateway or not */
	if (gw) {
		if (!inet_pton(af, gw, &gateway)) {
			fprintf(stderr, "*** Not a valid route expression '%s'.\n", arg);
			exit(1);
		}
	} else {
		memset(&gateway, 0x0, sizeof(gateway));
	}

	vt_route_add(af, &network, prefix, &gateway);
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
	printf("  -v, --route <network/prefix>[=gw]   attached IPv4/IPv6 route on this link, can be multiple\n");
	printf("  -M, --metric <metric>               metric of attached IPv4 routes\n");
	printf("  -T, --table <table_name>            route table of the attached IPv4 routes\n");
	printf("  -D, --dynamic-link                  dynamic link mode, not bring up until data received\n");
	printf("  -w, --wait-dns                      wait for DNS resolve ready after service started.\n");
	printf("      --health-file <file_path>       file for writing real-time health data.\n");
	printf("  -d, --daemon                        run as daemon process\n");
	printf("  -h, --help                          print this help\n");
	printf("Supported encryption algorithms:\n");
	printf("  ");
	for (i = 0; cipher_pairs[i].name; i++)
		printf("%s, ", cipher_pairs[i].name);
	printf("\n");
}

int main(int argc, char *argv[])
{
	const char *tun_ip_config = NULL, *tun_ip6_config = NULL;
	const char *loc_addr_pair = NULL, *peer_addr_pair = NULL;
	const char *crypto_type = CRYPTO_DEFAULT_ALGORITHM;
	int opt;

	static struct option long_opts[] = {
		{ "local", required_argument, 0, 'l', },
		{ "remote", required_argument, 0, 'r', },
		{ "resolve", required_argument, 0, 'R', },
		{ "health-file", required_argument, 0, 'H', },
		{ "ipv4-addr", required_argument, 0, 'a', },
		{ "ipv6-addr", required_argument, 0, 'A', },
		{ "mtu", required_argument, 0, 'm', },
		{ "keepalive", required_argument, 0, 'k', },
		{ "ifname", required_argument, 0, 'n', },
		{ "pidfile", required_argument, 0, 'p', },
		{ "key", required_argument, 0, 'e', },
		{ "type", required_argument, 0, 't', },
		{ "route", required_argument, 0, 'v', },
		{ "metric", required_argument, 0, 'M', },
		{ "table", required_argument, 0, 'T', },
		{ "dynamic-link", no_argument, 0, 'D', },
		{ "daemon", no_argument, 0, 'd', },
		{ "wait-dns", no_argument, 0, 'w', },
		{ "help", no_argument, 0, 'h', },
		{ 0, 0, 0, 0, },
	};

	while ((opt = getopt_long(argc, argv, "r:l:R:H:a:A:m:k:n:p:e:t:v:M:T:Ddwh",
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
		case 'H':
			config.health_file = optarg;
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
			strncpy(config.ifname, optarg, sizeof(config.ifname) - 1);
			config.ifname[sizeof(config.ifname) - 1] = '\0';
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
		case 'M':
			config.vt_metric = strtol(optarg, NULL, 0);
			break;
		case 'T':
			strncpy(config.vt_table, optarg, sizeof(config.vt_table));
			config.vt_table[sizeof(config.vt_table) - 1] = '\0';
			break;
		case 'D':
			config.dynamic_link = true;
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

	/* Random seed */
	srand(getpid());

	if (strlen(config.ifname) == 0)
		strcpy(config.ifname, "mv%d");
	if ((state.tunfd = tun_alloc(config.ifname)) < 0) {
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
		config.tun_in_local = vaddr;
		if (inet_pton(AF_INET, s_rip, &vaddr)) {
			if (loc_addr_pair) {
				struct in_addr nz = { .s_addr = 0 };
				vt_route_add(AF_INET, &nz, 0, &vaddr);
			}
			config.tun_in_peer = vaddr;
		} else if (sscanf(s_rip, "%d", &pfxlen) == 1 && pfxlen > 0 && pfxlen < 31 ) {
			config.tun_in_prefix = pfxlen;
		} else {
			fprintf(stderr, "*** Not a legal netmask or prefix length: %s.\n", s_rip);
			exit(1);
		}
		ip_addr_add_ipv4(config.ifname, &config.tun_in_local,
				&config.tun_in_peer, config.tun_in_prefix);
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
		config.tun_in6_local = vaddr;
		if (!(sscanf(s_pfx, "%d", &pfxlen) == 1 && pfxlen > 0 && pfxlen <= 128)) {
			fprintf(stderr, "*** Not a legal prefix length: %s.\n", s_pfx);
			exit(1);
		}
		config.tun_in6_prefix = pfxlen;

		ip_addr_add_ipv6(config.ifname, &config.tun_in6_local, config.tun_in6_prefix);
	}

	/* Set proper MTU size, and link up */
	ip_link_set_mtu(config.ifname, config.tun_mtu);
	ip_link_set_updown(config.ifname, true);

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
		run_server(loc_addr_pair);
	} else if (peer_addr_pair) {
		run_client(peer_addr_pair);
	} else {
		fprintf(stderr, "*** No valid local or peer address specified.\n");
		exit(1);
	}

	return 0;
}

