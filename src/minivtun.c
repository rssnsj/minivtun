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
#include <syslog.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include "minivtun.h"

struct minivtun_config config = {
	.ifname = "",
	.tun_mtu = 1300,
	.tun_qlen = 1500, /* driver default: 500 */
	.crypto_passwd = "",
	.crypto_type = NULL,
	.pid_file = NULL,
	.in_background = false,
	.tap_mode = false,
	.wait_dns = false,
	.exit_after = 0,
	.dynamic_link = false,
	.reconnect_timeo = 47,
	.max_droprate = 100,
	.max_rtt = 0,
	.keepalive_interval = 7,
	.health_assess_interval = 60,
	.nr_stats_buckets = 3,
	.health_file = NULL,
	.vt_metric = 0,
	.vt_table = "",
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

static void print_help(int argc, char *argv[])
{
	int i;

	printf("Mini virtual tunneller in non-standard protocol.\n");
	printf("Usage:\n");
	printf("  %s [options]\n", argv[0]);
	printf("Options:\n");
	printf("  -l, --local <ip:port>               local IP:port for server to listen\n");
	printf("  -r, --remote <host:port>            host:port of server to connect (brace with [] for bare IPv6)\n");
	printf("  -n, --ifname <ifname>               virtual interface name\n");
	printf("  -m, --mtu <mtu>                     set MTU size, default: %u.\n", config.tun_mtu);
	printf("  -Q, --qlen <qlen>                   set TX queue length, default: %u\n", config.tun_qlen);
	printf("  -a, --ipv4-addr <tun_lip/tun_rip>   pointopoint IPv4 pair of the virtual interface\n");
	printf("                  <tun_lip/pfx_len>   IPv4 address/prefix length pair\n");
	printf("  -A, --ipv6-addr <tun_ip6/pfx_len>   IPv6 address/prefix length pair\n");
	printf("  -d, --daemon                        run as daemon process\n");
	printf("  -p, --pidfile <pid_file>            PID file of the daemon\n");
	printf("  -E, --tap                           TAP mode\n");
	printf("  -e, --key <encryption_key>          shared password for data encryption\n");
	printf("  -t, --type <encryption_type>        encryption type\n");
	printf("  -v, --route <network/prefix>[=gw]   attached IPv4/IPv6 route on this link, can be multiple\n");
	printf("  -w, --wait-dns                      wait for DNS resolve ready after service started\n");
	printf("  -D, --dynamic-link                  dynamic link mode, not bring up until data received\n");
	printf("  -M, --metric <metric>               metric of attached IPv4 routes\n");
	printf("  -T, --table <table_name>            route table of the attached IPv4 routes\n");
	printf("  -x, --exit-after <N>                force the client to exit after N seconds\n");
	printf("  -H, --health-file <file_path>       file for writing real-time health data\n");
	printf("  -R, --reconnect-timeo <N>           maximum inactive time (seconds) before reconnect, default: %u\n", config.reconnect_timeo);
	printf("  -K, --keepalive <N>                 seconds between keep-alive tests, default: %u\n", config.keepalive_interval);
	printf("  -S, --health-assess <N>             seconds between health assess, default: %u\n", config.health_assess_interval);
	printf("  -B, --stats-buckets <N>             health data buckets, default: %u\n", config.nr_stats_buckets);
	printf("  -P, --max-droprate <1~100>          maximum allowed packet drop percentage, default: %u%%\n", config.max_droprate);
	printf("  -X, --max-rtt <N>                   maximum allowed echo delay (ms), default: unlimited\n");
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
	int override_mtu = 0, opt;
	struct timeval current;

	static struct option long_opts[] = {
		{ "local", required_argument, 0, 'l', },
		{ "remote", required_argument, 0, 'r', },
		{ "ipv4-addr", required_argument, 0, 'a', },
		{ "ipv6-addr", required_argument, 0, 'A', },
		{ "ifname", required_argument, 0, 'n', },
		{ "mtu", required_argument, 0, 'm', },
		{ "qlen", required_argument, 0, 'Q', },
		{ "pidfile", required_argument, 0, 'p', },
		{ "daemon", no_argument, 0, 'd', },
		{ "tap", no_argument, 0, 'E', },
		{ "key", required_argument, 0, 'e', },
		{ "type", required_argument, 0, 't', },
		{ "route", required_argument, 0, 'v', },
		{ "wait-dns", no_argument, 0, 'w', },
		{ "exit-after", required_argument, 0, 'x', },
		{ "dynamic-link", no_argument, 0, 'D', },
		{ "reconnect", required_argument, 0, 'R', },
		{ "keepalive", required_argument, 0, 'K', },
		{ "health-assess", required_argument, 0, 'S', },
		{ "stats-buckets", required_argument, 0, 'B', },
		{ "health-file", required_argument, 0, 'H', },
		{ "max-droprate", required_argument, 0, 'P', },
		{ "max-rtt", required_argument, 0, 'X', },
		{ "metric", required_argument, 0, 'M', },
		{ "table", required_argument, 0, 'T', },
		{ "help", no_argument, 0, 'h', },
		{ 0, 0, 0, 0, },
	};

	while ((opt = getopt_long(argc, argv, "r:l:a:A:m:Q:n:p:e:t:v:x:R:K:S:B:H:P:X:M:T:DEdwh",
			long_opts, NULL)) != -1) {
		switch (opt) {
		case 'l':
			loc_addr_pair = optarg;
			break;
		case 'r':
			peer_addr_pair = optarg;
			break;
		case 'a':
			tun_ip_config = optarg;
			break;
		case 'A':
			tun_ip6_config = optarg;
			break;
		case 'n':
			strncpy(config.ifname, optarg, sizeof(config.ifname) - 1);
			config.ifname[sizeof(config.ifname) - 1] = '\0';
			break;
		case 'm':
			override_mtu = strtoul(optarg, NULL, 10);
			break;
		case 'Q':
			config.tun_qlen = strtoul(optarg, NULL, 10);
			break;
		case 'p':
			config.pid_file = optarg;
			break;
		case 'd':
			config.in_background = true;
			break;
		case 'E':
			config.tap_mode = true;
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
		case 'w':
			config.wait_dns = true;
			break;
		case 'x':
			config.exit_after = strtoul(optarg, NULL, 10);
			break;
		case 'D':
			config.dynamic_link = true;
			break;
		case 'R':
			config.reconnect_timeo = strtoul(optarg, NULL, 10);
			break;
		case 'K':
			config.keepalive_interval = strtoul(optarg, NULL, 10);
			break;
		case 'S':
			config.health_assess_interval = strtoul(optarg, NULL, 10);
			break;
		case 'B':
			config.nr_stats_buckets = strtoul(optarg, NULL, 10);
			break;
		case 'H':
			config.health_file = optarg;
			break;
		case 'P':
			config.max_droprate = strtoul(optarg, NULL, 10);
			if (config.max_droprate < 1 || config.max_droprate > 100) {
				fprintf(stderr, "*** Acceptable '--max-droprate' values: 1~100.\n");
				exit(1);
			}
			break;
		case 'X':
			config.max_rtt = strtoul(optarg, NULL, 10);
			break;
		case 'M':
			config.vt_metric = strtoul(optarg, NULL, 10);
			break;
		case 'T':
			strncpy(config.vt_table, optarg, sizeof(config.vt_table));
			config.vt_table[sizeof(config.vt_table) - 1] = '\0';
			break;
		case 'h':
			print_help(argc, argv);
			exit(0);
			break;
		case '?':
			exit(1);
		}
	}

	if (override_mtu) {
		config.tun_mtu = override_mtu;
	} else {
		/* Default ethernet mode MTU: 1500 */
		if (config.tap_mode)
			config.tun_mtu = 1500;
	}

	/* Random seed */
	gettimeofday(&current, NULL);
	srand(current.tv_sec ^ current.tv_usec ^ getpid());

	if (config.ifname[0] == '\0')
		strcpy(config.ifname, "mv%d");
	if ((state.tunfd = tun_alloc(config.ifname, config.tap_mode)) < 0) {
		fprintf(stderr, "*** open_tun() failed: %s.\n", strerror(errno));
		exit(1);
	}

	openlog(config.ifname, LOG_PID | LOG_PERROR | LOG_NDELAY, LOG_USER);

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
	ip_link_set_txqueue_len(config.ifname, config.tun_qlen);
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

	/* Some cleanups before exit */
	if (config.health_file)
		remove(config.health_file);
	closelog();

	return 0;
}

