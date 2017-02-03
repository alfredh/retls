/**
 * @file main.c Main application code
 *
 * Copyright (C) 2010 - 2016 Creytiv.com
 */

#include <string.h>
#include <stdlib.h>
#include <getopt.h>
#include <re.h>


static struct client {

	struct sa srv;
	struct tls *tls;
	struct tls_conn *sc;
	struct tcp_conn *tc;
	struct dtls_sock *ds;
	uint64_t ts_start;
	char host[256];
	uint16_t port;
	bool estab;
	bool quiet;
	int proto;
	int err;

} g_client = {
	.proto = IPPROTO_TCP,
};


static void terminate(struct client *client, int err)
{
	client->err = err;
	re_cancel();
}


static void signal_handler(int signum)
{
	static bool term = false;
	(void)signum;

	if (term) {
		re_fprintf(stderr, "forced exit\n");
		exit(2);
	}

	re_fprintf(stderr, "cancelled\n");
	term = true;

	re_cancel();
}


static void estab_handler(void *arg)
{
	struct client *client = arg;
	uint64_t now = tmr_jiffies();
	char cn[512];

	client->estab = true;

	if (!client->quiet) {
		re_printf("TLS connection established with"
			  " cipher %s in %d milliseconds\n",
			  tls_cipher_name(client->sc),
			  (int)(now - client->ts_start));
	}

	if (0 == tls_peer_common_name(client->sc, cn, sizeof(cn))) {

		if (!client->quiet) {
			re_printf("Common name:    %s\n", cn);
		}
	}

	/* Stop the main loop and exit */
	re_cancel();
}


static void recv_handler(struct mbuf *mb, void *arg)
{
	struct client *client = arg;
	(void)client;

	re_printf("received application-data %zu bytes\n", mbuf_get_left(mb));
}


static void close_handler(int err, void *arg)
{
	struct client *client = arg;

	re_printf("connection closed: %m\n", err);

	client->sc = mem_deref(client->sc);
	client->tc = mem_deref(client->tc);

	terminate(client, err);
}


static void dtls_recv_handler(struct mbuf *mb, void *arg)
{
	struct client *client = arg;
	(void)client;

	re_printf("received application-data %zu bytes\n", mbuf_get_left(mb));
}


static void dtls_close_handler(int err, void *arg)
{
	struct client *client = arg;

	re_printf("DTLS connection closed: %m\n", err);

	client->sc = mem_deref(client->sc);

	terminate(client, err);
}


static int start(struct client *client)
{
	int err;

	client->ts_start = tmr_jiffies();

	switch (client->proto) {

	case IPPROTO_TCP:
		err = tcp_connect(&client->tc, &client->srv,
				  estab_handler, recv_handler, close_handler,
				  client);
		if (err) {
			re_fprintf(stderr, "TCP connection failed (%m)\n",
				   err);
			return err;
		}

		err = tls_start_tcp(&client->sc, client->tls, client->tc, 0);
		if (err) {
			re_fprintf(stderr, "TLS start failed (%m)\n", err);
			return err;
		}
		break;

	case IPPROTO_UDP:
		err = dtls_listen(&client->ds, NULL, NULL, 4, 0, NULL, NULL);
		if (err) {
			re_fprintf(stderr, "could not create DTLS-socket"
				   " (%m)\n", err);
			return err;
		}

		err = dtls_connect(&client->sc, client->tls,
				   client->ds, &client->srv,
				   estab_handler, dtls_recv_handler,
				   dtls_close_handler, client);
		if (err) {
			re_fprintf(stderr, "DTLS-connect error (%m)\n", err);
			return err;
		}
		break;

	default:
		return EPROTONOSUPPORT;
	}

	return 0;
}


static bool rr_handler(struct dnsrr *rr, void *arg)
{
	struct client *client = arg;

	switch (rr->type) {

	case DNS_TYPE_A:
		sa_set_in(&client->srv, rr->rdata.a.addr, client->port);
		return true;
	}

	return false;
}


static void query_handler(int err, const struct dnshdr *hdr, struct list *ansl,
			  struct list *authl, struct list *addl, void *arg)
{
	struct client *client = arg;
	(void)hdr;
	(void)authl;
	(void)addl;

	dns_rrlist_apply2(ansl, client->host, DNS_TYPE_A, DNS_TYPE_AAAA,
			  DNS_CLASS_IN, true, rr_handler, client);
	if (!sa_isset(&client->srv, SA_ALL)) {
		re_fprintf(stderr, "no DNS answers\n");
		terminate(client, EDESTADDRREQ);
		return;
	}

	if (!client->quiet) {
		re_printf("resolved host: %j\n", &client->srv);
	}

	err = start(client);
	if (err)
		goto out;

 out:
	if (err)
		terminate(client, err);
}


static int dns_init(struct dnsc **dnsc)
{
	struct sa nsv[8];
	uint32_t nsn;
	int err;

	nsn = ARRAY_SIZE(nsv);

	err = dns_srv_get(NULL, 0, nsv, &nsn);
	if (err) {
		re_fprintf(stderr, "dns_srv_get: %m\n", err);
		goto out;
	}

	err = dnsc_alloc(dnsc, NULL, nsv, nsn);
	if (err) {
		re_fprintf(stderr, "dnsc_alloc: %m\n", err);
		goto out;
	}

 out:
	return err;
}


static void usage(void)
{
	re_fprintf(stderr,
		   "retls -u TLS-server:port\n"
		   "\t-h            Show summary of options\n"
		   "\t-u            Use DTLS over UDP\n"
		   "\t-q            Quiet\n"
		   );
}


int main(int argc, char *argv[])
{
	struct client *client = &g_client;
	struct dnsc *dnsc = NULL;
	const char *server;
	enum tls_method method;
	struct pl pl_host, pl_port;
	int err = 0;

	for (;;) {

		const int c = getopt(argc, argv, "huq");
		if (0 > c)
			break;

		switch (c) {

		case 'u':
			client->proto = IPPROTO_UDP;
			break;

		case 'q':
			client->quiet = true;
			break;

		case '?':
			err = EINVAL;
			/*@fallthrough@*/
		case 'h':
			usage();
			return err;
		}
	}

	if (argc < 2 || argc != (optind + 1)) {
		usage();
		return -EINVAL;
	}

	server = argv[optind];

	if (re_regex(server, strlen(server), "[^:]+:[0-9]+",
		     &pl_host, &pl_port)) {
		usage();
		return 2;
	}

	pl_strcpy(&pl_host, client->host, sizeof(client->host));
	client->port = pl_u32(&pl_port);

	sys_coredump_set(true);

	err = libre_init();
	if (err) {
		re_fprintf(stderr, "libre_init: %m\n", err);
		goto out;
	}

	if (!client->quiet) {
		re_printf("connecting to %s:%u ...\n",
			  client->host, client->port);
	}

	switch (client->proto) {

	case IPPROTO_UDP:
		method = TLS_METHOD_DTLSV1;
		break;

	case IPPROTO_TCP:
		method = TLS_METHOD_SSLV23;
		break;

	default:
		err = EPROTONOSUPPORT;
		goto out;
	}

	err = tls_alloc(&client->tls, method, NULL, NULL);
	if (err) {
		re_fprintf(stderr, "could not create TLS context (%m)\n", err);
		goto out;
	}

	err = dns_init(&dnsc);
	if (err) {
		re_fprintf(stderr, "dnsinit: %m\n", err);
		goto out;
	}

	if (0 == sa_set_str(&client->srv, client->host, client->port)) {

		re_printf("using IP-address: %J\n", &client->srv);

		err = start(client);
		if (err)
			goto out;
	}
	else {
		if (!client->quiet) {
			re_printf("resolving host %s ...\n", client->host);
		}

		err = dnsc_query(NULL, dnsc, client->host,
				 DNS_TYPE_A, DNS_CLASS_IN,
				 true, query_handler, client);
		if (err) {
			re_fprintf(stderr, "dns query failed (%m)\n", err);
			goto out;
		}
	}

	re_main(signal_handler);

	if (client->err) {
		err = client->err;
		re_fprintf(stderr, "client error (%m)\n", client->err);
		goto out;
	}

 out:
	mem_deref(dnsc);

	mem_deref(client->sc);
	mem_deref(client->tc);
	mem_deref(client->ds);
	mem_deref(client->tls);

	libre_close();
	mem_debug();
	tmr_debug();

	if (err)
		return err;

	return g_client.estab ? 0 : 2;
}
