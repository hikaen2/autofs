/* ----------------------------------------------------------------------- *
 *   
 *  rpc_subs.c - routines for rpc discovery
 *
 *   Copyright 2004 Ian Kent <raven@themaw.net> - All Rights Reserved
 *   Copyright 2004 Jeff Moyer <jmoyer@redaht.com> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include "config.h"

#include <rpc/types.h>
#include <rpc/rpc.h>
#include <rpc/pmap_prot.h>
#include <sys/socket.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <rpcsvc/ypclnt.h>
#include <errno.h>
#include <sys/ioctl.h>
#include <ctype.h>
#include <pthread.h>
#include <poll.h>

#ifdef WITH_LIBTIRPC
#undef auth_destroy
#define auth_destroy(auth)                                              \
                do {                                                    \
                        int refs;                                       \
                        if ((refs = auth_put((auth))) == 0)             \
                                ((*((auth)->ah_ops->ah_destroy))(auth));\
                } while (0)
#endif

#include "mount.h"
#include "rpc_subs.h"
#include "automount.h"

/* #define STANDALONE */
#ifdef STANDALONE
#define error(logopt, msg, args...)	fprintf(stderr, msg "\n", ##args)
#else
#include "log.h"
#endif

#define MAX_IFC_BUF	1024
#define MAX_ERR_BUF	128

#define MAX_NETWORK_LEN		255

/* Get numeric value of the n bits starting at position p */
#define getbits(x, p, n)      ((x >> (p + 1 - n)) & ~(~0 << n))

static const rpcvers_t mount_vers[] = {
        MOUNTVERS_NFSV3,
        MOUNTVERS_POSIX,
        MOUNTVERS,
};

static int connect_nb(int, struct sockaddr *, socklen_t, struct timeval *);
inline void dump_core(void);

/*
 *  Perform a non-blocking connect on the socket fd.
 *
 *  The input struct timeval always has tv_nsec set to zero,
 *  we only ever use tv_sec for timeouts.
 */
static int connect_nb(int fd, struct sockaddr *addr, socklen_t len, struct timeval *tout)
{
	struct pollfd pfd[1];
	int timeout = tout->tv_sec;
	int flags, ret;

	flags = fcntl(fd, F_GETFL, 0);
	if (flags < 0)
		return -errno;

	ret = fcntl(fd, F_SETFL, flags | O_NONBLOCK);
	if (ret < 0)
		return -errno;

	/* 
	 * From here on subsequent sys calls could change errno so
	 * we set ret = -errno to capture it in case we decide to
	 * use it later.
	 */
	ret = connect(fd, addr, len);
	if (ret < 0 && errno != EINPROGRESS) {
		ret = -errno;
		goto done;
	}

	if (ret == 0)
		goto done;

	if (timeout != -1) {
		if (timeout >= (INT_MAX - 1)/1000)
			timeout = INT_MAX - 1;
		else
			timeout = timeout * 1000;
	}

	pfd[0].fd = fd;
	pfd[0].events = POLLOUT;

	ret = poll(pfd, 1, timeout);
	if (ret <= 0) {
		if (ret == 0)
			ret = -ETIMEDOUT;
		else
			ret = -errno;
		goto done;
	}

	if (pfd[0].revents) {
		int status;

		len = sizeof(ret);
		status = getsockopt(fd, SOL_SOCKET, SO_ERROR, &ret, &len);
		if (status < 0) {
			char buf[MAX_ERR_BUF + 1];
			char *estr = strerror_r(errno, buf, MAX_ERR_BUF);

			/*
			 * We assume getsockopt amounts to a read on the
			 * descriptor and gives us the errno we need for
			 * the POLLERR revent case.
			 */
			ret = -errno;

			/* Unexpected case, log it so we know we got caught */
			if (pfd[0].revents & POLLNVAL)
				logerr("unexpected poll(2) error on connect:"
				       " %s", estr);

			goto done;
		}

		/* Oops - something wrong with connect */
		if (ret)
			ret = -ret;
	}

done:
	fcntl(fd, F_SETFL, flags);
	return ret;
}

#ifndef WITH_LIBTIRPC
static int rpc_do_create_client(struct sockaddr *addr, struct conn_info *info, int *fd, CLIENT **client)
{
	CLIENT *clnt = NULL;
	struct sockaddr_in in4_laddr;
	struct sockaddr_in *in4_raddr;
	int type, proto, ret;
	socklen_t slen;

	*client = NULL;

	proto = info->proto->p_proto;
	if (proto == IPPROTO_UDP)
		type = SOCK_DGRAM;
	else
		type = SOCK_STREAM;

	/*
	 * bind to any unused port.  If we left this up to the rpc
	 * layer, it would bind to a reserved port, which has been shown
	 * to exhaust the reserved port range in some situations.
	 */
	in4_laddr.sin_family = AF_INET;
	in4_laddr.sin_port = htons(0);
	in4_laddr.sin_addr.s_addr = htonl(INADDR_ANY);
	slen = sizeof(struct sockaddr_in);

	if (!info->client) {
		struct sockaddr *laddr;

		*fd = open_sock(addr->sa_family, type, proto);
		if (*fd < 0)
			return -errno;

		laddr = (struct sockaddr *) &in4_laddr;
		if (bind(*fd, laddr, slen) < 0)
			return -errno;
	}

	in4_raddr = (struct sockaddr_in *) addr;
	in4_raddr->sin_port = htons(info->port);

	switch (info->proto->p_proto) {
	case IPPROTO_UDP:
		clnt = clntudp_bufcreate(in4_raddr,
					 info->program, info->version,
					 info->timeout, fd,
					 info->send_sz, info->recv_sz);
		break;

	case IPPROTO_TCP:
		ret = connect_nb(*fd, addr, slen, &info->timeout);
		if (ret < 0)
			return ret;

		clnt = clnttcp_create(in4_raddr,
				      info->program, info->version, fd,
				      info->send_sz, info->recv_sz);
		break;

	default:
		break;
	}

	*client = clnt;

	return 0;
}
#else
static int rpc_do_create_client(struct sockaddr *addr, struct conn_info *info, int *fd, CLIENT **client)
{
	CLIENT *clnt = NULL;
	struct sockaddr_in in4_laddr;
	struct sockaddr_in6 in6_laddr;
	struct sockaddr *laddr = NULL;
	struct netbuf nb_addr;
	int type, proto;
	size_t slen;
	int ret;

	*client = NULL;

	proto = info->proto->p_proto;
	if (proto == IPPROTO_UDP)
		type = SOCK_DGRAM;
	else
		type = SOCK_STREAM;

	/*
	 * bind to any unused port.  If we left this up to the rpc
	 * layer, it would bind to a reserved port, which has been shown
	 * to exhaust the reserved port range in some situations.
	 */
	if (addr->sa_family == AF_INET) {
		struct sockaddr_in *in4_raddr = (struct sockaddr_in *) addr;
		in4_laddr.sin_family = AF_INET;
		in4_laddr.sin_port = htons(0);
		in4_laddr.sin_addr.s_addr = htonl(INADDR_ANY);
		laddr = (struct sockaddr *) &in4_laddr;
		in4_raddr->sin_port = htons(info->port);
		slen = sizeof(struct sockaddr_in);
	} else if (addr->sa_family == AF_INET6) {
		struct sockaddr_in6 *in6_raddr = (struct sockaddr_in6 *) addr;
		in6_laddr.sin6_family = AF_INET6;
		in6_laddr.sin6_port = htons(0);
		in6_laddr.sin6_addr = in6addr_any;
		laddr = (struct sockaddr *) &in6_laddr;
		in6_raddr->sin6_port = htons(info->port);
		slen = sizeof(struct sockaddr_in6);
	} else
		return -EINVAL;

	/*
	 * bind to any unused port.  If we left this up to the rpc layer,
	 * it would bind to a reserved port, which has been shown to
	 * exhaust the reserved port range in some situations.
	 */
	if (!info->client) {
		*fd = open_sock(addr->sa_family, type, proto);
		if (*fd < 0) {
			ret = -errno;
			return ret;
		}

		if (bind(*fd, laddr, slen) < 0) {
			ret = -errno;
			return ret;
		}
	}

	nb_addr.maxlen = nb_addr.len = slen;
	nb_addr.buf = addr;

	if (info->proto->p_proto == IPPROTO_UDP)
		clnt = clnt_dg_create(*fd, &nb_addr,
				      info->program, info->version,
				      info->send_sz, info->recv_sz);
	else if (info->proto->p_proto == IPPROTO_TCP) {
		ret = connect_nb(*fd, addr, slen, &info->timeout);
		if (ret < 0)
			return ret;
		clnt = clnt_vc_create(*fd, &nb_addr,
				      info->program, info->version,
				      info->send_sz, info->recv_sz);
	} else
		return -EINVAL;

	/* Our timeout is in seconds */
	if (clnt && info->timeout.tv_sec)
		clnt_control(clnt, CLSET_TIMEOUT, (void *) &info->timeout);

	*client = clnt;

	return 0;
}
#endif

/*
 * Create an RPC client
 */
static int create_client(struct conn_info *info, CLIENT **client)
{
	struct addrinfo *ai, *haddr;
	struct addrinfo hints;
	int fd, ret;

	fd = RPC_ANYSOCK;
	*client = NULL;

	if (info->client) {
		if (!clnt_control(info->client, CLGET_FD, (char *) &fd)) {
			fd = RPC_ANYSOCK;
			clnt_destroy(info->client);
			info->client = NULL;
		} else {
			clnt_control(info->client, CLSET_FD_NCLOSE, NULL);
			clnt_destroy(info->client);
		}
	}

	if (info->addr) {
		ret = rpc_do_create_client(info->addr, info, &fd, client);
		if (ret == 0)
			goto done;
		if (ret == -EHOSTUNREACH)
			goto out_close;

		if (!info->client && fd != RPC_ANYSOCK) {
			close(fd);
			fd = RPC_ANYSOCK;
		}
	}

	memset(&hints, 0, sizeof(hints));
	hints.ai_flags = AI_ADDRCONFIG;
	hints.ai_family = AF_UNSPEC;
	if (info->proto->p_proto == IPPROTO_UDP)
		hints.ai_socktype = SOCK_DGRAM;
	else
		hints.ai_socktype = SOCK_STREAM;

	ret = getaddrinfo(info->host, NULL, &hints, &ai);
	if (ret) {
		error(LOGOPT_ANY,
		      "hostname lookup failed: %s", gai_strerror(ret));
		info->client = NULL;
		goto out_close;
	}

	haddr = ai;
	while (haddr) {
		if (haddr->ai_protocol != info->proto->p_proto) {
			haddr = haddr->ai_next;
			continue;
		}

		ret = rpc_do_create_client(haddr->ai_addr, info, &fd, client);
		if (ret == 0)
			break;
		if (ret == -EHOSTUNREACH)
			goto out_close;

		if (!info->client && fd != RPC_ANYSOCK) {
			close(fd);
			fd = RPC_ANYSOCK;
		}

		haddr = haddr->ai_next;
	}

	freeaddrinfo(ai);

done:
	if (!*client) {
		info->client = NULL;
		ret = -ENOTCONN;
		goto out_close;
	}

	/* Close socket fd on destroy, as is default for rpcowned fds */
	if  (!clnt_control(*client, CLSET_FD_CLOSE, NULL)) {
		clnt_destroy(*client);
		info->client = NULL;
		ret = -ENOTCONN;
		goto out_close;
	}

	return 0;

out_close:
	if (fd != -1)
		close(fd);
	return ret;
}

int rpc_udp_getclient(struct conn_info *info,
		      unsigned int program, unsigned int version)
{
	struct protoent *pe_proto;
	CLIENT *client;
	int ret;

	if (!info->client) {
		pe_proto = getprotobyname("udp");
		if (!pe_proto)
			return -ENOENT;

		info->proto = pe_proto;
		info->timeout.tv_sec = RPC_TOUT_UDP;
		info->timeout.tv_usec = 0;
		info->send_sz = UDPMSGSIZE;
		info->recv_sz = UDPMSGSIZE;
	}

	info->program = program;
	info->version = version;

	ret = create_client(info, &client);
	if (ret < 0)
		return ret;

	info->client = client;

	return 0;
}

void rpc_destroy_udp_client(struct conn_info *info)
{
	if (!info->client)
		return;

	clnt_destroy(info->client);
	info->client = NULL;
	return;
}

int rpc_tcp_getclient(struct conn_info *info,
		      unsigned int program, unsigned int version)
{
	struct protoent *pe_proto;
	CLIENT *client;
	int ret;

	if (!info->client) {
		pe_proto = getprotobyname("tcp");
		if (!pe_proto)
			return -ENOENT;

		info->proto = pe_proto;
		info->timeout.tv_sec = RPC_TOUT_TCP;
		info->timeout.tv_usec = 0;
		info->send_sz = 0;
		info->recv_sz = 0;
	}

	info->program = program;
	info->version = version;

	ret = create_client(info, &client);
	if (ret < 0)
		return ret;

	info->client = client;

	return 0;
}

void rpc_destroy_tcp_client(struct conn_info *info)
{
	struct linger lin = { 1, 0 };
	socklen_t lin_len = sizeof(struct linger);
	int fd;

	if (!info->client)
		return;

	if (!clnt_control(info->client, CLGET_FD, (char *) &fd))
		fd = -1;

	switch (info->close_option) {
	case RPC_CLOSE_NOLINGER:
		if (fd >= 0)
			setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, lin_len);
		break;
	}

	clnt_destroy(info->client);
	info->client = NULL;

	return;
}

int rpc_portmap_getclient(struct conn_info *info,
			  const char *host, struct sockaddr *addr, size_t addr_len,
			  const char *proto, unsigned int option)
{
	struct protoent *pe_proto;
	CLIENT *client;
	int ret;

	pe_proto = getprotobyname(proto);
	if (!pe_proto)
		return -ENOENT;

	info->host = host;
	info->addr = addr;
	info->addr_len = addr_len;
	info->program = PMAPPROG;
	info->port = PMAPPORT;
	info->version = PMAPVERS;
	info->proto = pe_proto;
	info->send_sz = RPCSMALLMSGSIZE;
	info->recv_sz = RPCSMALLMSGSIZE;
	info->timeout.tv_sec = PMAP_TOUT_UDP;
	info->timeout.tv_usec = 0;
	info->close_option = option;
	info->client = NULL;

	if (pe_proto->p_proto == IPPROTO_TCP)
		info->timeout.tv_sec = PMAP_TOUT_TCP;

	ret = create_client(info, &client);
	if (ret < 0)
		return ret;

	info->client = client;

	return 0;
}

int rpc_portmap_getport(struct conn_info *info,
			struct pmap *parms, unsigned short *port)
{
	struct conn_info pmap_info;
	CLIENT *client;
	enum clnt_stat status;
	int proto = info->proto->p_proto;
	int ret;

	memset(&pmap_info, 0, sizeof(struct conn_info));

	if (proto == IPPROTO_TCP)
		pmap_info.timeout.tv_sec = PMAP_TOUT_TCP;
	else
		pmap_info.timeout.tv_sec = PMAP_TOUT_UDP;

	if (info->client)
		client = info->client;
	else {
		pmap_info.host = info->host;
		pmap_info.addr = info->addr;
		pmap_info.addr_len = info->addr_len;
		pmap_info.port = PMAPPORT;
		pmap_info.program = PMAPPROG;
		pmap_info.version = PMAPVERS;
		pmap_info.proto = info->proto;
		pmap_info.send_sz = RPCSMALLMSGSIZE;
		pmap_info.recv_sz = RPCSMALLMSGSIZE;

		ret = create_client(&pmap_info, &client);
		if (ret < 0)
			return ret;
	}

	/*
	 * Check to see if server is up otherwise a getport will take
	 * forever to timeout.
	 */
	status = clnt_call(client, PMAPPROC_NULL,
			 (xdrproc_t) xdr_void, 0, (xdrproc_t) xdr_void, 0,
			 pmap_info.timeout);

	if (status == RPC_SUCCESS) {
		status = clnt_call(client, PMAPPROC_GETPORT,
				 (xdrproc_t) xdr_pmap, (caddr_t) parms,
				 (xdrproc_t) xdr_u_short, (caddr_t) port,
				 pmap_info.timeout);
	}

	if (!info->client) {
		/*
		 * Only play with the close options if we think it
		 * completed OK
		 */
		if (proto == IPPROTO_TCP && status == RPC_SUCCESS) {
			struct linger lin = { 1, 0 };
			socklen_t lin_len = sizeof(struct linger);
			int fd;

			if (!clnt_control(client, CLGET_FD, (char *) &fd))
				fd = -1;

			switch (info->close_option) {
			case RPC_CLOSE_NOLINGER:
				if (fd >= 0)
					setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, lin_len);
				break;
			}
		}
		clnt_destroy(client);
	}

	if (status == RPC_TIMEDOUT)
		return -ETIMEDOUT;
	else if (status != RPC_SUCCESS)
		return -EIO;

	return 0;
}

int rpc_ping_proto(struct conn_info *info)
{
	CLIENT *client;
	enum clnt_stat status;
	int proto = info->proto->p_proto;
	int ret;

	if (info->client)
		client = info->client;
	else {
		if (info->proto->p_proto == IPPROTO_UDP) {
			info->send_sz = UDPMSGSIZE;
			info->recv_sz = UDPMSGSIZE;
		}
		ret = create_client(info, &client);
		if (ret < 0)
			return ret;
	}

	clnt_control(client, CLSET_TIMEOUT, (char *) &info->timeout);
	clnt_control(client, CLSET_RETRY_TIMEOUT, (char *) &info->timeout);

	status = clnt_call(client, NFSPROC_NULL,
			 (xdrproc_t) xdr_void, 0, (xdrproc_t) xdr_void, 0,
			 info->timeout);

	if (!info->client) {
		/*
		 * Only play with the close options if we think it
		 * completed OK
		 */
		if (proto == IPPROTO_TCP && status == RPC_SUCCESS) {
			struct linger lin = { 1, 0 };
			socklen_t lin_len = sizeof(struct linger);
			int fd;

			if (!clnt_control(client, CLGET_FD, (char *) &fd))
				fd = -1;

			switch (info->close_option) {
			case RPC_CLOSE_NOLINGER:
				if (fd >= 0)
					setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, lin_len);
				break;
			}
		}
		clnt_destroy(client);
	}

	if (status == RPC_TIMEDOUT)
		return -ETIMEDOUT;
	else if (status != RPC_SUCCESS)
		return -EIO;

	return 1;
}

static unsigned int __rpc_ping(const char *host,
				unsigned long version,
				char *proto,
				long seconds, long micros,
				unsigned int option)
{
	unsigned int status;
	struct conn_info info;
	struct pmap parms;

	info.host = host;
	info.addr = NULL;
	info.addr_len = 0;
	info.program = NFS_PROGRAM;
	info.version = version;
	info.send_sz = 0;
	info.recv_sz = 0;
	info.timeout.tv_sec = seconds;
	info.timeout.tv_usec = micros;
	info.close_option = option;
	info.client = NULL;

	status = RPC_PING_FAIL;

	info.proto = getprotobyname(proto);
	if (!info.proto)
		return status;

	parms.pm_prog = NFS_PROGRAM;
	parms.pm_vers = version;
	parms.pm_prot = info.proto->p_proto;
	parms.pm_port = 0;

	status = rpc_portmap_getport(&info, &parms, &info.port);
	if (status < 0)
		return status;

	status = rpc_ping_proto(&info);

	return status;
}

int rpc_ping(const char *host, long seconds, long micros, unsigned int option)
{
	unsigned long vers3 = NFS3_VERSION;
	unsigned long vers2 = NFS2_VERSION;
	unsigned int status;

	status = __rpc_ping(host, vers2, "udp", seconds, micros, option);
	if (status > 0)
		return RPC_PING_V2 | RPC_PING_UDP;

	status = __rpc_ping(host, vers3, "udp", seconds, micros, option);
	if (status > 0)
		return RPC_PING_V3 | RPC_PING_UDP;

	status = __rpc_ping(host, vers2, "tcp", seconds, micros, option);
	if (status > 0)
		return RPC_PING_V2 | RPC_PING_TCP;

	status = __rpc_ping(host, vers3, "tcp", seconds, micros, option);
	if (status > 0)
		return RPC_PING_V3 | RPC_PING_TCP;

	return status;
}

double elapsed(struct timeval start, struct timeval end)
{
	double t1, t2;
	t1 =  (double)start.tv_sec + (double)start.tv_usec/(1000*1000);
	t2 =  (double)end.tv_sec + (double)end.tv_usec/(1000*1000);
	return t2-t1;
}

int rpc_time(const char *host,
	     unsigned int ping_vers, unsigned int ping_proto,
	     long seconds, long micros, unsigned int option, double *result)
{
	int status;
	double taken;
	struct timeval start, end;
	struct timezone tz;
	char *proto = (ping_proto & RPC_PING_UDP) ? "udp" : "tcp";
	unsigned long vers = ping_vers;

	gettimeofday(&start, &tz);
	status = __rpc_ping(host, vers, proto, seconds, micros, option);
	gettimeofday(&end, &tz);

	if (status == RPC_PING_FAIL || status < 0)
		return status;

	taken = elapsed(start, end);

	if (result != NULL)
		*result = taken;

	return status;
}

static int rpc_get_exports_proto(struct conn_info *info, exports *exp)
{
	CLIENT *client;
	enum clnt_stat status;
	int proto = info->proto->p_proto;
	unsigned int option = info->close_option;
	int vers_entry;
	int ret;

	if (info->proto->p_proto == IPPROTO_UDP) {
		info->send_sz = UDPMSGSIZE;
		info->recv_sz = UDPMSGSIZE;
	}
	ret = create_client(info, &client);
	if (ret < 0)
		return 0;

	clnt_control(client, CLSET_TIMEOUT, (char *) &info->timeout);
	clnt_control(client, CLSET_RETRY_TIMEOUT, (char *) &info->timeout);

	client->cl_auth = authunix_create_default();

	vers_entry = 0;
	while (1) {
		status = clnt_call(client, MOUNTPROC_EXPORT,
				 (xdrproc_t) xdr_void, NULL,
				 (xdrproc_t) xdr_exports, (caddr_t) exp,
				 info->timeout);
		if (status == RPC_SUCCESS)
			break;
		if (++vers_entry > 2)
			break;
		CLNT_CONTROL(client, CLSET_VERS,
			    (void *) &mount_vers[vers_entry]);
	}

	/* Only play with the close options if we think it completed OK */
	if (proto == IPPROTO_TCP && status == RPC_SUCCESS) {
		struct linger lin = { 1, 0 };
		socklen_t lin_len = sizeof(struct linger);
		int fd;

		if (!clnt_control(client, CLGET_FD, (char *) &fd))
			fd = -1;

		switch (option) {
		case RPC_CLOSE_NOLINGER:
			if (fd >= 0)
				setsockopt(fd, SOL_SOCKET, SO_LINGER, &lin, lin_len);
			break;
		}
	}
	auth_destroy(client->cl_auth);
	clnt_destroy(client);

	if (status != RPC_SUCCESS)
		return 0;

	return 1;
}

static void rpc_export_free(exports item)
{
	groups grp;
	groups tmp;

	if (item->ex_dir)
		free(item->ex_dir);

	grp = item->ex_groups;
	while (grp) {
		if (grp->gr_name)
			free(grp->gr_name);
		tmp = grp;
		grp = grp->gr_next;
		free(tmp);
	}
	free(item);
}

void rpc_exports_free(exports list)
{
	exports tmp;

	while (list) {
		tmp = list;
		list = list->ex_next;
		rpc_export_free(tmp);
	}
	return;
}

exports rpc_get_exports(const char *host, long seconds, long micros, unsigned int option)
{
	struct conn_info info;
	exports exportlist;
	struct pmap parms;
	int status;

	info.host = host;
	info.addr = NULL;
	info.addr_len = 0;
	info.program = MOUNTPROG;
	info.version = mount_vers[0];
	info.send_sz = 0;
	info.recv_sz = 0;
	info.timeout.tv_sec = seconds;
	info.timeout.tv_usec = micros;
	info.close_option = option;
	info.client = NULL;

	parms.pm_prog = info.program;
	parms.pm_vers = info.version;
	parms.pm_port = 0;

	/* Try UDP first */
	info.proto = getprotobyname("udp");
	if (!info.proto)
		goto try_tcp;

	parms.pm_prot = info.proto->p_proto;

	status = rpc_portmap_getport(&info, &parms, &info.port);
	if (status < 0)
		goto try_tcp;

	memset(&exportlist, '\0', sizeof(exportlist));

	status = rpc_get_exports_proto(&info, &exportlist);
	if (status)
		return exportlist;

try_tcp:
	info.proto = getprotobyname("tcp");
	if (!info.proto)
		return NULL;

	parms.pm_prot = info.proto->p_proto;

	status = rpc_portmap_getport(&info, &parms, &info.port);
	if (status < 0)
		return NULL;

	memset(&exportlist, '\0', sizeof(exportlist));

	status = rpc_get_exports_proto(&info, &exportlist);
	if (!status)
		return NULL;

	return exportlist;
}

const char *get_addr_string(struct sockaddr *sa, char *name, socklen_t len)
{
	void *addr;

	if (len < INET6_ADDRSTRLEN)
		return NULL;

	if (sa->sa_family == AF_INET) {
		struct sockaddr_in *ipv4 = (struct sockaddr_in *) sa;
		addr = &(ipv4->sin_addr);
	} else if (sa->sa_family == AF_INET6) {
		struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) sa;
		addr = &(ipv6->sin6_addr);
	} else {
		return NULL;
	}

	return inet_ntop(sa->sa_family, addr, name, len);
}

#if 0
#include <stdio.h>

int main(int argc, char **argv)
{
	int ret;
	double res = 0.0;
	exports exportlist, tmp;
	groups grouplist;
	int n, maxlen;

/*
	ret = rpc_ping("budgie", 10, 0, RPC_CLOSE_DEFAULT);
	printf("ret = %d\n", ret);

	res = 0.0;
	ret = rpc_time("budgie", NFS2_VERSION, RPC_PING_TCP, 10, 0, RPC_CLOSE_DEFAULT, &res);
	printf("v2 tcp ret = %d, res = %f\n", ret, res);

	res = 0.0;
	ret = rpc_time("budgie", NFS3_VERSION, RPC_PING_TCP, 10, 0, RPC_CLOSE_DEFAULT, &res);
	printf("v3 tcp ret = %d, res = %f\n", ret, res);

	res = 0.0;
	ret = rpc_time("budgie", NFS2_VERSION, RPC_PING_UDP, 10, 0, RPC_CLOSE_DEFAULT, &res);
	printf("v2 udp ret = %d, res = %f\n", ret, res);

	res = 0.0;
	ret = rpc_time("budgie", NFS3_VERSION, RPC_PING_UDP, 10, 0, RPC_CLOSE_DEFAULT, &res);
	printf("v3 udp ret = %d, res = %f\n", ret, res);
*/
	exportlist = rpc_get_exports("budgie", 10, 0, RPC_CLOSE_NOLINGER);
	exportlist = rpc_exports_prune(exportlist);

	maxlen = 0;
	for (tmp = exportlist; tmp; tmp = tmp->ex_next) {
		if ((n = strlen(tmp->ex_dir)) > maxlen)
			maxlen = n;
	}

	if (exportlist) {
		while (exportlist) {
			printf("%-*s ", maxlen, exportlist->ex_dir);
			grouplist = exportlist->ex_groups;
			if (grouplist) {
				while (grouplist) {
					printf("%s%s", grouplist->gr_name,
						grouplist->gr_next ? "," : "");
					grouplist = grouplist->gr_next;
				}
			}
			printf("\n");
			exportlist = exportlist->ex_next;
		}
	}
	rpc_exports_free(exportlist);

	exit(0);
}
#endif
