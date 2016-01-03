/* ----------------------------------------------------------------------- *
 *   
 *  lookup_program.c - module for Linux automount to access an
 *                     automount map via a query program 
 *
 *   Copyright 1997 Transmeta Corporation - All Rights Reserved
 *   Copyright 1999-2000 Jeremy Fitzhardinge <jeremy@goop.org>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <ctype.h>
#include <malloc.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/times.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <poll.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MAPFMT_DEFAULT "sun"

#define MODPREFIX "lookup(program): "

struct lookup_context {
	const char *mapname;
	struct parse_mod *parse;
};

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt;
	char buf[MAX_ERR_BUF];

	*context = NULL;

	ctxt = malloc(sizeof(struct lookup_context));
	if (!ctxt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		return 1;
	}

	if (argc < 1) {
		logmsg(MODPREFIX "No map name");
		free(ctxt);
		return 1;
	}
	ctxt->mapname = argv[0];

	if (ctxt->mapname[0] != '/') {
		logmsg(MODPREFIX "program map %s is not an absolute pathname",
		     ctxt->mapname);
		free(ctxt);
		return 1;
	}

	if (access(ctxt->mapname, X_OK)) {
		logmsg(MODPREFIX "program map %s missing or not executable",
		     ctxt->mapname);
		free(ctxt);
		return 1;
	}

	if (!mapfmt)
		mapfmt = MAPFMT_DEFAULT;

	ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1);
	if (!ctxt->parse) {
		logmsg(MODPREFIX "failed to open parse context");
		free(ctxt);
		return 1;
	}
	*context = ctxt;

	return 0;
}

int lookup_read_master(struct master *master, time_t age, void *context)
{
        return NSS_STATUS_UNKNOWN;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	return NSS_STATUS_UNKNOWN;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source;
	struct mapent_cache *mc;
	char *mapent = NULL, *mapp, *tmp;
	struct mapent *me;
	char buf[MAX_ERR_BUF];
	char errbuf[1024], *errp;
	char ch;
	int pipefd[2], epipefd[2];
	struct pollfd pfd[2];
	pid_t f;
	int status;
	enum state { st_space, st_map, st_done } state;
	int quoted = 0;
	int ret = 1;
	int distance;
	int alloci = 1;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	/* Check if we recorded a mount fail for this key anywhere */
	me = lookup_source_mapent(ap, name, LKP_DISTINCT);
	if (me) {
		if (me->status >= time(NULL)) {
			cache_unlock(me->mc);
			return NSS_STATUS_NOTFOUND;
		} else {
			struct mapent_cache *smc = me->mc;
			struct mapent *sme;

			if (me->mapent)
				cache_unlock(smc);
			else {
				cache_unlock(smc);
				cache_writelock(smc);
				sme = cache_lookup_distinct(smc, name);
				/* Negative timeout expired for non-existent entry. */
				if (sme && !sme->mapent)
					cache_delete(smc, name);
				cache_unlock(smc);
			}
		}
	}

	/* Catch installed direct offset triggers */
	cache_readlock(mc);
	me = cache_lookup_distinct(mc, name);
	if (!me) {
		cache_unlock(mc);
		/*
		 * If there's a '/' in the name and the offset is not in
		 * the cache then it's not a valid path in the mount tree.
		 */
		if (strchr(name, '/')) {
			debug(ap->logopt,
			      MODPREFIX "offset %s not found", name);
			return NSS_STATUS_NOTFOUND;
		}
	} else {
		/* Otherwise we found a valid offset so try mount it */
		debug(ap->logopt, MODPREFIX "%s -> %s", name, me->mapent);

		/*
		 * If this is a request for an offset mount (whose entry
		 * must be present in the cache to be valid) or the entry
		 * is newer than the negative timeout value then just
		 * try and mount it. Otherwise try and remove it and
		 * proceed with the program map lookup.
		 */
		if (strchr(name, '/') ||
		    me->age + ap->negative_timeout > time(NULL)) {
			char *ent = NULL;

			if (me->mapent) {
				ent = alloca(strlen(me->mapent) + 1);
				strcpy(ent, me->mapent);
			}
			cache_unlock(mc);
			master_source_current_wait(ap->entry);
			ap->entry->current = source;
			ret = ctxt->parse->parse_mount(ap, name,
				 name_len, ent, ctxt->parse->context);
			goto out_free;
		} else {
			if (me->multi) {
				cache_unlock(mc);
				warn(ap->logopt, MODPREFIX
				     "unexpected lookup for active multi-mount"
				     " key %s, returning fail", name);
				return NSS_STATUS_UNAVAIL;
			}
			cache_unlock(mc);
			cache_writelock(mc);
			me = cache_lookup_distinct(mc, name);
			if (me)
				cache_delete(mc, name);
			cache_unlock(mc);
		}
	}

	mapent = (char *) malloc(MAPENT_MAX_LEN + 1);
	if (!mapent) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		return NSS_STATUS_UNAVAIL;
	}

	debug(ap->logopt, MODPREFIX "looking up %s", name);

	/*
	 * We don't use popen because we don't want to run /bin/sh plus we
	 * want to send stderr to the syslog, and we don't use spawnl()
	 * because we need the pipe hooks
	 */
	if (open_pipe(pipefd)) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "pipe: %s", estr);
		goto out_free;
	}
	if (open_pipe(epipefd)) {
		close(pipefd[0]);
		close(pipefd[1]);
		goto out_free;
	}

	f = fork();
	if (f < 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "fork: %s", estr);
		close(pipefd[0]);
		close(pipefd[1]);
		close(epipefd[0]);
		close(epipefd[1]);
		goto out_free;
	} else if (f == 0) {
		reset_signals();
		close(pipefd[0]);
		close(epipefd[0]);
		dup2(pipefd[1], STDOUT_FILENO);
		dup2(epipefd[1], STDERR_FILENO);
		close(pipefd[1]);
		close(epipefd[1]);
		if (chdir(ap->path))
			warn(ap->logopt,
			     MODPREFIX "failed to set PWD to %s for map %s",
			     ap->path, ctxt->mapname);
		execl(ctxt->mapname, ctxt->mapname, name, NULL);
		_exit(255);	/* execl() failed */
	}
	close(pipefd[1]);
	close(epipefd[1]);

	mapp = mapent;
	errp = errbuf;
	state = st_space;

	pfd[0].fd = pipefd[0];
	pfd[0].events = POLLIN;
	pfd[1].fd = epipefd[0];
	pfd[1].events = POLLIN;

	while (1) {
		int bytes;

		if (poll(pfd, 2, -1) < 0 && errno != EINTR)
			break;

		if (pfd[0].fd == -1 && pfd[1].fd == -1)
			break;

		if ((pfd[0].revents & (POLLIN|POLLHUP)) == POLLHUP &&
		    (pfd[1].revents & (POLLIN|POLLHUP)) == POLLHUP)
			break;

		/* Parse maps from stdout */
		if (pfd[0].revents) {
cont:
			bytes = read(pipefd[0], &ch, 1);
			if (bytes == 0)
				goto next;
			else if (bytes < 0) {
				pfd[0].fd = -1;
				state = st_done;
				goto next;
			}

			if (!quoted && ch == '\\') {
				quoted = 1;
				goto cont;
			}

			switch (state) {
			case st_space:
				if (quoted || !isspace(ch)) {
					*mapp++ = ch;
					state = st_map;
				}
				break;
			case st_map:
				if (!quoted && ch == '\n') {
					*mapp = '\0';
					state = st_done;
					break;
				}

				/* We overwrite up to 3 characters, so we
				 * need to make sure we have enough room
				 * in the buffer for this. */
				/* else */
				if (mapp - mapent > 
				    ((MAPENT_MAX_LEN+1) * alloci) - 3) {
					/*
					 * Alloc another page for map entries.
					 */
					distance = mapp - mapent;
					tmp = realloc(mapent,
						      ((MAPENT_MAX_LEN + 1) * 
						       ++alloci));
					if (!tmp) {
						alloci--;
						logerr(MODPREFIX "realloc: %s",
						      strerror(errno));
						break;
					}
					mapent = tmp;
					mapp = tmp + distance;
				}
				/* 
				 * Eat \ quoting \n, otherwise pass it
				 * through for the parser
				 */
				if (quoted) {
					if (ch == '\n')
						*mapp++ = ' ';
					else {
						*mapp++ = '\\';
						*mapp++ = ch;
					}
				} else
					*mapp++ = ch;
				break;
			case st_done:
				/* Eat characters till there's no more output */
				break;
			}
			quoted = 0;
			goto cont;
		}
		quoted = 0;
next:
		/* Deal with stderr */
		if (pfd[1].revents) {
			while (1) {
				bytes = read(epipefd[0], &ch, 1);
				if (bytes == 0)
					break;
				else if (bytes < 0) {
					pfd[1].fd = -1;
					break;
				} else if (ch == '\n') {
					*errp = '\0';
					if (errbuf[0])
						logmsg(">> %s", errbuf);
					errp = errbuf;
				} else {
					if (errp >= &errbuf[1023]) {
						*errp = '\0';
						logmsg(">> %s", errbuf);
						errp = errbuf;
					}
					*(errp++) = ch;
				}
			}
		}
	}

	if (mapp)
		*mapp = '\0';
	if (errp > errbuf) {
		*errp = '\0';
		logmsg(">> %s", errbuf);
	}

	close(pipefd[0]);
	close(epipefd[0]);

	if (waitpid(f, &status, 0) != f) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "waitpid: %s", estr);
		goto out_free;
	}

	if (mapp == mapent || !WIFEXITED(status) || WEXITSTATUS(status) != 0) {
		info(ap->logopt, MODPREFIX "lookup for %s failed", name);
		goto out_free;
	}

	cache_writelock(mc);
	ret = cache_update(mc, source, name, mapent, time(NULL));
	cache_unlock(mc);
	if (ret == CHE_FAIL) {
		free(mapent);
		return NSS_STATUS_UNAVAIL;
	}

	debug(ap->logopt, MODPREFIX "%s -> %s", name, mapent);

	master_source_current_wait(ap->entry);
	ap->entry->current = source;

	ret = ctxt->parse->parse_mount(ap, name, name_len,
				       mapent, ctxt->parse->context);
out_free:
	if (mapent)
		free(mapent);

	if (ret) {
		time_t now = time(NULL);
		int rv = CHE_OK;

		cache_writelock(mc);
		me = cache_lookup_distinct(mc, name);
		if (!me)
			rv = cache_update(mc, source, name, NULL, now);
		if (rv != CHE_FAIL) {
			me = cache_lookup_distinct(mc, name);
			me->status = now + ap->negative_timeout;
		}
		cache_unlock(mc);
		return NSS_STATUS_TRYAGAIN;
	}

	return NSS_STATUS_SUCCESS;
}

int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parse);
	free(ctxt);
	return rv;
}
