/*
 * lookup_nisplus.c
 *
 * Module for Linux automountd to access a NIS+ automount map
 */

#include <stdio.h>
#include <malloc.h>
#include <sys/param.h>
#include <sys/types.h>
#include <signal.h>
#include <sys/stat.h>
#include <rpc/rpc.h>
#include <rpc/xdr.h>
#include <rpcsvc/nis.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MAPFMT_DEFAULT "sun"

#define MODPREFIX "lookup(nisplus): "

struct lookup_context {
	const char *domainname;
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
		logerr(MODPREFIX "%s", estr);
		return 1;
	}

	if (argc < 1) {
		free(ctxt);
		logmsg(MODPREFIX "No map name");
		return 1;
	}
	ctxt->mapname = argv[0];

	/* 
	 * nis_local_directory () returns a pointer to a static buffer.
	 * We don't need to copy or free it.
	 */
	ctxt->domainname = nis_local_directory();
	if (!ctxt->domainname) {
		free(ctxt);
		logmsg(MODPREFIX "NIS+ domain not set");
		return 1;
	}

	if (!mapfmt)
		mapfmt = MAPFMT_DEFAULT;

	ctxt->parse = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1);
	if (!ctxt->parse) {
		free(ctxt);
		logerr(MODPREFIX "failed to open parse context");
		return 1;
	}
	*context = ctxt;

	return 0;
}

int lookup_read_master(struct master *master, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	unsigned int timeout = master->default_timeout;
	unsigned int logging = master->default_logging;
	unsigned int logopt =  master->logopt;
	char *tablename;
	nis_result *result;
	nis_object *this;
	unsigned int current, result_count;
	char *path, *ent;
	char *buffer;
	char buf[MAX_ERR_BUF];
	int cur_state, len;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	tablename = malloc(strlen(ctxt->mapname) + strlen(ctxt->domainname) + 20);
	if (!tablename) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		pthread_setcancelstate(cur_state, NULL);
		return NSS_STATUS_UNAVAIL;
	}
	sprintf(tablename, "%s.org_dir.%s", ctxt->mapname, ctxt->domainname);

	/* check that the table exists */
	result = nis_lookup(tablename, FOLLOW_PATH | FOLLOW_LINKS);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_freeresult(result);
		crit(logopt,
		     MODPREFIX "couldn't locate nis+ table %s", ctxt->mapname);
		free(tablename);
		pthread_setcancelstate(cur_state, NULL);
		return NSS_STATUS_NOTFOUND;
	}

	sprintf(tablename, "[],%s.org_dir.%s", ctxt->mapname, ctxt->domainname);

	result = nis_list(tablename, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_freeresult(result);
		crit(logopt,
		     MODPREFIX "couldn't enumrate nis+ map %s", ctxt->mapname);
		free(tablename);
		pthread_setcancelstate(cur_state, NULL);
		return NSS_STATUS_UNAVAIL;
	}

	current = 0;
	result_count = NIS_RES_NUMOBJ(result);

	while (result_count--) {
		this = &result->objects.objects_val[current++];
		path = ENTRY_VAL(this, 0);
		/*
		 * Ignore keys beginning with '+' as plus map
		 * inclusion is only valid in file maps.
		 */
		if (*path == '+')
			continue;

		ent = ENTRY_VAL(this, 1);

		len = ENTRY_LEN(this, 0) + 1 + ENTRY_LEN(this, 1) + 2;
		buffer = malloc(len);
		if (!buffer) {
			logerr(MODPREFIX "could not malloc parse buffer");
			continue;
		}
		memset(buffer, 0, len);

		strcat(buffer, path);
		strcat(buffer, " ");
		strcat(buffer, ent);

		master_parse_entry(buffer, timeout, logging, age);

		free(buffer);
	}

	nis_freeresult(result);
	free(tablename);
	pthread_setcancelstate(cur_state, NULL);

	return NSS_STATUS_SUCCESS;
}

int lookup_read_map(struct autofs_point *ap, time_t age, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source;
	struct mapent_cache *mc;
	char *tablename;
	nis_result *result;
	nis_object *this;
	unsigned int current, result_count;
	char *key, *mapent;
	char buf[MAX_ERR_BUF];
	int cur_state;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	/*
	 * If we don't need to create directories then there's no use
	 * reading the map. We always need to read the whole map for
	 * direct mounts in order to mount the triggers.
	 */
	if (!(ap->flags & MOUNT_FLAG_GHOST) && ap->type != LKP_DIRECT) {
		debug(ap->logopt, "map read not needed, so not done");
		return NSS_STATUS_SUCCESS;
	}

	mc = source->mc;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	tablename = malloc(strlen(ctxt->mapname) + strlen(ctxt->domainname) + 20);
	if (!tablename) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		pthread_setcancelstate(cur_state, NULL);
		return NSS_STATUS_UNAVAIL;
	}
	sprintf(tablename, "%s.org_dir.%s", ctxt->mapname, ctxt->domainname);

	/* check that the table exists */
	result = nis_lookup(tablename, FOLLOW_PATH | FOLLOW_LINKS);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_freeresult(result);
		crit(ap->logopt,
		     MODPREFIX "couldn't locate nis+ table %s", ctxt->mapname);
		free(tablename);
		pthread_setcancelstate(cur_state, NULL);
		return NSS_STATUS_NOTFOUND;
	}

	sprintf(tablename, "[],%s.org_dir.%s", ctxt->mapname, ctxt->domainname);

	result = nis_list(tablename, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_freeresult(result);
		crit(ap->logopt,
		     MODPREFIX "couldn't enumrate nis+ map %s", ctxt->mapname);
		free(tablename);
		pthread_setcancelstate(cur_state, NULL);
		return NSS_STATUS_UNAVAIL;
	}

	current = 0;
	result_count = NIS_RES_NUMOBJ(result);

	while (result_count--) {
		char *s_key;
		size_t len;

		this = &result->objects.objects_val[current++];
		key = ENTRY_VAL(this, 0);
		len = ENTRY_LEN(this, 0);

		/*
		 * Ignore keys beginning with '+' as plus map
		 * inclusion is only valid in file maps.
		 */
		if (*key == '+')
			continue;

		s_key = sanitize_path(key, len, ap->type, ap->logopt);
		if (!s_key)
			continue;

		mapent = ENTRY_VAL(this, 1);

		cache_writelock(mc);
		cache_update(mc, source, s_key, mapent, age);
		cache_unlock(mc);

		free(s_key);
	}

	nis_freeresult(result);

	source->age = age;

	free(tablename);
	pthread_setcancelstate(cur_state, NULL);

	return NSS_STATUS_SUCCESS;
}

static int lookup_one(struct autofs_point *ap,
		      const char *key, int key_len,
		      struct lookup_context *ctxt)
{
	struct map_source *source;
	struct mapent_cache *mc;
	char *tablename;
	nis_result *result;
	nis_object *this;
	char *mapent;
	time_t age = time(NULL);
	int ret, cur_state;
	char buf[MAX_ERR_BUF];

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	tablename = malloc(strlen(key) + strlen(ctxt->mapname) +
			   strlen(ctxt->domainname) + 20);
	if (!tablename) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		pthread_setcancelstate(cur_state, NULL);
		return -1;
	}
	sprintf(tablename, "[key=%s],%s.org_dir.%s", key, ctxt->mapname,
		ctxt->domainname);

	result = nis_list(tablename, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_error rs = result->status;
		nis_freeresult(result);
		free(tablename);
		pthread_setcancelstate(cur_state, NULL);
		if (rs == NIS_NOTFOUND ||
		    rs == NIS_S_NOTFOUND ||
		    rs == NIS_PARTIAL)
			return CHE_MISSING;

		return -rs;
	}

	
	this = NIS_RES_OBJECT(result);
	mapent = ENTRY_VAL(this, 1);
	cache_writelock(mc);
	ret = cache_update(mc, source, key, mapent, age);
	cache_unlock(mc);

	nis_freeresult(result);
	free(tablename);
	pthread_setcancelstate(cur_state, NULL);

	return ret;
}

static int lookup_wild(struct autofs_point *ap, struct lookup_context *ctxt)
{
	struct map_source *source;
	struct mapent_cache *mc;
	char *tablename;
	nis_result *result;
	nis_object *this;
	char *mapent;
	time_t age = time(NULL);
	int ret, cur_state;
	char buf[MAX_ERR_BUF];

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	pthread_setcancelstate(PTHREAD_CANCEL_DISABLE, &cur_state);
	tablename = malloc(strlen(ctxt->mapname) + strlen(ctxt->domainname) + 20);
	if (!tablename) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		pthread_setcancelstate(cur_state, NULL);
		return -1;
	}
	sprintf(tablename, "[key=*],%s.org_dir.%s", ctxt->mapname,
		ctxt->domainname);

	result = nis_list(tablename, FOLLOW_PATH | FOLLOW_LINKS, NULL, NULL);
	if (result->status != NIS_SUCCESS && result->status != NIS_S_SUCCESS) {
		nis_error rs = result->status;
		nis_freeresult(result);
		free(tablename);
		pthread_setcancelstate(cur_state, NULL);
		if (rs == NIS_NOTFOUND ||
		    rs == NIS_S_NOTFOUND ||
		    rs == NIS_PARTIAL)
			return CHE_MISSING;

		return -rs;
	}

	this = NIS_RES_OBJECT(result);
	mapent = ENTRY_VAL(this, 1);
	cache_writelock(mc);
	ret = cache_update(mc, source, "*", mapent, age);
	cache_unlock(mc);

	nis_freeresult(result);
	free(tablename);
	pthread_setcancelstate(cur_state, NULL);

	return ret;
}

static int check_map_indirect(struct autofs_point *ap,
			      char *key, int key_len,
			      struct lookup_context *ctxt)
{
	struct map_source *source;
	struct mapent_cache *mc;
	struct mapent *me, *exists;
	time_t now = time(NULL);
	time_t t_last_read;
	int ret = 0;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	master_source_current_wait(ap->entry);
	ap->entry->current = source;

	/* check map and if change is detected re-read map */
	ret = lookup_one(ap, key, key_len, ctxt);
	if (ret == CHE_FAIL)
		return NSS_STATUS_NOTFOUND;

	if (ret < 0) {
		/*
		 * If the server is down and the entry exists in the cache
		 * and belongs to this map return success and use the entry.
		 */
		exists = cache_lookup(mc, key);
		if (exists && exists->source == source)
			return NSS_STATUS_SUCCESS;

		warn(ap->logopt,
		     MODPREFIX "lookup for %s failed: %s",
		     key, nis_sperrno(-ret));

		return NSS_STATUS_UNAVAIL;
	}

	cache_writelock(mc);
	t_last_read = ap->exp_runfreq + 1;
	me = cache_lookup_first(mc);
	while (me) {
		if (me->source == source) {
			t_last_read = now - me->age;
			break;
		}
		me = cache_lookup_next(mc, me);
	}
	exists = cache_lookup_distinct(mc, key);
	/* Not found in the map but found in the cache */
	if (exists && exists->source == source && ret & CHE_MISSING) {
		if (exists->mapent) {
			free(exists->mapent);
			exists->mapent = NULL;
			source->stale = 1;
			exists->status = 0;
		}
	}
	cache_unlock(mc);

	if (t_last_read > ap->exp_runfreq && ret & CHE_UPDATED)
		source->stale = 1;

	if (ret == CHE_MISSING) {
		int wild = CHE_MISSING;
		struct mapent *we;

		master_source_current_wait(ap->entry);
		ap->entry->current = source;

		wild = lookup_wild(ap, ctxt);
		/*
		 * Check for map change and update as needed for
		 * following cache lookup.
		*/
		cache_writelock(mc);
		we = cache_lookup_distinct(mc, "*");
		if (we) {
			/* Wildcard entry existed and is now gone */
			if (we->source == source && wild & CHE_MISSING) {
				cache_delete(mc, "*");
				source->stale = 1;
			}
		} else {
			/* Wildcard not in map but now is */
			if (wild & (CHE_OK | CHE_UPDATED))
				source->stale = 1;
		}
		cache_unlock(mc);

		if (wild & (CHE_UPDATED | CHE_OK))
			return NSS_STATUS_SUCCESS;
	}

	if (ret == CHE_MISSING)
		return NSS_STATUS_NOTFOUND;

	return NSS_STATUS_SUCCESS;
}

int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	struct map_source *source;
	struct mapent_cache *mc;
	char key[KEY_MAX_LEN + 1];
	int key_len;
	char *mapent = NULL;
	int mapent_len;
	struct mapent *me;
	int status;
	int ret = 1;

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	debug(ap->logopt, MODPREFIX "looking up %s", name);

	key_len = snprintf(key, KEY_MAX_LEN + 1, "%s", name);
	if (key_len > KEY_MAX_LEN)
		return NSS_STATUS_NOTFOUND;

	/* Check if we recorded a mount fail for this key anywhere */
	me = lookup_source_mapent(ap, key, LKP_DISTINCT);
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
				sme = cache_lookup_distinct(smc, key);
				/* Negative timeout expired for non-existent entry. */
				if (sme && !sme->mapent)
					cache_delete(smc, key);
				cache_unlock(smc);
			}
		}
	}

	/*
	 * We can't check the direct mount map as if it's not in
	 * the map cache already we never get a mount lookup, so
	 * we never know about it.
	 */
	if (ap->type == LKP_INDIRECT && *key != '/') {
		char *lkp_key;

		cache_readlock(mc);
		me = cache_lookup_distinct(mc, key);
		if (me && me->multi)
			lkp_key = strdup(me->multi->key);
		else
			lkp_key = strdup(key);
		cache_unlock(mc);

		if (!lkp_key)
			return NSS_STATUS_UNKNOWN;

		master_source_current_wait(ap->entry);
		ap->entry->current = source;

		status = check_map_indirect(ap, lkp_key, strlen(lkp_key), ctxt);
		if (status)
			return status;
	}

	cache_readlock(mc);
	me = cache_lookup(mc, key);
	/* Stale mapent => check for entry in alternate source or wildcard */
	if (me && !me->mapent) {
		while ((me = cache_lookup_key_next(me)))
			if (me->source == source)
				break;
		if (!me)
			me = cache_lookup_distinct(mc, "*");
	}
	if (me && me->mapent && (me->source == source || *me->key == '/')) {
		mapent_len = strlen(me->mapent);
		mapent = malloc(mapent_len + 1);
		strcpy(mapent, me->mapent);
	}
	cache_unlock(mc);

	if (!mapent)
		return NSS_STATUS_TRYAGAIN;

	master_source_current_wait(ap->entry);
	ap->entry->current = source;

	debug(ap->logopt, MODPREFIX "%s -> %s", key, mapent);
	ret = ctxt->parse->parse_mount(ap, key, key_len,
				       mapent, ctxt->parse->context);
	if (ret) {
		time_t now = time(NULL);
		int rv = CHE_OK;

		cache_writelock(mc);
		me = cache_lookup_distinct(mc, key);
		if (!me)
			rv = cache_update(mc, source, key, NULL, now);
		if (rv != CHE_FAIL) {
			me = cache_lookup_distinct(mc, key);
			me->status = time(NULL) + ap->negative_timeout;
		}
		cache_unlock(mc);
		free(mapent);
		return NSS_STATUS_TRYAGAIN;
	}
	free(mapent);

	return NSS_STATUS_SUCCESS;
}

int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parse);
	free(ctxt);
	return rv;
}
