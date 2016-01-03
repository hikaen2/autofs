/*
 * lookup_hesiod.c
 *
 * Module for Linux automountd to access automount maps in hesiod filsys
 * entries.
 *
 */

#include <sys/types.h>
#include <ctype.h>
#include <limits.h>
#include <string.h>
#include <stdlib.h>
#include <netinet/in.h>
#include <arpa/nameser.h>
#include <resolv.h>
#include <hesiod.h>

#define MODULE_LOOKUP
#include "automount.h"
#include "nsswitch.h"

#define MAPFMT_DEFAULT "hesiod"

#define MODPREFIX "lookup(hesiod): "
#define HESIOD_LEN 512

struct lookup_context {
	struct parse_mod *parser;
	void *hesiod_context;
};

static pthread_mutex_t hesiod_mutex = PTHREAD_MUTEX_INITIALIZER;

int lookup_version = AUTOFS_LOOKUP_VERSION;	/* Required by protocol */

/* This initializes a context (persistent non-global data) for queries to
   this module. */
int lookup_init(const char *mapfmt, int argc, const char *const *argv, void **context)
{
	struct lookup_context *ctxt = NULL;
	char buf[MAX_ERR_BUF];

	*context = NULL;

	/* If we can't build a context, bail. */
	ctxt = malloc(sizeof(struct lookup_context));
	if (!ctxt) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "malloc: %s", estr);
		return 1;
	}

	/* Initialize the resolver. */
	res_init();

	/* Initialize the hesiod context. */
	if (hesiod_init(&(ctxt->hesiod_context)) != 0) {
		char *estr = strerror_r(errno, buf, MAX_ERR_BUF);
		logerr(MODPREFIX "hesiod_init(): %s", estr);
		free(ctxt);
		return 1;
	}

	/* If a map type isn't explicitly given, parse it as hesiod entries. */
	if (!mapfmt)
		mapfmt = MAPFMT_DEFAULT;

	/* Open the parser, if we can. */
	ctxt->parser = open_parse(mapfmt, MODPREFIX, argc - 1, argv + 1);
	if (!ctxt->parser) {
		logerr(MODPREFIX "failed to open parse context");
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

/*
 * Lookup and act on a filesystem name.  In this case, lookup the "filsys"
 * record in hesiod.  If it's an AFS or NFS filesystem, parse it out.  If
 * it's an ERR filesystem, it's an error message we should log.  Otherwise,
 * assume it's something we know how to deal with already (generic).
 */
int lookup_mount(struct autofs_point *ap, const char *name, int name_len, void *context)
{
	struct map_source *source;
	struct mapent_cache *mc;
	char **hes_result;
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int status, rv;
	char **record, *best_record = NULL, *p;
	int priority, lowest_priority = INT_MAX;	

	source = ap->entry->current;
	ap->entry->current = NULL;
	master_source_current_signal(ap->entry);

	mc = source->mc;

	debug(ap->logopt,
	      MODPREFIX "looking up root=\"%s\", name=\"%s\"",
	      ap->path, name);

	chdir("/");		/* If this is not here the filesystem stays
				   busy, for some reason... */

	status = pthread_mutex_lock(&hesiod_mutex);
	if (status)
		fatal(status);

	hes_result = hesiod_resolve(ctxt->hesiod_context, name, "filsys");
	if (!hes_result || !hes_result[0]) {
		/* Note: it is not clear to me how to distinguish between
		 * the "no search results" case and other failures.  --JM */
		error(ap->logopt,
		      MODPREFIX "key \"%s\" not found in map", name);
		status = pthread_mutex_unlock(&hesiod_mutex);
		if (status)
			fatal(status);
		return NSS_STATUS_NOTFOUND;
	}

	/* autofs doesn't support falling back to alternate records, so just
	   find the record with the lowest priority and hope it works.
	   -- Aaron Ucko <amu@alum.mit.edu> 2002-03-11 */
	for (record = hes_result; *record; ++record) {
	    p = strrchr(*record, ' ');
	    if ( p && isdigit(p[1]) ) {
		priority = atoi(p+1);
	    } else {
		priority = INT_MAX - 1;
	    }
	    if (priority < lowest_priority) {
		lowest_priority = priority;
		best_record = *record;
	    }
	}

	cache_writelock(mc);
	rv = cache_update(mc, source, name, best_record, time(NULL));
	cache_unlock(mc);
	if (rv == CHE_FAIL)
		return NSS_STATUS_UNAVAIL;

	debug(ap->logopt,
	      MODPREFIX "lookup for \"%s\" gave \"%s\"",
	      name, best_record);

	rv = ctxt->parser->parse_mount(ap, name, name_len, best_record,
				       ctxt->parser->context);

	hesiod_free_list(ctxt->hesiod_context, hes_result);

	status = pthread_mutex_unlock(&hesiod_mutex);
	if (status)
		fatal(status);

	/*
	 * Unavailable due to error such as module load fail 
	 * or out of memory, etc.
	 */
	if (rv == 1 || rv == -1)
		return NSS_STATUS_UNAVAIL;

	return NSS_STATUS_SUCCESS;
}

/* This destroys a context for queries to this module.  It releases the parser
   structure (unloading the module) and frees the memory used by the context. */
int lookup_done(void *context)
{
	struct lookup_context *ctxt = (struct lookup_context *) context;
	int rv = close_parse(ctxt->parser);

	hesiod_end(ctxt->hesiod_context);
	free(ctxt);
	return rv;
}
