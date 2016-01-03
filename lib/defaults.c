/* ----------------------------------------------------------------------- *
 *
 *  defaults.h - system initialization defaults.
 *
 *   Copyright 2006 Ian Kent <raven@themaw.net> - All Rights Reserved
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version; incorporated herein by reference.
 *
 * ----------------------------------------------------------------------- */

#include <stdlib.h>
#include <stdio.h>
#include <ctype.h>
#include <string.h>

#include "list.h"
#include "defaults.h"
#include "lookup_ldap.h"
#include "log.h"
#include "automount.h"

#define DEFAULTS_CONFIG_FILE		AUTOFS_CONF_DIR "/autofs"
#define MAX_LINE_LEN			256

#define ENV_NAME_MASTER_MAP		"MASTER_MAP_NAME"

#define ENV_NAME_TIMEOUT		"TIMEOUT"
#define ENV_NAME_NEGATIVE_TIMEOUT	"NEGATIVE_TIMEOUT"
#define ENV_NAME_BROWSE_MODE		"BROWSE_MODE"
#define ENV_NAME_LOGGING		"LOGGING"

#define LDAP_URI			"LDAP_URI"
#define ENV_LDAP_TIMEOUT		"LDAP_TIMEOUT"
#define ENV_LDAP_NETWORK_TIMEOUT	"LDAP_NETWORK_TIMEOUT"

#define SEARCH_BASE			"SEARCH_BASE"

#define ENV_NAME_MAP_OBJ_CLASS		"MAP_OBJECT_CLASS"
#define ENV_NAME_ENTRY_OBJ_CLASS	"ENTRY_OBJECT_CLASS"
#define ENV_NAME_MAP_ATTR		"MAP_ATTRIBUTE"
#define ENV_NAME_ENTRY_ATTR		"ENTRY_ATTRIBUTE"
#define ENV_NAME_VALUE_ATTR		"VALUE_ATTRIBUTE"

#define ENV_MOUNT_NFS_DEFAULT_PROTOCOL	"MOUNT_NFS_DEFAULT_PROTOCOL"
#define ENV_APPEND_OPTIONS		"APPEND_OPTIONS"
#define ENV_MOUNT_WAIT			"MOUNT_WAIT"
#define ENV_UMOUNT_WAIT			"UMOUNT_WAIT"
#define ENV_AUTH_CONF_FILE		"AUTH_CONF_FILE"

#define ENV_MAP_HASH_TABLE_SIZE		"MAP_HASH_TABLE_SIZE"

static const char *default_master_map_name = DEFAULT_MASTER_MAP_NAME;
static const char *default_auth_conf_file  = DEFAULT_AUTH_CONF_FILE;

static char *get_env_string(const char *name)
{
	char *val, *res;

	val = getenv(name);
	if (!val)
		return NULL;

	res = strdup(val);
	if (!res)
		return NULL;

	return res;
}

static long get_env_number(const char *name)
{
	char *val;
	long res = -1;

	val = getenv(name);
	if (!val)
		return -1;

	if (isdigit(*val))
		res = atol(val);

	if (res < 0)
		return -1;

	return res;
}

static int get_env_yesno(const char *name)
{
	const char *val;
	int res = -1;

	val = getenv(name);
	if (!val)
		return -1;

	if (isdigit(*val))
		res = atoi(val);
	else if (!strcasecmp(val, "yes"))
		return 1;
	else if (!strcasecmp(val, "no"))
		return 0;

	return res;
}

/*
 * We've changed the key names so we need to check for the
 * config key and it's old name for backward conpatibility.
*/
static int check_set_config_value(const char *res, const char *name, const char *value, unsigned to_syslog)
{
	char *old_name;
	int ret;

	if (!strcasecmp(res, name)) {
		ret = setenv(name, value, 0);
		if (ret) {
			if (!to_syslog)
				fprintf(stderr,
				        "can't set config value for %s, "
					"error %d\n", name, ret);
			else
				logmsg("can't set config value for %s, "
				      "error %d", name, ret);
		}
		return 1;
	}

	old_name = alloca(strlen(name) + 9);
	strcpy(old_name, "DEFAULT_");
	strcat(old_name, name);

	if (!strcasecmp(res, old_name)) {
		ret = setenv(name, value, 0);
		if (ret) {
			if (!to_syslog)
				fprintf(stderr,
				        "can't set config value for %s, "
					"error %d\n", name, ret);
			else
				logmsg("can't set config value for %s, "
				      "error %d\n", name, ret);
		}
		return 1;
	}
	return 0;
}

static int parse_line(char *line, char **res, char **value)
{
	char *key, *val, *trailer;
	int len;

	key = line;

	if (*key == '#' || !isalpha(*key))
		return 0;

	while (*key && *key == ' ')
		key++;

	if (!key)
		return 0;

	if (!(val = strchr(key, '=')))
		return 0;

	*val++ = '\0';

	while (*val && (*val == '"' || isblank(*val)))
		val++;

	len = strlen(val);

	if (val[len - 1] == '\n') {
		val[len - 1] = '\0';
		len--;
	}

	trailer = strchr(val, '#');
	if (!trailer)
		trailer = val + len - 1;
	else
		trailer--;

	while (*trailer && (*trailer == '"' || isblank(*trailer)))
		*(trailer--) = '\0';;

	*res = key;
	*value = val;

	return 1;
}

void defaults_free_uris(struct list_head *list)
{
	struct list_head *next;
	struct ldap_uri *uri;

	if (list_empty(list)) {
		free(list);
		return;
	}

	next = list->next;
	while (next != list) {
		uri = list_entry(next, struct ldap_uri, list);
		next = next->next;
		list_del(&uri->list);
		free(uri->uri);
		free(uri);
	}
	free(list);

	return;
}

static unsigned int add_uris(char *value, struct list_head *list)
{
	char *str, *tok, *ptr = NULL;
	size_t len = strlen(value);

	str = alloca(len);
	if (!str)
		return 0;
	strcpy(str, value);

	tok = strtok_r(str, " ", &ptr);
	while (tok) {
		struct ldap_uri *new;
		char *uri;

		new = malloc(sizeof(struct ldap_uri));
		if (!new)
			continue;

		uri = strdup(tok);
		if (!uri)
			free(new);
		else {
			new->uri = uri;
			list_add_tail(&new->list, list);
		}

		tok = strtok_r(NULL, " ", &ptr);
	}

	return 1;
}

struct list_head *defaults_get_uris(void)
{
	FILE *f;
	char buf[MAX_LINE_LEN];
	char *res;
	struct list_head *list;

	f = open_fopen_r(DEFAULTS_CONFIG_FILE);
	if (!f)
		return NULL;

	list = malloc(sizeof(struct list_head));
	if (!list) {
		fclose(f);
		return NULL;
	}
	INIT_LIST_HEAD(list);

	while ((res = fgets(buf, MAX_LINE_LEN, f))) {
		char *key, *value;

		if (!parse_line(res, &key, &value))
			continue;

		if (!strcasecmp(res, LDAP_URI))
			add_uris(value, list);
	}

	if (list_empty(list)) {
		free(list);
		list = NULL;
	}

	fclose(f);
	return list;
}

/*
 * Read config env variables and check they have been set.
 *
 * This simple minded routine assumes the config file
 * is valid bourne shell script without spaces around "="
 * and that it has valid values.
 */
unsigned int defaults_read_config(unsigned int to_syslog)
{
	FILE *f;
	char buf[MAX_LINE_LEN];
	char *res;

	f = open_fopen_r(DEFAULTS_CONFIG_FILE);
	if (!f)
		return 0;

	while ((res = fgets(buf, MAX_LINE_LEN, f))) {
		char *key, *value;

		if (!parse_line(res, &key, &value))
			continue;

		if (check_set_config_value(key, ENV_NAME_MASTER_MAP, value, to_syslog) ||
		    check_set_config_value(key, ENV_NAME_TIMEOUT, value, to_syslog) ||
		    check_set_config_value(key, ENV_NAME_NEGATIVE_TIMEOUT, value, to_syslog) ||
		    check_set_config_value(key, ENV_NAME_BROWSE_MODE, value, to_syslog) ||
		    check_set_config_value(key, ENV_NAME_LOGGING, value, to_syslog) ||
		    check_set_config_value(key, ENV_LDAP_TIMEOUT, value, to_syslog) ||
		    check_set_config_value(key, ENV_LDAP_NETWORK_TIMEOUT, value, to_syslog) ||
		    check_set_config_value(key, ENV_NAME_MAP_OBJ_CLASS, value, to_syslog) ||
		    check_set_config_value(key, ENV_NAME_ENTRY_OBJ_CLASS, value, to_syslog) ||
		    check_set_config_value(key, ENV_NAME_MAP_ATTR, value, to_syslog) ||
		    check_set_config_value(key, ENV_NAME_ENTRY_ATTR, value, to_syslog) ||
		    check_set_config_value(key, ENV_NAME_VALUE_ATTR, value, to_syslog) ||
		    check_set_config_value(key, ENV_APPEND_OPTIONS, value, to_syslog) ||
		    check_set_config_value(key, ENV_MOUNT_WAIT, value, to_syslog) ||
		    check_set_config_value(key, ENV_UMOUNT_WAIT, value, to_syslog) ||
		    check_set_config_value(key, ENV_AUTH_CONF_FILE, value, to_syslog) ||
		    check_set_config_value(key, ENV_MAP_HASH_TABLE_SIZE, value, to_syslog) ||
		    check_set_config_value(key, ENV_MOUNT_NFS_DEFAULT_PROTOCOL, value, to_syslog))
			;
	}

	if (!feof(f) || ferror(f)) {
		if (!to_syslog) {
			fprintf(stderr,
				"fgets returned error %d while reading %s\n",
				ferror(f), DEFAULTS_CONFIG_FILE);
		} else {
			logmsg("fgets returned error %d while reading %s",
			      ferror(f), DEFAULTS_CONFIG_FILE);
		}
		fclose(f);
		return 0;
	}

	fclose(f);
	return 1;
}

const char *defaults_get_master_map(void)
{
	char *master;

	master = get_env_string(ENV_NAME_MASTER_MAP);
	if (!master)
		return strdup(default_master_map_name);

	return (const char *) master;
}

int defaults_master_set(void)
{
	char *val = getenv(ENV_NAME_MASTER_MAP);
	if (!val)
		return 0;

	return 1;
}

unsigned int defaults_get_timeout(void)
{
	long timeout;

	timeout = get_env_number(ENV_NAME_TIMEOUT);
	if (timeout < 0)
		timeout = DEFAULT_TIMEOUT;

	return (unsigned int) timeout;
}

unsigned int defaults_get_negative_timeout(void)
{
	long n_timeout;

	n_timeout = get_env_number(ENV_NAME_NEGATIVE_TIMEOUT);
	if (n_timeout <= 0)
		n_timeout = DEFAULT_NEGATIVE_TIMEOUT;

	return (unsigned int) n_timeout;
}

unsigned int defaults_get_browse_mode(void)
{
	int res;

	res = get_env_yesno(ENV_NAME_BROWSE_MODE);
	if (res < 0)
		res = DEFAULT_BROWSE_MODE;

	return res;
}

unsigned int defaults_get_logging(void)
{
	char *res;
	unsigned int logging = DEFAULT_LOGGING;

	res = get_env_string(ENV_NAME_LOGGING);
	if (!res)
		return logging;

	if (!strcasecmp(res, "none"))
		logging = DEFAULT_LOGGING;
	else {
		if (!strcasecmp(res, "verbose"))
			logging |= LOGOPT_VERBOSE;

		if (!strcasecmp(res, "debug"))
			logging |= LOGOPT_DEBUG;
	}

	free(res);

	return logging;
}

unsigned int defaults_get_ldap_timeout(void)
{
	int res;

	res = get_env_number(ENV_LDAP_TIMEOUT);
	if (res < 0)
		res = DEFAULT_LDAP_TIMEOUT;

	return res;
}

unsigned int defaults_get_ldap_network_timeout(void)
{
	int res;

	res = get_env_number(ENV_LDAP_NETWORK_TIMEOUT);
	if (res < 0)
		res = DEFAULT_LDAP_NETWORK_TIMEOUT;

	return res;
}

struct ldap_schema *defaults_get_default_schema(void)
{
	struct ldap_schema *schema;
	char *mc, *ma, *ec, *ea, *va;

	mc = strdup(DEFAULT_MAP_OBJ_CLASS);
	if (!mc)
		return NULL;

	ma = strdup(DEFAULT_MAP_ATTR);
	if (!ma) {
		free(mc);
		return NULL;
	}

	ec = strdup(DEFAULT_ENTRY_OBJ_CLASS);
	if (!ec) {
		free(mc);
		free(ma);
		return NULL;
	}

	ea = strdup(DEFAULT_ENTRY_ATTR);
	if (!ea) {
		free(mc);
		free(ma);
		free(ec);
		return NULL;
	}

	va = strdup(DEFAULT_VALUE_ATTR);
	if (!va) {
		free(mc);
		free(ma);
		free(ec);
		free(ea);
		return NULL;
	}

	schema = malloc(sizeof(struct ldap_schema));
	if (!schema) {
		free(mc);
		free(ma);
		free(ec);
		free(ea);
		free(va);
		return NULL;
	}

	schema->map_class = mc;
	schema->map_attr = ma;
	schema->entry_class = ec;
	schema->entry_attr = ea;
	schema->value_attr = va;

	return schema;
}

static struct ldap_searchdn *alloc_searchdn(const char *value)
{
	struct ldap_searchdn *sdn;
	char *val;

	sdn = malloc(sizeof(struct ldap_searchdn));
	if (!sdn)
		return NULL;

	val = strdup(value);
	if (!val) {
		free(sdn);
		return NULL;
	}

	sdn->basedn = val;
	sdn->next = NULL;

	return sdn;
}

void defaults_free_searchdns(struct ldap_searchdn *sdn)
{
	struct ldap_searchdn *this = sdn;
	struct ldap_searchdn *next;

	while (this) {
		next = this->next;
		free(this->basedn);
		free(this);
		this = next;
	}

	return;
}

struct ldap_searchdn *defaults_get_searchdns(void)
{
	FILE *f;
	char buf[MAX_LINE_LEN];
	char *res;
	struct ldap_searchdn *sdn, *last;

	f = open_fopen_r(DEFAULTS_CONFIG_FILE);
	if (!f)
		return NULL;

	sdn = last = NULL;

	while ((res = fgets(buf, MAX_LINE_LEN, f))) {
		char *key, *value;

		if (!parse_line(res, &key, &value))
			continue;

		if (!strcasecmp(key, SEARCH_BASE)) {
			struct ldap_searchdn *new = alloc_searchdn(value);

			if (!new) {
				defaults_free_searchdns(sdn);
				fclose(f);
				return NULL;
			}

			if (!last)
				last = new;
			else {
				last->next = new;
				last = new;
			}

			if (!sdn)
				sdn = new;
		}
	}

	fclose(f);
	return sdn;
}

struct ldap_schema *defaults_get_schema(void)
{
	struct ldap_schema *schema;
	char *mc, *ma, *ec, *ea, *va;

	mc = get_env_string(ENV_NAME_MAP_OBJ_CLASS);
	if (!mc)
		return NULL;

	ma = get_env_string(ENV_NAME_MAP_ATTR);
	if (!ma) {
		free(mc);
		return NULL;
	}

	ec = get_env_string(ENV_NAME_ENTRY_OBJ_CLASS);
	if (!ec) {
		free(mc);
		free(ma);
		return NULL;
	}

	ea = get_env_string(ENV_NAME_ENTRY_ATTR);
	if (!ea) {
		free(mc);
		free(ma);
		free(ec);
		return NULL;
	}

	va = get_env_string(ENV_NAME_VALUE_ATTR);
	if (!va) {
		free(mc);
		free(ma);
		free(ec);
		free(ea);
		return NULL;
	}

	schema = malloc(sizeof(struct ldap_schema));
	if (!schema) {
		free(mc);
		free(ma);
		free(ec);
		free(ea);
		free(va);
		return NULL;
	}

	schema->map_class = mc;
	schema->map_attr = ma;
	schema->entry_class = ec;
	schema->entry_attr = ea;
	schema->value_attr = va;

	return schema;
}

unsigned int defaults_get_mount_nfs_default_proto(void)
{
	long proto;

	proto = get_env_number(ENV_MOUNT_NFS_DEFAULT_PROTOCOL);
	if (proto < 2 || proto > 4)
		proto = DEFAULT_NFS_MOUNT_PROTOCOL;

	return (unsigned int) proto;
}

unsigned int defaults_get_append_options(void)
{
	int res;

	res = get_env_yesno(ENV_APPEND_OPTIONS);
	if (res < 0)
		res = DEFAULT_APPEND_OPTIONS;

	return res;
}

unsigned int defaults_get_mount_wait(void)
{
	long wait;

	wait = get_env_number(ENV_MOUNT_WAIT);
	if (wait < 0)
		wait = DEFAULT_MOUNT_WAIT;

	return (unsigned int) wait;
}

unsigned int defaults_get_umount_wait(void)
{
	long wait;

	wait = get_env_number(ENV_UMOUNT_WAIT);
	if (wait < 0)
		wait = DEFAULT_UMOUNT_WAIT;

	return (unsigned int) wait;
}

const char *defaults_get_auth_conf_file(void)
{
	char *cf;

	cf = get_env_string(ENV_AUTH_CONF_FILE);
	if (!cf)
		return strdup(default_auth_conf_file);

	return (const char *) cf;
}

unsigned int defaults_get_map_hash_table_size(void)
{
	long size;

	size = get_env_number(ENV_MAP_HASH_TABLE_SIZE);
	if (size < 0)
		size = DEFAULT_MAP_HASH_TABLE_SIZE;

	return (unsigned int) size;
}

