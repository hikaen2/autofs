/* ----------------------------------------------------------------------- *
 *
 *  defaults.h - system initialization defaults.
 *
 *   Copyright 2006 Ian Kent <raven@themaw.net>
 *
 *   This program is free software; you can redistribute it and/or modify
 *   it under the terms of the GNU General Public License as published by
 *   the Free Software Foundation, Inc., 675 Mass Ave, Cambridge MA 02139,
 *   USA; either version 2 of the License, or (at your option) any later
 *   version.
 *
 *   This program is distributed in the hope that it will be useful,
 *   but WITHOUT ANY WARRANTY; without even the implied warranty of
 *   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *   GNU General Public License for more details.
 *
 * ----------------------------------------------------------------------- */

#ifndef DEFAULTS_H
#define DEFAULTS_H

#define DEFAULT_MASTER_MAP_NAME	"auto.master"

#define DEFAULT_TIMEOUT			600
#define DEFAULT_NEGATIVE_TIMEOUT	60
#define DEFAULT_MOUNT_WAIT		-1
#define DEFAULT_UMOUNT_WAIT		12
#define DEFAULT_BROWSE_MODE		1
#define DEFAULT_LOGGING			0

#define DEFAULT_LDAP_TIMEOUT		-1
#define DEFAULT_LDAP_NETWORK_TIMEOUT	8

#define DEFAULT_MAP_OBJ_CLASS		"nisMap"
#define DEFAULT_ENTRY_OBJ_CLASS		"nisObject"
#define DEFAULT_MAP_ATTR		"nisMapName"
#define DEFAULT_ENTRY_ATTR		"cn"
#define DEFAULT_VALUE_ATTR		"nisMapEntry"

#define DEFAULT_NFS_MOUNT_PROTOCOL	3
#define DEFAULT_APPEND_OPTIONS		1
#define DEFAULT_AUTH_CONF_FILE		AUTOFS_MAP_DIR "/autofs_ldap_auth.conf"

#define DEFAULT_MAP_HASH_TABLE_SIZE	1024

struct ldap_schema;
struct ldap_searchdn;

unsigned int defaults_read_config(unsigned int);
const char *defaults_get_master_map(void);
int defaults_master_set(void);
unsigned int defaults_get_timeout(void);
unsigned int defaults_get_negative_timeout(void);
unsigned int defaults_get_browse_mode(void);
unsigned int defaults_get_logging(void);
const char *defaults_get_ldap_server(void);
unsigned int defaults_get_ldap_timeout(void);
unsigned int defaults_get_ldap_network_timeout(void);
struct list_head *defaults_get_uris(void);
void defaults_free_uris(struct list_head *);
struct ldap_schema *defaults_get_default_schema(void);
struct ldap_schema *defaults_get_schema(void);
struct ldap_searchdn *defaults_get_searchdns(void);
void defaults_free_searchdns(struct ldap_searchdn *);
unsigned int defaults_get_mount_nfs_default_proto(void);
unsigned int defaults_get_append_options(void);
unsigned int defaults_get_mount_wait(void);
unsigned int defaults_get_umount_wait(void);
const char *defaults_get_auth_conf_file(void);
unsigned int defaults_get_map_hash_table_size(void);

#endif

