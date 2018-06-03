/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2018 The OpenLDAP Foundation.
 * Portions Copyright 2018 Symas Corporation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the
 * GNU General Public License version 3, as published by the
 * the Free Software Foundation;
 *
 * A copy of this license is available at
 * <http://www.gnu.org/licenses/>.
 */

#ifndef SAMBA_UTILS_H
#define SAMBA_UTILS_H

#include "portable.h"
#include "slap.h"
#include "config.h"
#include "samba_security.h"
#include "ldb.h"
#include "ndr.h"
#include "gen_ndr/security.h"

typedef struct ConnExtraToken {
	ConnExtra ce;
	struct security_token token;
	DATA_BLOB* ndr_token;
} ConnExtraToken;

bool
samba_is_trusted_connection( Operation *op );

AttributeDescription*
samba_find_attr_description( const char *attr_name );

int
samba_set_partitions_db_pointers( BackendDB *be );

BackendDB *get_schema_db();
BackendDB *get_domain_db();
BackendDB *get_config_db();

int
samba_get_parent_sd( Operation *op,
		     SlapReply *rs,
		     struct berval *instanceType,
		     struct berval *parent_sd );

SD_PARTITION
samba_get_partition_flag( Operation *op );

int
samba_get_domain_sid_bv( Operation *op, SlapReply *rs, struct berval *domain_sid );

int
samba_get_next_rid( Operation *op, SlapReply *rs );

void
samba_attr_delvals( Attribute *a );

int
samba_add_time_val( Entry *e, char *name, time_t value );

int
samba_add_guid_val( Entry *e, char *name, struct GUID *guid );

int
samba_add_int64_val( Entry *e, char *name, int64_t value );

int
samba_add_uint64_val( Entry *e, char *name, uint64_t value );

int
samba_add_sid_val( Entry *e, char *name, struct dom_sid *sid, TALLOC_CTX *tmp_ctx );

int
samba_timestring( struct berval *val, time_t t );

Attribute *
samba_find_attribute( Attribute *attr_list, const char *attr_name );

Modification *
samba_find_modification( Modifications *mod_list, const char *attr_name );

int
samba_find_attribute_int( Attribute *attr_list,
			  const char *attr_name,
			  int default_val,
			  int index);

bool
samba_as_system( Operation *op );

struct dom_sid *
samba_get_domain_sid( Operation *op, SlapReply *rs, TALLOC_CTX *talloc_mem_ctx );

struct security_token *
samba_get_token_from_connection( Operation *op );

struct ad_schema_class *
samba_get_structural_class( Operation *op );

struct security_descriptor *
samba_get_object_sd( Operation *op, SlapReply *rs, TALLOC_CTX *mem_ctx );

struct security_descriptor *
samba_get_new_parent_sd( Operation *op, SlapReply *rs, TALLOC_CTX *mem_ctx );

/* opprep o_extra - will likely be unnecessary */
typedef struct opprep_info_add {
	struct berval parent_sd;
	struct berval object_guid;
}opprep_info_add;

typedef struct opprep_info_search {
	struct berval parent_sd;
	struct berval object_guid;
}opprep_info_search;

typedef struct opprep_info_mod {
	struct berval object_class;
	struct berval instanceType;
	struct berval sd;
}opprep_info_mod;

typedef struct opprep_info_modrdn {
	struct berval parent_sd;
	struct berval new_parent_sd;
}opprep_info_modrdn;

typedef struct opprep_info_del {
	struct berval parent_sd;
	struct berval object_sd;
}opprep_info_del;

typedef union opprep_un {
	opprep_info_add    add;
	opprep_info_mod    mod;
	opprep_info_modrdn modrdn;
	opprep_info_del    del;
	opprep_info_search search;
}opprep_un;

typedef struct opprep_info {
	struct dsdb_schema *schema;
	uint32_t internal_flags;
	uint32_t sd_flags;
	DATA_BLOB *sec_token;
	bool is_trusted;
	opprep_un un; 
} opprep_info_t;

const char *opprep_id = "opprep";

typedef struct OpExtraOpprep {
	OpExtra oe;
	opprep_info_t *oe_opi;
} OpExtraOpprep;

const char *token_id = "token";

typedef struct TokenExtra {
	ConnExtra ce;
	struct security_token *token;
} TokenExtra;

/* defined as in samba's samdb.h, which is not public at the moment.
 * We will have the same problem for any internal controls of samba
 * that we might want to accept for some reason.
 * TODO we must have only one definition of this                  */
#define DSDB_CONTROL_SEC_TOKEN_OID "1.3.6.1.4.1.7165.4.3.22"


/* TODO this is copied from dom_sid.h, security.h and access_check.h. Fix it by either making it public
 * or fix the makefile here to have a path to samba source */
struct dom_sid *dom_sid_parse_length(TALLOC_CTX *mem_ctx, const DATA_BLOB *sid);
struct dom_sid *dom_sid_add_rid(TALLOC_CTX *mem_ctx,
				const struct dom_sid *domain_sid,
				uint32_t rid);

struct object_tree {
	uint32_t remaining_access;
	struct GUID guid;
	int num_of_children;
	struct object_tree *children;
};

bool insert_in_object_tree(TALLOC_CTX *mem_ctx,
			   const struct GUID *guid,
			   uint32_t init_access,
			   struct object_tree *root,
			   struct object_tree **new_node_out);

NTSTATUS sec_access_check_ds(const struct security_descriptor *sd,
			     const struct security_token *token,
			     uint32_t access_desired,
			     uint32_t *access_granted,
			     struct object_tree *tree,
			     struct dom_sid *replace_sid);

NTSTATUS unmarshall_sec_desc(TALLOC_CTX *mem_ctx, uint8_t *data, size_t len,
			     struct security_descriptor **psecdesc);

bool sid_to_blob(TALLOC_CTX *mem_ctx, struct dom_sid *sid,
		 DATA_BLOB *out);
#endif /*SAMBA_UTILS_H*/
