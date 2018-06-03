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

/* This file contains data common to samba4 overlays and access
   and helper functions */

#include "portable.h"
#include <stdio.h>

#include "ac/string.h"
#include "ac/socket.h"

#include "slap.h"
#include "config.h"

#include "lutil.h"
#include "ldap_rq.h"
#include "ldb.h"
#include "talloc.h"
#include "samba_security.h"
#include "core/werror.h"
#include "samba_utils.h"
#include "flags.h"
#include "ndr.h"

/* pointers to databases of the commonly used partitions */
static 	BackendDB	*schema_db = NULL;
static 	BackendDB	*config_db = NULL;
static 	BackendDB	*domain_db = NULL;

/*Todo this is a hack - move that info to cn=config */

int
samba_set_partitions_db_pointers( BackendDB *be )
{
	/* find the configuration, schema and domain naming context db's.
	 * probably not the best way to do this, change when changes to root_dse are done */
	struct berval config_rdn;
	struct berval schema_rdn;
	struct berval domain_dn;
	struct berval rdn;
	config_rdn.bv_val = "cn=configuration";
	config_rdn.bv_len = strlen( config_rdn.bv_val );
	schema_rdn.bv_val = "cn=schema";
	schema_rdn.bv_len = strlen( schema_rdn.bv_val );
	dnRdn( be->be_nsuffix, &rdn );
	if ( ber_bvcmp( &config_rdn, &rdn ) == 0 ) {
		if ( config_db == NULL ) {
			config_db = select_backend( &be->be_nsuffix[0], 0 );
		}
		if ( domain_db == NULL ) {
			dnParent( &be->be_nsuffix[0], &domain_dn );
			domain_db = select_backend( &domain_dn, 0 );
		}
		return 0;
	}
	if ( schema_db == NULL && ber_bvcmp( &schema_rdn, &rdn ) == 0 ) {
		schema_db = select_backend( &be->be_nsuffix[0], 0 );
	}
	return 0;
}

BackendDB *
samba_get_schema_db()
{
	/* should not be used unless initialized */
	assert( schema_db != NULL );
	return schema_db;
}

BackendDB *
samba_get_domain_db()
{
	/* should not be used unless initialized */
	assert( domain_db != NULL );
	return domain_db;
}

BackendDB *
samba_get_config_db()
{
	/* should not be used unless initialized */
	assert( config_db != NULL );
	return config_db;
}


/* This is a local samba connection */
bool
samba_is_trusted_connection( Operation *op )
{
	struct berval sl_name;
	sl_name.bv_val = "PATH=/usr/local/samba/private/ldap/ldapi"; /*todo make this configurable, this is a hack*/
	sl_name.bv_len = strlen( sl_name.bv_val );
	return ( ber_bvcmp( &sl_name, &op->o_hdr->oh_conn->c_listener->sl_name ) == 0 );
}

bool
samba_as_system( Operation *op )
{
	/* for the time being assume samba's slapi connection is system,
	   which makes it exempt from access checks and some other things,
	   should also use the token*/
	return samba_is_trusted_connection( op );
}
struct berval *
samba_aggregate_schema_dn( void *memctx ) 
{
	struct berval aggregate;
	struct berval *new_dn = (struct berval *)slap_sl_malloc( sizeof( struct berval ), memctx );
	ber_str2bv( "CN=Aggregate", STRLENOF( "CN=Aggregate" ), 1, &aggregate );
	build_new_dn( new_dn, &schema_db->be_nsuffix[0], &aggregate, memctx );
	return new_dn;
}

AttributeDescription *
samba_find_attr_description( const char *attr_name )
{
	int rc;
	const char *text = NULL;
	AttributeDescription *attr_description = NULL;
	rc = slap_str2ad( attr_name, &attr_description, &text );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
		       "samba_find_attr_description: Failed to find description of %s (%d), %s\n",
		       attr_name, rc, text );
		return NULL;
	}
	return attr_description;
}

Attribute *
samba_find_attribute( Attribute *attr_list, const char *attr_name )
{
	AttributeDescription *attr_descr = NULL;
	attr_descr = samba_find_attr_description( attr_name );
	if ( attr_descr == NULL ) {
		return NULL;
	}
	return attr_find( attr_list, attr_descr );
}


Modification *
samba_find_modification( Modifications *mod_list, const char *attr_name )
{
	AttributeDescription *attr_descr = NULL;
	Modifications *ml;
	attr_descr = samba_find_attr_description( attr_name );
	if ( attr_descr == NULL ) {
		return NULL;
	}
	for ( ml = mod_list; ml != NULL; ml = ml->sml_next ) {
		if ( ml->sml_mod.sm_desc == attr_descr ) {
			return &ml->sml_mod;
		}
	}
	return NULL;
}

int
samba_find_attribute_int( Attribute *attr_list, const char *attr_name,
			  int default_val, int index )
{
	Attribute *attr = samba_find_attribute( attr_list, attr_name );
	if ( attr == NULL || attr->a_numvals < index+1 ) {
		return default_val;
	}
	return (int)strtol( attr->a_vals[index].bv_val,0,0 );
}


int
samba_timestring( struct berval *val, time_t t )
{
	struct tm *tm = gmtime( &t );
	char ts[18];
	int r;
	if (!tm) {
		return LDAP_OPERATIONS_ERROR;
	}
	
	/* formatted like: 20040408072012.0Z */
	r = snprintf( ts, 18,
		      "%04u%02u%02u%02u%02u%02u.0Z",
		      tm->tm_year+1900, tm->tm_mon+1,
		      tm->tm_mday, tm->tm_hour, tm->tm_min,
		      tm->tm_sec );
	
	if ( r != 17 ) {
		return LDAP_OPERATIONS_ERROR;
	}
	
	*val = *( ber_bvstr( ts ) );
	return LDAP_SUCCESS;
}

int
samba_get_parent_sd ( Operation *op,
		      SlapReply *rs,
		      struct berval *instanceType,
		      struct berval *parent_sd )
{
	int flags_val = (int)strtol( instanceType->bv_val,0,0 );
	Entry *e = NULL;
	struct berval p_dn;
	int rc;
	Attribute *sd_att;
	slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
	BackendInfo *o_op_info = op->o_bd->bd_info;

	op->o_bd->bd_info = (BackendInfo *)on->on_info->oi_orig;
	assert(parent_sd != NULL);

	if ( flags_val & INSTANCE_TYPE_IS_NC_HEAD ) {
		/* this is a naming context, it has no parent */
		op->o_bd->bd_info = o_op_info;
		return LDAP_SUCCESS;
	}

	dnParent( &op->o_req_ndn, &p_dn );

	rc = be_entry_get_rw( op, &p_dn, NULL, NULL, 0, &e );
	if ( rc != LDAP_SUCCESS ) {
		op->o_bd->bd_info = o_op_info;
		return rc;
	}

	sd_att = attr_find( e->e_attrs, slap_schema.si_ad_nTSecurityDescriptor );

	if (sd_att != NULL && sd_att->a_vals != NULL) {
		ber_dupbv_x( parent_sd, &(sd_att->a_vals[0]), op->o_tmpmemctx );
	}

	be_entry_release_r( op, e );
	op->o_bd->bd_info = o_op_info;
	return LDAP_SUCCESS;
}


/* determine which partition for the sake of finding default owner */
SD_PARTITION
samba_get_partition_flag( Operation *op )
{
	SD_PARTITION partition;	
	if ( op->o_bd->bd_self == domain_db ) {
		partition = SD_PARTITION_DEFAULT;
	}
	else if ( op->o_bd->bd_self == config_db ) {
		partition = SD_PARTITION_CONFIG;
	}
	else if ( op->o_bd->bd_self == schema_db ) {
		partition = SD_PARTITION_SCHEMA;
	}
	else  {
		partition = SD_PARTITION_OTHER;
	}
	return partition;
}

/* get the domain sid as struct berval */
int
samba_get_domain_sid_bv( Operation *op, SlapReply *rs, struct berval *domain_sid )
{
	Entry		*e = NULL;
	Attribute *sid_att = NULL;
	AttributeDescription *sid_d = samba_find_attr_description( "objectSid" );
	int rc;	
	BackendDB	*orig_db = op->o_bd;
	op->o_bd = domain_db;

	rc = be_entry_get_rw( op, &domain_db->be_nsuffix[0], NULL, NULL, 0, &e );
	if ( rc != LDAP_SUCCESS ) {
		op->o_bd = orig_db;
		return rc;
	}

	sid_att = attr_find( e->e_attrs, sid_d );

	if ( sid_att != NULL && sid_att->a_vals != NULL ) {
		ber_dupbv_x( domain_sid, &(sid_att->a_vals[0]), op->o_tmpmemctx );
	}
	be_entry_release_r( op, e );
	op->o_bd = orig_db;
	return LDAP_SUCCESS;
}

struct dom_sid *
samba_get_domain_sid( Operation *op, SlapReply *rs, TALLOC_CTX *talloc_mem_ctx )
{
	struct berval ds_bv;
	DATA_BLOB blob_ds;
	struct dom_sid *sid;
	samba_get_domain_sid_bv( op, rs, &ds_bv );
	blob_ds.length = ds_bv.bv_len;
	blob_ds.data = ds_bv.bv_val;
	sid = dom_sid_parse_length( talloc_mem_ctx, &blob_ds );
	return sid;
}
/* Obviously this is not how this should happen, this needs to be protected and also proper rid
 * pool allocation needs to happen */
int
samba_get_next_rid( Operation *op, SlapReply *rs )
{
	Entry *e = NULL;
	int next_rid = 0;

	int rc;	
	BackendDB	*orig_db = op->o_bd;
	op->o_bd = domain_db;

	rc = be_entry_get_rw( op, &domain_db->be_nsuffix[0], NULL, NULL, 0, &e );
	if ( rc != LDAP_SUCCESS ) {
		op->o_bd = orig_db;
		return rc;
	}
	next_rid = samba_find_attribute_int( e->e_attrs, "nextRid", 0, 0 );
	be_entry_release_r( op, e );
	op->o_bd = orig_db;
	return next_rid;
}

/* Remove all values of an attribute - only used when it is necessary to
 * replace the value(s) of an attribute. Very similar to attr_cleanup but
 * we want to keep the attribute description  */
void
samba_attr_delvals( Attribute *a )
{
	if ( a->a_nvals && a->a_nvals != a->a_vals &&
	     !( a->a_flags & SLAP_ATTR_DONT_FREE_VALS )) {
		if ( a->a_flags & SLAP_ATTR_DONT_FREE_DATA ) {
			free( a->a_nvals );
		} else {
			ber_bvarray_free( a->a_nvals );
		}
	}

	if ( a->a_vals != &slap_dummy_bv &&
	     !( a->a_flags & SLAP_ATTR_DONT_FREE_VALS )) {
		if ( a->a_flags & SLAP_ATTR_DONT_FREE_DATA ) {
			free( a->a_vals );
		} else {
			ber_bvarray_free( a->a_vals );
		}
	}
	a->a_vals = NULL;
	a->a_nvals = NULL;
	a->a_numvals = 0;
}

/*Some functions for adding values to an ora->e entry */
int
samba_add_time_val( Entry *e, char *name, time_t value )
{
	struct berval val;
	int rc;
	AttributeDescription *descr = samba_find_attr_description(name);
	if (descr == NULL) {
		return LDAP_NO_SUCH_ATTRIBUTE;
	}
	if ( (rc = samba_timestring( &val, value )) != LDAP_SUCCESS ) {
		return rc;
	}

	attr_merge_one( e, descr, &val, NULL );
	return LDAP_SUCCESS;
}

int
samba_add_guid_val( Entry *e, char *name, struct GUID *guid )
{
	struct ldb_val v;
	NTSTATUS status;
	TALLOC_CTX *tmp_ctx;
	struct berval guid_val = { 0, NULL };
	AttributeDescription *descr = samba_find_attr_description( name );
	if ( descr == NULL ) {
		return LDAP_NO_SUCH_ATTRIBUTE;
	}
	tmp_ctx = talloc_init( NULL );

	status = GUID_to_ndr_blob( guid, tmp_ctx, &v );
	if ( !NT_STATUS_IS_OK(status) ) {
		talloc_free( tmp_ctx );
		return LDAP_OPERATIONS_ERROR;
	}
	guid_val.bv_len = v.length;
	guid_val.bv_val = (char *)v.data;
	/* does not seem like we have to copy as attr_merge_one does a copy */
	attr_merge_one( e, descr, &guid_val, NULL );
	talloc_free( tmp_ctx );
	return LDAP_SUCCESS;
}

int
samba_add_sid_val( Entry *e, char *name, struct dom_sid *sid, TALLOC_CTX *tmp_ctx )
{
	struct ldb_val v;
	struct berval sid_val = { 0, NULL };
	AttributeDescription *descr = samba_find_attr_description( name );
	if ( descr == NULL ) {
		return LDAP_NO_SUCH_ATTRIBUTE;
	}

	if ( !(sid_to_blob( tmp_ctx, sid, &v )) ) {
		return LDAP_OPERATIONS_ERROR;
	}
	
	sid_val.bv_len = v.length;
	sid_val.bv_val = (char *)v.data;

	attr_merge_one( e, descr, &sid_val, NULL );

	return LDAP_SUCCESS;
}

int
samba_add_int64_val( Entry *e, char *name, int64_t value )
{
	char val_buf[ LDAP_PVT_INTTYPE_CHARS( long long ) ];
	int val_len = sprintf( val_buf, "%lld", (long long) value );
	struct berval *val = NULL;
	AttributeDescription *descr = samba_find_attr_description( name );
	if ( descr == NULL ) {
		return LDAP_NO_SUCH_ATTRIBUTE;
	}
	if ( val_len <= 0 ) {
		return LDAP_OPERATIONS_ERROR;
	}
	val = ber_bvstr( val_buf );
	attr_merge_one( e, descr, val, NULL );
	return LDAP_SUCCESS;
}

int
samba_add_uint64_val( Entry *e, char *name, uint64_t value )
{
	return samba_add_int64_val( e, name, (int64_t) value );
}

struct security_token *
samba_get_token_from_connection( Operation *op )
{
	ConnExtra *extra;
	struct security_token *token = NULL;
	LDAP_SLIST_FOREACH( extra, &op->o_conn->conn_extra, ce_next ) {
		if ( extra->ce_key == (void *)token_id ) {
			token = ( (TokenExtra*)extra )->token;
			break;
		}
	}
	return token;
}

/* TODO this is overly simplified, we must implement
 * object class sorting, and check objectClassCategory */
struct ad_schema_class *
samba_get_structural_class( Operation *op )
{
	Attribute *at_objectClass = samba_find_attribute( op->ora_e->e_attrs, "objectClass" );
	ObjectClass *oc;
	struct ad_schema_class *objectclass = NULL;

	assert( at_objectClass != 0 );
	
	oc = oc_find( at_objectClass->a_vals[at_objectClass->a_numvals-1].bv_val );
	assert ( oc != NULL );

	objectclass = (struct ad_schema_class *)oc->oc_private;
	return objectclass;
}

struct security_descriptor *
samba_get_object_sd( Operation *op, SlapReply *rs, TALLOC_CTX *mem_ctx )
{
	Entry		*e = NULL;
	Attribute *sd_att = NULL;
	int rc;
	slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
	BackendInfo *o_op_info = op->o_bd->bd_info;
	struct security_descriptor *sd = NULL;

	op->o_bd->bd_info = (BackendInfo *)on->on_info->oi_orig;
	rc = be_entry_get_rw( op, &op->o_req_ndn, NULL, NULL, 0, &e );
	if ( rc != LDAP_SUCCESS ) {
		op->o_bd->bd_info = o_op_info;
		return sd;
	}

	sd_att = attr_find( e->e_attrs, slap_schema.si_ad_nTSecurityDescriptor );

	if ( sd_att != NULL && sd_att->a_vals != NULL ) {
		unmarshall_sec_desc( mem_ctx, sd_att->a_vals[0].bv_val, sd_att->a_vals[0].bv_len, &sd );
	}

	be_entry_release_r( op, e );
	op->o_bd->bd_info = o_op_info;
	return sd;
}

struct security_descriptor *
samba_get_new_parent_sd( Operation *op, SlapReply *rs, TALLOC_CTX *mem_ctx )
{
	Entry		*e = NULL;
	Attribute *sd_att = NULL;
	int rc;
	struct berval parent_dn = { 0, NULL };
	slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
	BackendInfo *o_op_info = op->o_bd->bd_info;
	struct security_descriptor *sd = NULL;

	dnParent( &parent_dn, &op->o_req_ndn );
	op->o_bd->bd_info = (BackendInfo *)on->on_info->oi_orig;
	rc = be_entry_get_rw( op, &parent_dn, NULL, NULL, 0, &e );
	if ( rc != LDAP_SUCCESS ) {
		op->o_bd->bd_info = o_op_info;
		return sd;
	}

	sd_att = attr_find( e->e_attrs, slap_schema.si_ad_nTSecurityDescriptor );

	if (sd_att != NULL && sd_att->a_vals != NULL) {
		unmarshall_sec_desc( mem_ctx, sd_att->a_vals[0].bv_val, sd_att->a_vals[0].bv_len, &sd );
	}

	be_entry_release_r( op, e );
	op->o_bd->bd_info = o_op_info;
	return sd;
}


