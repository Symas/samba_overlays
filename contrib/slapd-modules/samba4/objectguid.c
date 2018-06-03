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

/* an overlay responsible for the creation of objectguid, objectSid, whenCreated, whenChanged and
   instanceType attributes */

#include "portable.h"
#ifdef SLAPD_OVER_OBJECTGUID

#include <stdio.h>

#include "ac/string.h"
#include "ac/socket.h"

#include "slap.h"
#include "config.h"

#include "lutil.h"
#include "ldap_rq.h"
#include "ldb.h"
#include "samba_security.h"
#include <ndr.h>
#include "samba_utils.h"
#include "flags.h"

static slap_overinst 		objectguid;

static int objectguid_add_instancetype( Operation *op, SlapReply *rs )
{
	Attribute *instance_attribute = NULL;
	AttributeDescription *instancetype_descr = NULL;
	int rc;
	const char *text = NULL;

	rc = slap_str2ad( "instanceType", &instancetype_descr, &text );
	if ( rc != LDAP_SUCCESS ) {
		send_ldap_error( op, rs, LDAP_NO_SUCH_ATTRIBUTE,
					"unable to find attribute 'instanceType'" );
			return rs->sr_err;
	}
	instance_attribute = attr_find( op->ora_e->e_attrs, instancetype_descr);
	if ( instance_attribute == NULL ) {
		int instance_flags = INSTANCE_TYPE_WRITE;
		char itflags_buf[ LDAP_PVT_INTTYPE_CHARS( unsigned long ) ];
		int itflags_len = sprintf(itflags_buf, "%0X", instance_flags);
		struct berval it_val;

		if (itflags_len <= 0) {
			send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
					"Error creating instanceType." );
			return rs->sr_err;
		}
		ber_str2bv(itflags_buf, 0, 1, &it_val );

		attr_merge_one(op->ora_e, instancetype_descr, &it_val, NULL);
		return SLAP_CB_CONTINUE;

	}
	else {
		if (instance_attribute->a_numvals != 1) {
			send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
					"instanceType is a single-valued attribute." );
			return rs->sr_err;
		}
		int flags_val = (int)strtol(instance_attribute->a_vals[0].bv_val,0,0);
		if (flags_val & INSTANCE_TYPE_IS_NC_HEAD) {
			if (!(flags_val & INSTANCE_TYPE_WRITE)) {
				send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
					"NC_HEAD is only compatible with WRITE" );
				return rs->sr_err;
			}
		}
		// only 0 and INSTANCE_TYPE_WRITE allowed
		else if ((flags_val !=0) && (flags_val != INSTANCE_TYPE_WRITE)) {
			send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
					"NC_HEAD is only compatible with WRITE" );
			return rs->sr_err;
		}
		return SLAP_CB_CONTINUE;
	}

	return SLAP_CB_CONTINUE;
}

static int
objectguid_update_nextrid(
	Operation *op,
	int new_rid)
{
	Connection conn = {0};
	OperationBuffer opbuf;
	Operation *new_op;
	SlapReply rs = {REP_RESULT};
	void *thrctx;
	AttributeDescription *ad_nextRid;
	Modifications mod;
	slap_callback cb = {0};
	char intbuf[64];
	struct berval bv[2];
	slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
	if ((ad_nextRid = samba_find_attr_description( "nextRid" )) == NULL) {
		return -1;
	}
	thrctx = ldap_pvt_thread_pool_context();
	connection_fake_init( &conn, &opbuf, thrctx );
	new_op = &opbuf.ob_op;
	/* TODO this should select the domain backend but its fine for now */
	new_op->o_bd = op->o_bd;
	BER_BVZERO( &bv[1] );
	bv[0].bv_len = snprintf( intbuf, sizeof(intbuf), "%d", new_rid );
	bv[0].bv_val = intbuf;
	mod.sml_numvals = 1;
	mod.sml_values = bv;
	mod.sml_nvalues = NULL;
	mod.sml_desc = ad_nextRid;
	mod.sml_op = LDAP_MOD_REPLACE;
	mod.sml_flags = 0;
	mod.sml_next = NULL;

	cb.sc_response = slap_null_cb;
	new_op->o_tag = LDAP_REQ_MODIFY;
	new_op->o_callback = &cb;
	new_op->orm_modlist = &mod;
	new_op->orm_no_opattrs = 1;
	new_op->o_dn = op->o_bd->be_rootdn;
	new_op->o_ndn = op->o_bd->be_rootndn;
	new_op->o_req_dn = new_op->o_bd->be_suffix[0];
	new_op->o_req_ndn = new_op->o_bd->be_nsuffix[0];
	new_op->o_bd->bd_info = on->on_info->oi_orig;
	new_op->o_managedsait = SLAP_CONTROL_NONCRITICAL;
	new_op->o_no_schema_check = 1;
	new_op->o_bd->be_modify( new_op, &rs );
	if ( mod.sml_next != NULL ) {
		slap_mods_free( mod.sml_next, 1 );
	}
	return 0;
}

static int 
objectguid_add_SID( Operation *op, SlapReply *rs )
{
	Attribute *sid_attribute = NULL;
	TALLOC_CTX *talloc_mem_ctx = talloc_new(NULL);
	int rc;
	struct dom_sid *sid;
	struct dom_sid *domain_sid;
	struct berval ds_bv;
	DATA_BLOB blob_ds;
	int rid, next_rid;

	Debug(LDAP_DEBUG_ANY, "objectguid_add_SID\n",0,0,0);
	sid_attribute  = samba_find_attribute(op->ora_e->e_attrs, "objectSID");
	if (sid_attribute != NULL) {
	        if (!samba_is_trusted_connection(op)) {
			send_ldap_error( op, rs, LDAP_CONSTRAINT_VIOLATION,
					 "objectSid cannot be provided" );
			talloc_free(talloc_mem_ctx);
			return LDAP_CONSTRAINT_VIOLATION;
		}
		return LDAP_SUCCESS;
	}

	/* TODO - this is just a kludge for now. Getting the next rid,
	 * setting the object sid and updating nextRid needs to happen in a transaction
	 * and probably implemented differently */
	samba_get_domain_sid_bv(op, rs, &ds_bv);
	blob_ds.length = ds_bv.bv_len;
	blob_ds.data = ds_bv.bv_val;
	domain_sid = dom_sid_parse_length(talloc_mem_ctx, &blob_ds);
	rid = samba_get_next_rid(op, rs);
	sid = dom_sid_add_rid(talloc_mem_ctx, domain_sid, rid);
	rc = samba_add_sid_val(op->ora_e, "objectSid", sid, talloc_mem_ctx );
	if (rc != LDAP_SUCCESS) {
		send_ldap_error( op, rs, rc,
				 "Error creating objectSID." );
		talloc_free(talloc_mem_ctx);
		return rs->sr_err;
	}
	next_rid = rid++;

	objectguid_update_nextrid( op, next_rid );

	talloc_free(talloc_mem_ctx);
	return LDAP_SUCCESS;
}

static int
objectguid_add_guid( Operation *op, SlapReply *rs )
{
	Attribute *objectguid_attribute = NULL;
	int rc;
	struct GUID guid;

	objectguid_attribute = samba_find_attribute(op->ora_e->e_attrs, "objectGUID");

	if (objectguid_attribute != NULL) {
		 if (!samba_is_trusted_connection(op)) {
			send_ldap_error( op, rs, LDAP_CONSTRAINT_VIOLATION,
					 "objectGUID cannot be provided" );
			return LDAP_CONSTRAINT_VIOLATION;
		}
		return LDAP_SUCCESS;
	}

	guid = GUID_random();
    
	rc = samba_add_guid_val(op->ora_e, "objectGUID", &guid);

	if (rc != LDAP_SUCCESS) {
			send_ldap_error( op, rs, rc,
					"Error creating objectGUID." );
			return rs->sr_err;
	}
	return LDAP_SUCCESS;
}

static int objectguid_add_when( Operation *op, SlapReply *rs )
{
	int rc;
	time_t t = time(NULL); 

	rc = samba_add_time_val(op->ora_e, "whenChanged", t);
	if ( rc != LDAP_SUCCESS ) {
		send_ldap_error( op, rs, rc,
					"objectguid:unable to set attribute 'whenChanged'" );
			return rs->sr_err;
	}

	rc = samba_add_time_val(op->ora_e, "whenCreated", t);
	if ( rc != LDAP_SUCCESS ) {
		send_ldap_error( op, rs, rc,
					"objectguid:unable to set attribute 'whenCreated'" );
			return rs->sr_err;
	}

	return LDAP_SUCCESS;
}

static int 
objectguid_op_add( Operation *op, SlapReply *rs )
{
	int rc;

	Debug(LDAP_DEBUG_ANY, "objectguid_op_add\n",0,0,0);
	if ((rc = objectguid_add_instancetype(op, rs)) != LDAP_SUCCESS) {
		return rc;
	}

	if ((rc = objectguid_add_when(op, rs)) != LDAP_SUCCESS) {
		return rc;
	}

	if ((rc = objectguid_add_guid(op, rs)) != LDAP_SUCCESS) {
		return rc;
	}

	if ((rc = objectguid_add_SID(op, rs)) != LDAP_SUCCESS) {
		return rc;
	}

	return SLAP_CB_CONTINUE;
}

/*TODO - we need to implement DBCHECK_CONTROL */

static int 
objectguid_op_modify( Operation *op, SlapReply *rs )
{
	time_t t = time(NULL);
	Modification* md = samba_find_modification(op->orm_modlist, "objectGUID");
	Modifications *ml, *mod;
	AttributeDescription *ad_whenChanged = NULL;
	struct berval val;
	int rc;

	if ( (op->o_tag == LDAP_REQ_MODIFY) && (md != NULL)) {
		send_ldap_error( op, rs, LDAP_CONSTRAINT_VIOLATION,
					"objectguid: objectGUID cannot be modified after object creation." );
			return rs->sr_err;
	}

	md = samba_find_modification(op->orm_modlist, "objectSid");
	if ( (op->o_tag == LDAP_REQ_MODIFY) && (md != NULL)) {
		send_ldap_error( op, rs, LDAP_CONSTRAINT_VIOLATION,
				 "objectguid: objectSid cannot be modified after object creation." );
			return rs->sr_err;
	}

	md = samba_find_modification(op->orm_modlist, "instanceType");
	if ( (op->o_tag == LDAP_REQ_MODIFY) && (md != NULL)) {
		send_ldap_error( op, rs, LDAP_CONSTRAINT_VIOLATION,
				 "objectguid: instanceType cannot be modified after object creation." );
			return rs->sr_err;
	}

	ad_whenChanged = samba_find_attr_description("whenChanged");
	if (ad_whenChanged == NULL) {
		send_ldap_error( op, rs, LDAP_NO_SUCH_ATTRIBUTE,
					"objectguid: cannot find whenChanged in schema!" );
			return rs->sr_err;
	}
	if (rc = samba_timestring(&val, t) != LDAP_SUCCESS) {
		send_ldap_error( op, rs, LDAP_OTHER,
					"objectguid: cannot create whenChanged value!" );
			return rs->sr_err;
	}

	mod = ch_calloc( sizeof( Modifications ), 1 );	
	for ( ml = op->orm_modlist; ml && ml->sml_next; ml = ml->sml_next );
	ml->sml_next = mod;
	mod->sml_desc = ad_whenChanged;
	mod->sml_numvals = 1;
	value_add_one( &mod->sml_values, &val );
	mod->sml_nvalues = NULL;
	mod->sml_op = LDAP_MOD_REPLACE;
	mod->sml_flags = 0;
	mod->sml_next = NULL;
	return SLAP_CB_CONTINUE;
}

int objectguid_initialize(void)
{
	objectguid.on_bi.bi_type = "objectguid";
	objectguid.on_bi.bi_op_add = objectguid_op_add;
	objectguid.on_bi.bi_op_modify = objectguid_op_modify;
	Debug(LDAP_DEBUG_TRACE, "objectguid_initialize\n",0,0,0);
	return overlay_register(&objectguid);
}


#if SLAPD_OVER_OBJECTGUID == SLAPD_MOD_DYNAMIC
int init_module( int argc, char *argv[] )
{
	return objectguid_initialize();
}
#endif /* SLAPD_OVER_OBJECTGUID == SLAPD_MOD_DYNAMIC */

#endif /*SLAPD_OVER_OBJECTGUID*/
