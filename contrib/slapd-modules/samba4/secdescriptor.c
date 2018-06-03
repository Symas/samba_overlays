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

/* This is an overlay responsible for the creation and modification of
 * NT Style security descriptors on directory objects */

#include "portable.h"

#ifdef SLAPD_OVER_SECDESCRIPTOR

#include <stdio.h>

#include "ac/string.h"
#include "ac/socket.h"

#include "slap.h"
#include "config.h"

#include "lutil.h"
#include "ldap_rq.h"
#include "flags.h"
#include "ldb.h"
#include "samba_security.h"
#include "samba_utils.h"

static slap_overinst 		secdescriptor;
static int sectoken_cid;
static int sdflags_cid;
#define o_sectoken			o_ctrlflag[sectoken_cid]
#define o_ctrlsectoken		        o_controls[sectoken_cid]
#define o_sdflags		        o_ctrlflag[sdflags_cid]
#define o_ctrlsdflags		        o_controls[sdflags_cid]

struct sec_add_info {
	DATA_BLOB *domain_sid;
	DATA_BLOB *parent_sd;
	DATA_BLOB *schemaIDGUID;
	char      *default_sd;
};

struct schema_info {
	struct berval *schemaIDGUID;
	struct berval *default_sd;
};

struct sec_mod_info {
	Operation *mod_ch;
	Operation *search_ch;
	struct berval dom_sid;
	DATA_BLOB* sec_token;
	Operation *op;
	SlapReply *rs;
	OpExtra *txn;
};

static int
sdflags_parseCtrl( Operation *op,
		   SlapReply *rs,
		   LDAPControl *ctrl )
{
	ber_tag_t tag;
	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;
	ber_int_t flag = 0;

	if ( BER_BVISNULL( &ctrl->ldctl_value ) ) {
		rs->sr_text = "sd_flags control value is absent";
		return LDAP_PROTOCOL_ERROR;
	}

	if ( BER_BVISEMPTY( &ctrl->ldctl_value )) {
		rs->sr_text = "sd_flags control value is empty";
		return LDAP_PROTOCOL_ERROR;
	}

	ber_init2( ber, &ctrl->ldctl_value, 0 );
	if (( tag = ber_scanf( ber, "{b}", &flag )) == LBER_ERROR ) {
		rs->sr_text = "sd_flags control: flag decoding error";
		return LDAP_PROTOCOL_ERROR;
	}

	op->o_sdflags = ctrl->ldctl_iscritical ?
		SLAP_CONTROL_CRITICAL : SLAP_CONTROL_NONCRITICAL;
	if ( flag )
		op->o_sdflags |= ( flag << 4 );

//	ctrl->ldctl_iscritical = SLAP_CONTROL_NONCRITICAL;

	return LDAP_SUCCESS;
}

static int
sectoken_parseCtrl( Operation *op,
		    SlapReply *rs,
		    LDAPControl *ctrl )
{
/* This control is not ber encoded, rather we send
 * the security token NDR encoded */
	DATA_BLOB *blob_token = NULL;
	
	if ( BER_BVISNULL( &ctrl->ldctl_value ) ) {
		rs->sr_text = "sec_token control value is absent";
		return LDAP_SUCCESS;
	}

	if ( BER_BVISEMPTY( &ctrl->ldctl_value ) ) {
		rs->sr_text = "sec_token control value is empty";
		return LDAP_SUCCESS;
	}

	blob_token = (DATA_BLOB *)op->o_tmpalloc( sizeof(DATA_BLOB),
						  op->o_tmpmemctx );
	blob_token->data = op->o_tmpalloc( ctrl->ldctl_value.bv_len,
					   op->o_tmpmemctx );
	blob_token->length = ctrl->ldctl_value.bv_len;
	memcpy( (void *)blob_token->data, (void *)ctrl->ldctl_value.bv_val,
		ctrl->ldctl_value.bv_len );

	op->o_ctrlsectoken = (void *)blob_token;

	op->o_sectoken = ctrl->ldctl_iscritical
		? SLAP_CONTROL_CRITICAL
		: SLAP_CONTROL_NONCRITICAL;

	rs->sr_err = LDAP_SUCCESS;
	return rs->sr_err;
}

static int
secdescriptor_get_schema_cb( Operation *op, SlapReply *rs )
{
	if ( rs->sr_type == REP_SEARCH ) {
		struct schema_info *sc_info = (struct schema_info *)op->o_callback->sc_private;
	       	AttributeDescription *schemaIDGUID_descr = NULL;
		AttributeDescription *defaultsd_descr = NULL;
		Attribute *schemaIDGUID_attribute = NULL;
		Attribute *defaultsd_attribute = NULL;
		
		if ( (schemaIDGUID_descr = samba_find_attr_description( "schemaIDGUID" )) == NULL ) {
			return rs->sr_err;
		}
		
		schemaIDGUID_attribute = attr_find( rs->sr_entry->e_attrs, schemaIDGUID_descr );
		if ( schemaIDGUID_attribute == NULL ) {
			sc_info->schemaIDGUID = NULL; 
			send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
					 "Could not find the schemaIDGUID" );
			return rs->sr_err;
		}
		sc_info->schemaIDGUID = &(schemaIDGUID_attribute->a_vals[0]);
			
		if ( (defaultsd_descr = samba_find_attr_description( "defaultSecurityDescriptor" ) ) == NULL) {
			return rs->sr_err;
		}
		
		defaultsd_attribute = attr_find( rs->sr_entry->e_attrs, defaultsd_descr );
		if ( defaultsd_attribute == NULL ) {
			sc_info->default_sd = NULL; 
			send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
					 "Could not find defaultSecurityDescriptor" );
			return rs->sr_err;
		}
		sc_info->default_sd = &(defaultsd_attribute->a_vals[0]);
		
	}

	return 0;
}
/* Todo implement caching of schemaIDGUID and default_sd */
static int
get_schema_sd_info( Operation *op,
		    SlapReply *rs,
		    struct berval *last_object_class,
		    DATA_BLOB **schemaIDGUID,
		    char **default_sd )
{
	Operation new_op = *op;
	SlapReply new_rs = { 0 };
	slap_callback cb = { 0 };
	AttributeName an[3];
	char *idguid_name = "schemaIDGUID";
	char *default_sd_name = "defaultSecurityDescriptor";
	AttributeDescription *idguid_descr = NULL;
      	AttributeDescription *default_sd_descr = NULL;
	char *tmp_ptr;
	const char filter[] = "lDAPDisplayName=";
	struct schema_info sc_info;
	BackendDB *schema_db = get_schema_db();

	assert( schemaIDGUID != NULL );
	assert( default_sd != NULL );
	BER_BVZERO( &an[2].an_name );
	sc_info.schemaIDGUID = NULL;
	sc_info.default_sd = NULL;
	
	if ( ( idguid_descr = samba_find_attr_description( idguid_name )) == NULL ) {
		return rs->sr_err;
	}
	if ( (default_sd_descr = samba_find_attr_description( default_sd_name )) == NULL ) {
		return rs->sr_err;
	}
	
	an[0].an_name.bv_len = strlen( idguid_name );
	an[0].an_name.bv_val = idguid_name;
	an[0].an_desc = idguid_descr;

	an[1].an_name.bv_len = strlen( default_sd_name );
	an[1].an_name.bv_val = default_sd_name;
	an[1].an_desc = default_sd_descr;

	new_op.o_tag = LDAP_REQ_SEARCH;
	new_op.o_callback = &cb;
	cb.sc_response = secdescriptor_get_schema_cb;
	cb.sc_private = (void *)&sc_info;
	new_op.o_req_dn = schema_db->be_nsuffix[0];
	new_op.o_req_ndn = new_op.o_req_dn;
	new_op.o_bd = select_backend( &schema_db->be_nsuffix[0], 0 );
	new_op.o_dn = new_op.o_bd->be_rootdn;
	new_op.o_ndn = new_op.o_bd->be_rootndn;
	new_op.ors_limit = NULL;
	new_op.ors_slimit = 1;
	new_op.ors_tlimit = SLAP_NO_LIMIT;
	new_op.ors_attrs = an;
	new_op.ors_attrsonly = 1;
	new_op.ors_deref = LDAP_DEREF_NEVER;
	new_op.ors_scope = LDAP_SCOPE_SUBTREE;
	
	/* construct the filter lDAPDisplayName=lastStructuralClass */
	new_op.ors_filterstr.bv_len = STRLENOF( filter );
	new_op.ors_filterstr.bv_len += last_object_class->bv_len;
	new_op.ors_filterstr.bv_val = op->o_tmpalloc( new_op.ors_filterstr.bv_len+1, op->o_tmpmemctx );
	tmp_ptr = new_op.ors_filterstr.bv_val;
	tmp_ptr = lutil_strcopy( tmp_ptr, filter );
	tmp_ptr = lutil_strncopy( tmp_ptr, last_object_class->bv_val, last_object_class->bv_len );
	*tmp_ptr++ = '\0';
	new_op.ors_filter = str2filter_x( op, new_op.ors_filterstr.bv_val );
	assert( new_op.ors_filter != NULL );
	(void)new_op.o_bd->be_search( &new_op, &new_rs );
	if ( new_rs.sr_err != LDAP_SUCCESS ) {
		return new_rs.sr_err;
	}
	if ( sc_info.schemaIDGUID != NULL ) {
		*schemaIDGUID = (DATA_BLOB *)op->o_tmpalloc( sizeof(DATA_BLOB),
							     op->o_tmpmemctx );
		(*schemaIDGUID)->data = op->o_tmpalloc( sc_info.schemaIDGUID->bv_len,
							op->o_tmpmemctx );
		(*schemaIDGUID)->length = sc_info.schemaIDGUID->bv_len;
		memcpy( (void *)(*schemaIDGUID)->data, (void *)( sc_info.schemaIDGUID->bv_val ),
			sc_info.schemaIDGUID->bv_len );
	}
	if ( sc_info.default_sd != NULL ) {
		*default_sd = op->o_tmpalloc( sc_info.default_sd->bv_len+1,
					      op->o_tmpmemctx );
		tmp_ptr = *default_sd;
		memcpy( (void *)tmp_ptr, (void *)(sc_info.default_sd->bv_val),
			sc_info.default_sd->bv_len );
		tmp_ptr[sc_info.default_sd->bv_len] = '\0';
	}

	filter_free_x( op, new_op.ors_filter, 1 );
	op->o_tmpfree( new_op.ors_filterstr.bv_val, op->o_tmpmemctx );
	
	return new_rs.sr_err;
	
}
static int
secdescriptor_modify_cb( Operation *op, SlapReply *rs );

static int
secdescriptor_get_modify_attrs_from_entry( Entry *e,
					   struct berval *instanceType,
					   struct berval *blob_sd,
					   struct berval *objectClass )
{
	Attribute *sd_att = NULL;
	Attribute *oc_att = NULL;
	Attribute *it_att = NULL;

	sd_att = attr_find( e->e_attrs, slap_schema.si_ad_nTSecurityDescriptor );
	oc_att = attr_find( e->e_attrs, slap_schema.si_ad_objectClass );
	it_att = attr_find( e->e_attrs, slap_schema.si_ad_instanceType );

	if ( oc_att != NULL && oc_att->a_numvals >= 1 ) {
		ber_dupbv( objectClass, &(oc_att->a_vals[oc_att->a_numvals-1]) );
	}
	if ( it_att != NULL && it_att->a_vals != NULL ) {
		ber_dupbv( instanceType, &(it_att->a_vals[0]) );
	}
	if ( sd_att != NULL && it_att->a_vals != NULL ) {
		ber_dupbv( blob_sd, &(sd_att->a_vals[0]) );
	}
	return LDAP_SUCCESS;
}

static int
secdescriptor_modify_child_cb( Operation *op, SlapReply *rs )
{
	struct berval instanceType;
	struct berval old_descriptor;
	struct berval objectClass;
	struct berval parent_sd;
	struct berval last_object_class;
	TALLOC_CTX *talloc_mem_ctx = talloc_new( NULL );
	DATA_BLOB *user_descriptor_ptr = NULL;
	DATA_BLOB *schemaIDGUID = NULL;
	char *default_sd = NULL;
	char *as_sddl = NULL;
	SD_PARTITION partition;
	struct berval bv_new_sd;
	DATA_BLOB old_sd_blob;
	DATA_BLOB blob_dsid;
	DATA_BLOB blob_psd;
	SlapReply new_rs = { 0 };
	struct sec_mod_info *mod_info = (struct sec_mod_info *)op->o_callback->sc_private;
	Modifications *m = mod_info->mod_ch->orm_modlist;
	
	if ( rs->sr_type == REP_SEARCH ) {
		secdescriptor_get_modify_attrs_from_entry( rs->sr_entry,
							   &instanceType,
							   &old_descriptor,
							   &objectClass );
		samba_get_parent_sd( op, rs, &instanceType, &parent_sd );
		get_schema_sd_info( op, rs, 
				    &last_object_class,
				    &schemaIDGUID, &default_sd );
      
		partition = samba_get_partition_flag( op );
		old_sd_blob.length = old_descriptor.bv_len;
		old_sd_blob.data = (uint8_t*)old_descriptor.bv_val;
		blob_dsid.length = mod_info->dom_sid.bv_len;
		blob_dsid.data = (uint8_t*)mod_info->dom_sid.bv_val;
		blob_psd.length = parent_sd.bv_len;
		blob_psd.data = (uint8_t*)parent_sd.bv_val;
		DATA_BLOB *final_sd = security_descriptor_ds_create_as_blob( talloc_mem_ctx,
									     mod_info->sec_token,
									     &blob_dsid,
									     default_sd,
									     schemaIDGUID,
									     &blob_psd,
									     user_descriptor_ptr,
									     &old_sd_blob,
									     partition,
									     SD_SECINFO_OWNER|SD_SECINFO_GROUP|SD_SECINFO_SACL|SD_SECINFO_DACL,
									     &as_sddl );
		if ( as_sddl ) {
			Debug( LDAP_DEBUG_ANY,
			       "result descriptor: (%s)\n",
			       as_sddl, 0, 0 );
		}
		
		if ( final_sd == NULL ) {
			send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
					 "" );
			talloc_free( talloc_mem_ctx );
			ch_free( instanceType.bv_val );
			ch_free( old_descriptor.bv_val );
			ch_free( objectClass.bv_val );
			return rs->sr_err; 
		}

		bv_new_sd.bv_len = final_sd->length;
		bv_new_sd.bv_val = (char *)final_sd->data;
		/* replace the new value in the request */
		if ( m->sml_values[0].bv_val ) {
			ch_free( m->sml_values[0].bv_val );
		}
		ber_dupbv( &m->sml_values[0],&bv_new_sd );		
		talloc_free( talloc_mem_ctx );
		ch_free( instanceType.bv_val );
		ch_free( old_descriptor.bv_val );
		ch_free( objectClass.bv_val );
		mod_info->mod_ch->o_req_dn.bv_val = NULL;
		ber_dupbv( &mod_info->mod_ch->o_req_dn, &rs->sr_un.sru_search.r_entry->e_name );
		mod_info->mod_ch->o_bd->be_modify( mod_info->mod_ch, &new_rs );
	}
	return rs->sr_err;	
}

/* get the attributes of the object whose sd is being modified,
 * necessary for the sd calculation - nTSecurityDescriptor, objectClass, instanceType */
static int
secdescriptor_get_modify_attrs( Operation *op,
				SlapReply *rs,
				struct berval *instanceType,
				struct berval *blob_sd,
				struct berval *objectClass )
{
	Entry		*e = NULL;
	Attribute *sd_att = NULL;
	Attribute *oc_att = NULL;
	Attribute *it_att = NULL;
	int rc;
	slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
	BackendInfo *o_op_info = op->o_bd->bd_info;

	op->o_bd->bd_info = (BackendInfo *)on->on_info->oi_orig;
	rc = be_entry_get_rw( op, &op->o_req_ndn, NULL, NULL, 0, &e );
	if ( rc != LDAP_SUCCESS ) {
		op->o_bd->bd_info = o_op_info;
		return rc;
	}

	sd_att = attr_find( e->e_attrs, slap_schema.si_ad_nTSecurityDescriptor );
	oc_att = attr_find( e->e_attrs, slap_schema.si_ad_objectClass );
	it_att = attr_find( e->e_attrs, slap_schema.si_ad_instanceType );

	if ( oc_att != NULL && oc_att->a_numvals >= 1 ) {
		ber_dupbv_x( objectClass, &(oc_att->a_vals[oc_att->a_numvals-1]), op->o_tmpmemctx );
	}
	if (it_att != NULL && it_att->a_vals != NULL) {
		ber_dupbv_x( instanceType, &(it_att->a_vals[0]), op->o_tmpmemctx );
	}
	if (sd_att != NULL && it_att->a_vals != NULL) {
		ber_dupbv_x( blob_sd, &(sd_att->a_vals[0]), op->o_tmpmemctx );
	}
	be_entry_release_r( op, e );
	op->o_bd->bd_info = o_op_info;
	return LDAP_SUCCESS;
}

static int
secdescriptor_modify_cb( Operation *op, SlapReply *rs )
{
	struct sec_mod_info *mod_info = (struct sec_mod_info *)op->o_callback->sc_private;
	SlapReply new_rs = { 0 };
	if ( rs->sr_err == LDAP_SUCCESS ) {
		mod_info->search_ch->o_req_dn = op->o_req_dn;
		mod_info->search_ch->o_req_ndn = op->o_req_ndn;
		(void)mod_info->search_ch->o_bd->be_search( mod_info->search_ch, &new_rs );
	} 
	return SLAP_CB_CONTINUE;
	
}

static int
secdescriptor_op_add( Operation *op, SlapReply *rs )
{
	Attribute *instance_attribute;
	Attribute *secdesc_attribute;
	Attribute *objectclass_attribute;
	TALLOC_CTX *talloc_mem_ctx = talloc_new(NULL);
	DATA_BLOB *sec_token = (DATA_BLOB*)op->o_ctrlsectoken;
	DATA_BLOB user_descriptor;
	DATA_BLOB *user_descriptor_ptr = NULL;
	struct berval domain_sid;
	DATA_BLOB blob_dsid;
	struct berval parent_sd;
	DATA_BLOB *schemaIDGUID = NULL;
	char *default_sd = NULL;
	char *as_sddl = NULL;
	SD_PARTITION partition;
	DATA_BLOB blob_psd;
	struct berval bv_new_sd;
	int rc;

	instance_attribute = attr_find( op->ora_e->e_attrs, slap_schema.si_ad_instanceType );
	
	if ( instance_attribute == NULL || instance_attribute->a_numvals != 1) {
		/* we should have instanceType at this point,
		 * instancetype overlay should be above */
		return LDAP_OPERATIONS_ERROR;
	}

	objectclass_attribute = attr_find( op->ora_e->e_attrs, slap_schema.si_ad_objectClass );
	/* these should never happen but just in case */
	if ( objectclass_attribute == NULL ) {
		return LDAP_OPERATIONS_ERROR;
	}
	
	if ( objectclass_attribute->a_numvals < 1 ) {
		return LDAP_OPERATIONS_ERROR;
	}
	
	/* check return codes */ 
	samba_get_domain_sid( op, rs, &domain_sid );
	samba_get_parent_sd( op, rs, &(instance_attribute->a_vals[0]), &parent_sd );
	get_schema_sd_info( op, rs, 
			    &(objectclass_attribute->a_vals[objectclass_attribute->a_numvals-1]),
			    &schemaIDGUID, &default_sd );

	secdesc_attribute = attr_find( op->ora_e->e_attrs, slap_schema.si_ad_nTSecurityDescriptor );
	if ( secdesc_attribute != NULL ) {
	       
		/* todo check correct error */
		if ( secdesc_attribute->a_numvals !=1 ) {
			send_ldap_error( op, rs, LDAP_CONSTRAINT_VIOLATION,
					 "Incorrect read of attribute nTSecurityDescriptor" );
			return rs->sr_err;
		}
		/* this is fine because input descriptor will not be changed */
		user_descriptor.data = (uint8_t *)secdesc_attribute->a_vals[0].bv_val;
		user_descriptor.length = secdesc_attribute->a_vals[0].bv_len;
		user_descriptor_ptr = &user_descriptor;
	}

	partition = samba_get_partition_flag(op);
	blob_dsid.length = domain_sid.bv_len;
	blob_dsid.data = (uint8_t*)domain_sid.bv_val;
	blob_psd.length = parent_sd.bv_len;
	blob_psd.data = (uint8_t*)parent_sd.bv_val;
	DATA_BLOB *final_sd = security_descriptor_ds_create_as_blob( talloc_mem_ctx,
								     sec_token,
								     &blob_dsid,
								     default_sd,
								     schemaIDGUID,
								     &blob_psd,
								     user_descriptor_ptr,
								     NULL,
								     partition,
								     SD_SECINFO_OWNER|SD_SECINFO_GROUP|SD_SECINFO_SACL|SD_SECINFO_DACL,
								     &as_sddl );
	if ( as_sddl ) {
		Debug( LDAP_DEBUG_ANY,
		       "result descriptor: (%s)\n",
		       as_sddl, 0, 0 );
	}
	
	if ( final_sd == NULL ) {
		send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
				 "" );
		talloc_free( talloc_mem_ctx );
		return rs->sr_err; 
	}
	
	bv_new_sd.bv_len = final_sd->length;
	bv_new_sd.bv_val = (char *)final_sd->data;
	
	if ( secdesc_attribute == NULL ) {
		attr_merge_one( op->ora_e, slap_schema.si_ad_nTSecurityDescriptor, &bv_new_sd, NULL );
	}
	else { 
		samba_attr_delvals( secdesc_attribute );
	
		rc = attr_valadd( secdesc_attribute,
				  &bv_new_sd, NULL, 1 );
		if ( rc != 0 ) { 
			send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
					 "" );
			talloc_free( talloc_mem_ctx );
			return rs->sr_err; 
		}
	}
	talloc_free( talloc_mem_ctx );
	return SLAP_CB_CONTINUE;	
}

static int
secdescriptor_prep_child_ops( Operation *op, SlapReply *rs, struct sec_mod_info *mod_info, OpExtra *txn)
{
	
	AttributeName *an = (AttributeName *)op->o_tmpalloc( sizeof(AttributeName)*4, op->o_tmpmemctx );
	slap_callback *cb = op->o_tmpcalloc( 1, sizeof( slap_callback ), op->o_tmpmemctx );
	slap_callback *m_cb = op->o_tmpcalloc( 1, sizeof( slap_callback ), op->o_tmpmemctx );
	BackendDB *db = op->o_tmpcalloc( 1, sizeof( BackendDB ), op->o_tmpmemctx );
	slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
	const char *filter = "(&)";
	Modifications *modlist;
	mod_info->search_ch = op->o_tmpcalloc( 1, sizeof( Operation ), op->o_tmpmemctx );
	mod_info->mod_ch = op->o_tmpcalloc( 1, sizeof( Operation ), op->o_tmpmemctx );
	*db = *op->o_bd;
	BER_BVZERO( &an[3].an_name );
	an[0].an_name = slap_schema.si_ad_nTSecurityDescriptor->ad_cname;
	an[0].an_desc = slap_schema.si_ad_nTSecurityDescriptor;

	an[1].an_name = slap_schema.si_ad_objectClass->ad_cname;
	an[1].an_desc = slap_schema.si_ad_objectClass;

	an[2].an_name = slap_schema.si_ad_instanceType->ad_cname;
	an[2].an_desc = slap_schema.si_ad_instanceType;
	
	*mod_info->search_ch = *op;
	*mod_info->mod_ch = *op;
	mod_info->search_ch->o_bd = db;
	mod_info->mod_ch->o_bd = db;
	mod_info->search_ch->o_bd->bd_info = (BackendInfo *)on->on_info->oi_orig;
	mod_info->mod_ch->o_bd->bd_info = (BackendInfo *)on->on_info->oi_orig;

	mod_info->search_ch->o_tag = LDAP_REQ_SEARCH;
	mod_info->search_ch->o_dn = op->o_bd->be_rootdn;
	mod_info->search_ch->o_ndn = op->o_bd->be_rootndn;
	mod_info->search_ch->o_callback = cb;
	cb->sc_response = secdescriptor_modify_child_cb;
	cb->sc_private = (void *)mod_info;

	mod_info->search_ch->ors_limit = NULL;
	mod_info->search_ch->ors_slimit = 1;
	mod_info->search_ch->ors_tlimit = SLAP_NO_LIMIT;
	mod_info->search_ch->ors_attrs = an;
	mod_info->search_ch->ors_attrsonly = 1;
	mod_info->search_ch->ors_deref = LDAP_DEREF_NEVER;
	mod_info->search_ch->ors_scope = LDAP_SCOPE_ONE;
	mod_info->search_ch->ors_filterstr.bv_len = STRLENOF( filter );
	mod_info->search_ch->ors_filterstr.bv_val = op->o_tmpalloc( mod_info->search_ch->ors_filterstr.bv_len+1, op->o_tmpmemctx );
	memcpy( (void *)mod_info->search_ch->ors_filterstr.bv_val, (void *)filter, mod_info->search_ch->ors_filterstr.bv_len );
	mod_info->search_ch->ors_filterstr.bv_val[mod_info->search_ch->ors_filterstr.bv_len] = '\0';
	mod_info->search_ch->ors_filter = str2filter_x( op, mod_info->search_ch->ors_filterstr.bv_val );
	assert( mod_info->search_ch->ors_filter != NULL );

	mod_info->mod_ch->o_tag = LDAP_REQ_MODIFY;
	mod_info->mod_ch->o_dn = op->o_bd->be_rootdn;
	mod_info->mod_ch->o_ndn = op->o_bd->be_rootndn;
	mod_info->mod_ch->o_callback = m_cb;
	m_cb->sc_response = secdescriptor_modify_cb;
	m_cb->sc_private =(void *)mod_info;
	modlist = (Modifications *)ch_calloc( 1, sizeof( Modifications ) );
	modlist->sml_values = (struct berval *)ch_calloc( 2, sizeof( struct berval ));
	modlist->sml_numvals = 1;
	modlist->sml_op = LDAP_MOD_REPLACE;
	modlist->sml_desc = slap_schema.si_ad_nTSecurityDescriptor;
	mod_info->mod_ch->orm_modlist = modlist;
	LDAP_SLIST_INSERT_HEAD( &mod_info->mod_ch->o_extra, txn, oe_next );
	LDAP_SLIST_INSERT_HEAD( &mod_info->search_ch->o_extra, txn, oe_next );
	return LDAP_SUCCESS;
}


static int
secdescriptor_modify_tnx_commit( Operation *op, SlapReply *rs )
{
	int rc;
	struct sec_mod_info *mod_info = (struct sec_mod_info *)op->o_callback->sc_private;
	rc = op->o_bd->bd_info->bi_op_txn( op, SLAP_TXN_COMMIT, &mod_info->txn );
	if ( rc ) {
		send_ldap_error( op, rs, LDAP_OTHER,
				 "secdescriptor: Transaction commit failed!" );
		return LDAP_OTHER;
	}
	return SLAP_CB_CONTINUE;
}


static int
secdescriptor_cb_cleanup( Operation *op, SlapReply *rs )
{
	if ( rs->sr_type == REP_RESULT || rs->sr_err == SLAPD_ABANDON ) {
		slap_callback *sc = op->o_callback;
		op->o_callback = op->o_callback->sc_next;
		op->o_tmpfree( sc, op->o_tmpmemctx );
	}
	return 0;
}

static int
secdescriptor_modify_cleanup( Operation *op, SlapReply *rs )
{
	if ( rs->sr_type == REP_RESULT || rs->sr_err == SLAPD_ABANDON ) {
		slap_callback *sc = op->o_callback;
		struct sec_mod_info *mod_info = (struct sec_mod_info *)op->o_callback->sc_private;
		op->o_callback = op->o_callback->sc_next;
		op->o_tmpfree( mod_info->search_ch->ors_filterstr.bv_val, op->o_tmpmemctx );
		filter_free_x( op, mod_info->search_ch->ors_filter, 1 );
		op->o_tmpfree( mod_info->search_ch->ors_attrs, op->o_tmpmemctx );
		op->o_tmpfree( mod_info->search_ch->o_callback, op->o_tmpmemctx );
		op->o_tmpfree( mod_info->mod_ch->o_callback, op->o_tmpmemctx );
		op->o_tmpfree( mod_info->mod_ch->orm_modlist, op->o_tmpmemctx );
		op->o_tmpfree( mod_info->mod_ch->o_bd, op->o_tmpmemctx );
		op->o_tmpfree( mod_info->search_ch, op->o_tmpmemctx );
		op->o_tmpfree( mod_info->mod_ch, op->o_tmpmemctx );
		op->o_tmpfree( mod_info, op->o_tmpmemctx );
		op->o_tmpfree( sc, op->o_tmpmemctx );
	}

	return 0;
}

static int
secdescriptor_op_modify( Operation *op, SlapReply *rs )
{
	struct berval instancetype;
	struct berval old_descriptor;
	struct berval last_object_class;
	Modifications *ml;
	slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
	TALLOC_CTX *talloc_mem_ctx = NULL;
	DATA_BLOB *sec_token = (DATA_BLOB*)op->o_ctrlsectoken;
	DATA_BLOB user_descriptor;
	DATA_BLOB *user_descriptor_ptr = NULL;
	struct berval domain_sid;
	struct berval parent_sd = {0, NULL};
	DATA_BLOB *schemaIDGUID = NULL;
	char *default_sd = NULL;
	char *as_sddl = NULL;
	SD_PARTITION partition;
	struct berval bv_new_sd;
	slap_callback *sc, *t_sc;
	DATA_BLOB old_sd_blob;
	DATA_BLOB blob_dsid;
	DATA_BLOB blob_psd;
	OpExtra *txn = NULL;
	int rc;
	struct sec_mod_info *mod_info = NULL;

	/* do not apply through Samba for now */
	if (samba_is_trusted_connection(op)) {
		return SLAP_CB_CONTINUE;
	}
	for ( ml = op->orm_modlist; ml != NULL; ml = ml->sml_next ) {
		if ( ml->sml_mod.sm_desc == slap_schema.si_ad_nTSecurityDescriptor ) {
			if ( ml->sml_op == LDAP_MOD_DELETE ) {
				send_ldap_error( op, rs, LDAP_UNWILLING_TO_PERFORM,
						 "nTSecurityDescriptor DELETE not supported" );
				return LDAP_UNWILLING_TO_PERFORM;
			} else if ( ml->sml_numvals == 0 ) {
				send_ldap_error( op, rs, LDAP_CONSTRAINT_VIOLATION,
						 "nTSecurityDescriptor must have at least one value!" );
				return LDAP_CONSTRAINT_VIOLATION;
			} else {
				user_descriptor.data = (uint8_t *)ml->sml_values[0].bv_val;
				user_descriptor.length = ml->sml_values[0].bv_len;
				user_descriptor_ptr = &user_descriptor;
			}
			break;	
		}
	}
	/* no sd mods, nothing to do */
	if ( !ml ) {
		return SLAP_CB_CONTINUE;
	}

	secdescriptor_get_modify_attrs( op, rs,
					&instancetype,
					&old_descriptor,
					&last_object_class );

	samba_get_domain_sid( op, rs, &domain_sid );
	samba_get_parent_sd( op, rs, &instancetype, &parent_sd );
	get_schema_sd_info( op, rs, 
			    &last_object_class,
			    &schemaIDGUID, &default_sd );
	mod_info = op->o_tmpcalloc( 1, sizeof( struct sec_mod_info ), op->o_tmpmemctx );
	rc = on->on_info->oi_orig->bi_op_txn( op, SLAP_TXN_BEGIN, &txn );
	if ( rc ) {
		send_ldap_error( op, rs, LDAP_OTHER,
				 "couldn't start DB transaction" );
		return LDAP_OTHER; 
	}

	talloc_mem_ctx = talloc_new( NULL );
	mod_info = op->o_tmpcalloc( 1, sizeof( struct sec_mod_info ), op->o_tmpmemctx );
	mod_info->txn = txn;
	/* prepare the operations that will have the same transaction pointer */
	secdescriptor_prep_child_ops( op, rs, mod_info, txn );
	ber_dupbv_x( &mod_info->dom_sid, &domain_sid, op->o_tmpmemctx );
	mod_info->sec_token = sec_token;
	partition = samba_get_partition_flag( op );
	old_sd_blob.length = old_descriptor.bv_len;
	old_sd_blob.data = (uint8_t*)old_descriptor.bv_val;
	blob_dsid.length = domain_sid.bv_len;
	blob_dsid.data = (uint8_t*)domain_sid.bv_val;
	blob_psd.length = parent_sd.bv_len;
	blob_psd.data = (uint8_t*)parent_sd.bv_val;
	DATA_BLOB *final_sd = security_descriptor_ds_create_as_blob( talloc_mem_ctx,
								     sec_token,
								     &blob_dsid,
								     default_sd,
								     schemaIDGUID,
								     &blob_psd,
								     user_descriptor_ptr,
								     &old_sd_blob,
								     partition,
								     SD_SECINFO_OWNER|SD_SECINFO_GROUP|SD_SECINFO_SACL|SD_SECINFO_DACL,
								     &as_sddl );
	if ( as_sddl ) {
		Debug( LDAP_DEBUG_ANY,
		       "result descriptor: (%s)\n",
		       as_sddl, 0, 0 );
	}
	
	if ( final_sd == NULL ) {
		send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
				 "" );
		op->o_tmpfree( mod_info, op->o_tmpmemctx );
		talloc_free( talloc_mem_ctx );
		return rs->sr_err; 
	}

	bv_new_sd.bv_len = final_sd->length;
	bv_new_sd.bv_val = (char *)final_sd->data;
	/* replace the new value in the request */
	if ( ml->sml_values[0].bv_val ) {
		ch_free( ml->sml_values[0].bv_val );
	}
	ber_dupbv( &ml->sml_values[0],&bv_new_sd );		
	talloc_free( talloc_mem_ctx );	
	sc = op->o_tmpcalloc( 1, sizeof( slap_callback ), op->o_tmpmemctx );
	t_sc = op->o_tmpcalloc( 1, sizeof( slap_callback ), op->o_tmpmemctx );
	t_sc->sc_response = secdescriptor_modify_tnx_commit;
	sc->sc_response = secdescriptor_modify_cb;
	t_sc->sc_private = (void*)mod_info;
	t_sc->sc_next = sc;
	sc->sc_next = op->o_callback;
	sc->sc_cleanup = secdescriptor_cb_cleanup;
	t_sc->sc_cleanup = secdescriptor_modify_cleanup; 
	mod_info->op = op;
	mod_info->rs = rs;
	sc->sc_private = (void*)mod_info;
	op->o_callback = t_sc;
	return SLAP_CB_CONTINUE;	
}

/* TODO*/
static int
secdescriptor_op_modrdn( Operation *op, SlapReply *rs )
{
	return SLAP_CB_CONTINUE;
}


static int
secdescriptor_response_entry( Operation *op, SlapReply *rs )
{	
	int sd_flags = 0;
	DATA_BLOB *show_descr = NULL;
	DATA_BLOB full_desc;
	TALLOC_CTX *talloc_mem_ctx = NULL;
	Attribute *secdesc_attribute = NULL;
	int rc;
	struct berval bv_show_descr;

	secdesc_attribute = attr_find( rs->sr_entry->e_attrs, slap_schema.si_ad_nTSecurityDescriptor );
	if ( secdesc_attribute == NULL ) {
		return SLAP_CB_CONTINUE;
	}
	if ( secdesc_attribute->a_numvals !=1 ) {
		send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
				 "Incorrect read of attribute nTSecurityDescriptor" );
		return rs->sr_err;
	}
	sd_flags |= ( op->o_sdflags >> 4 );
	/* nothing to do, the full decriptor is needed */
	if ( sd_flags == 0 || sd_flags == 0xF ) {
		return SLAP_CB_CONTINUE;
	}
	talloc_mem_ctx = talloc_new( NULL );
	/* this is fine because input descriptor will not be changed */
	full_desc.data = (uint8_t *)secdesc_attribute->a_vals[0].bv_val;
	full_desc.length = secdesc_attribute->a_vals[0].bv_len;
	/* modify the descriptor to display depending on the sd_flags */
	show_descr = security_descriptor_ds_get_sd_to_display( talloc_mem_ctx,
							       &full_desc, sd_flags );
	if ( !show_descr ) {
		send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
				 "Incorrect read of attribute nTSecurityDescriptor" );
		
		if ( talloc_mem_ctx != NULL ) {
			talloc_free( talloc_mem_ctx );
		}
		return rs->sr_err;
	}
	samba_attr_delvals( secdesc_attribute );
	/* fine becasue attr_valadd does a deep copy */
	bv_show_descr.bv_len = show_descr->length;
	bv_show_descr.bv_val = (char *)show_descr->data;
	rc = attr_valadd( secdesc_attribute,
			  &bv_show_descr, NULL, 1);
	if ( rc != 0 ) { 
		send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
				 "Incorrect read of attribute nTSecurityDescriptor" );
		talloc_free( talloc_mem_ctx );
		return rs->sr_err; 
	}
	
	talloc_free( talloc_mem_ctx );
	return SLAP_CB_CONTINUE;	
}

static int
secdescriptor_response( Operation *op, SlapReply *rs )
{
	switch ( rs->sr_type ) {
	case REP_SEARCH:
		return secdescriptor_response_entry( op, rs );
	case REP_RESULT:
	case REP_SEARCHREF:
		break;

	default:
		assert( 0 );
	}

	return SLAP_CB_CONTINUE;
}

static int
secdescriptor_op_search( Operation *op, SlapReply *rs )
{
	int sd_flags = 0;
	slap_callback *sc;
	sd_flags |= (op->o_sdflags >> 4);

	/* do not apply through Samba for now */
	if ( samba_is_trusted_connection( op ) ) {
		return SLAP_CB_CONTINUE;
	}

	/* nothing to do, the full decriptor is needed */
	if ( sd_flags == 0 || sd_flags == 0xF ) {
		return SLAP_CB_CONTINUE;
	}
	/* Todo Filter here if SD is to be displayed at all */
	sc = op->o_tmpcalloc( 1, sizeof(slap_callback), op->o_tmpmemctx );
	sc->sc_response = secdescriptor_response;
	sc->sc_cleanup = secdescriptor_cb_cleanup;
	sc->sc_next = op->o_callback->sc_next;
	op->o_callback->sc_next = sc;
	return SLAP_CB_CONTINUE;
}

static int
secdescriptor_db_open(
	BackendDB	*be,
	ConfigReply	*cr )
{
	return samba_set_partitions_db_pointers( be );
}

int
secdescriptor_initialize(void)
{
	int rc;
	rc = register_supported_control( DSDB_CONTROL_SEC_TOKEN_OID,
					 SLAP_CTRL_SEARCH|SLAP_CTRL_ADD|SLAP_CTRL_DELETE|SLAP_CTRL_RENAME|SLAP_CTRL_MODIFY,
					 NULL,
					 sectoken_parseCtrl, &sectoken_cid );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
		       "secdescriptor_initialize: Failed to register control (%d)\n",
		       rc, 0, 0 );
		return -1;
	}
	/* these will be removed */
	rc = register_supported_control( LDB_CONTROL_SD_FLAGS_OID,
					 SLAP_CTRL_SEARCH|SLAP_CTRL_ADD|SLAP_CTRL_DELETE|SLAP_CTRL_RENAME|SLAP_CTRL_MODIFY,
					 NULL,
					 sdflags_parseCtrl, &sdflags_cid );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
		       "secdescriptor_initialize: Failed to register control (%d)\n",
		       rc, 0, 0 );
		return -1;
	}
	secdescriptor.on_bi.bi_type = "secdescriptor";
	secdescriptor.on_bi.bi_db_open = secdescriptor_db_open;
	secdescriptor.on_bi.bi_op_add = secdescriptor_op_add;
	secdescriptor.on_bi.bi_op_modrdn = secdescriptor_op_modrdn;
	secdescriptor.on_bi.bi_op_modify = secdescriptor_op_modify;
	secdescriptor.on_bi.bi_op_search = secdescriptor_op_search;
	Debug(LDAP_DEBUG_TRACE, "secdescriptor_initialize\n",0,0,0);
	return overlay_register(&secdescriptor);
}


#if SLAPD_OVER_SECDESCRIPTOR == SLAPD_MOD_DYNAMIC
int
init_module( int argc, char *argv[] )
{
	return secdescriptor_initialize();
}
#endif /* SLAPD_OVER_SECDESCRIPTOR == SLAPD_MOD_DYNAMIC */

#endif /*SLAPD_OVER_SECDESCRIPTOR*/
