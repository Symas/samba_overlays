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
/* Does op extra preparation - gathers common operation data such as parent info, , parses internal controls.*/
#include "portable.h"
#ifdef SLAPD_OVER_OPPREP
#include <stdio.h>
#include <sys/stat.h>

#include "ac/string.h"
#include "ac/socket.h"

#include "slap.h"
#include "config.h"

#include "lutil.h"
#include "ldap_rq.h"
#include "ldb.h"
#include "talloc.h"
#include "samba_security.h"
#include "flags.h"
#include "samba_utils.h"

static slap_overinst 		opprep;
static int sectoken_cid;
static int sdflags_cid;

#define o_sectoken			o_ctrlflag[sectoken_cid]
#define o_ctrlsectoken		        o_controls[sectoken_cid]
#define o_sdflags		        o_ctrlflag[sdflags_cid]
#define o_ctrlsdflags		        o_controls[sdflags_cid]


struct sec_mod_info {
	struct berval *nTSecurityDescriptor;
	struct berval *lastObjectClass;
	struct berval *instanceType;
	Operation *op;
};

struct sec_add_info {
	struct berval *parent_sd;
	struct berval *object_guid;
	Operation *op;
};

struct sec_sd_info {
	struct berval *sd;
	Operation *op;
};

struct sec_search_info {
	struct berval *parent_sd;
	struct berval *objectGUID; /* for parent guid */
	Operation *op;
};

/* parse LDAP controls used by more than one overlay */
static int
sdflags_parseCtrl(
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	ber_tag_t tag;
	BerElementBuffer berbuf;
	BerElement *ber = (BerElement *)&berbuf;
	ber_int_t flag = 0;

	if ( BER_BVISNULL( &ctrl->ldctl_value )) {
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
		op->o_sdflags |= (flag << 4);

	ctrl->ldctl_iscritical = 0;

	return LDAP_SUCCESS;
}

/* parse internal controls */
static int
sectoken_parseCtrl (
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
/* This control is not ber encoded, rather we send
 * the security token NDR encoded */
	DATA_BLOB *blob_token = NULL;
	if (!samba_is_trusted_connection(op)) {
		/* This is an internal control, only accepted from an
		 * internal connection */
		return LDAP_OPERATIONS_ERROR;
	}
	if ( BER_BVISNULL( &ctrl->ldctl_value ) ) {
		rs->sr_text = "sec_token control value is absent";
		return LDAP_SUCCESS;
	}

	if ( BER_BVISEMPTY( &ctrl->ldctl_value ) ) {
		rs->sr_text = "sec_token control value is empty";
		return LDAP_SUCCESS;
	}

	blob_token = (DATA_BLOB *)op->o_tmpalloc(sizeof(DATA_BLOB),
						 op->o_tmpmemctx );
	blob_token->data = op->o_tmpalloc(ctrl->ldctl_value.bv_len,
					  op->o_tmpmemctx );
	blob_token->length = ctrl->ldctl_value.bv_len;
	memcpy((void *)blob_token->data, (void *)ctrl->ldctl_value.bv_val,
	       ctrl->ldctl_value.bv_len);

	op->o_ctrlsectoken = (void *)blob_token;

	op->o_sectoken = ctrl->ldctl_iscritical
		? SLAP_CONTROL_CRITICAL
		: SLAP_CONTROL_NONCRITICAL;

	rs->sr_err = LDAP_SUCCESS;
	return rs->sr_err;
}

static void
opprep_cleanup_extra( Operation *op, OpExtraOpprep *o_prep)
{
	opprep_info_t *oi;
	if (o_prep == NULL ||o_prep->oe_opi == NULL ) {
		return;
	}
	oi = o_prep->oe_opi;
	switch (op->o_tag) {
	case LDAP_REQ_ADD:
		if (oi->un.add.parent_sd.bv_len > 0) {
			op->o_tmpfree( oi->un.add.parent_sd.bv_val, op->o_tmpmemctx );
		}
		break;
	case LDAP_REQ_DELETE:
		if (oi->un.del.parent_sd.bv_len > 0) {
			op->o_tmpfree( oi->un.del.parent_sd.bv_val, op->o_tmpmemctx );
		}
		break;
	case LDAP_REQ_MODIFY:
		if (oi->un.mod.sd.bv_len > 0) {
			op->o_tmpfree( oi->un.mod.sd.bv_val, op->o_tmpmemctx );
		}
		if (oi->un.mod.object_class.bv_len > 0) {
			op->o_tmpfree( oi->un.mod.object_class.bv_val, op->o_tmpmemctx );
		}
		if (oi->un.mod.instanceType.bv_len > 0) {
			op->o_tmpfree( oi->un.mod.instanceType.bv_val, op->o_tmpmemctx );
		}
		break;
	case LDAP_REQ_MODRDN:
		if (oi->un.modrdn.new_parent_sd.bv_len > 0) {
			op->o_tmpfree( oi->un.modrdn.new_parent_sd.bv_val, op->o_tmpmemctx );
		}
		if (oi->un.modrdn.parent_sd.bv_len > 0) {
			op->o_tmpfree( oi->un.modrdn.parent_sd.bv_val, op->o_tmpmemctx );
		}
		break;
	case LDAP_REQ_SEARCH:
		if (oi->un.search.parent_sd.bv_len > 0) {
			op->o_tmpfree( oi->un.search.parent_sd.bv_val, op->o_tmpmemctx );
		}
		break;
	} 
	op->o_tmpfree( oi, op->o_tmpmemctx );
	op->o_tmpfree( o_prep, op->o_tmpmemctx );
}

static int
opprep_cleanup( Operation *op, SlapReply *rs )
{
	OpExtra *oex;
	if ( rs->sr_type == REP_RESULT || rs->sr_err == SLAPD_ABANDON ) {
		op->o_tmpfree( op->o_callback, op->o_tmpmemctx );
		op->o_callback = NULL;

		if (op->o_ctrlsectoken) {
			DATA_BLOB *blob = (DATA_BLOB *)op->o_ctrlsectoken;
			op->o_tmpfree( blob->data, op->o_tmpmemctx );
			op->o_tmpfree( op->o_ctrlsectoken, op->o_tmpmemctx );
		}
		op->o_ctrlsectoken = NULL;
     
		LDAP_SLIST_FOREACH( oex, &op->o_extra, oe_next ) {
			if ( oex->oe_key == (void *)&opprep )
				break;
		}
		// todo remove
		if ( !oex ) {
			return SLAP_CB_CONTINUE;
		}
		opprep_cleanup_extra( op, (OpExtraOpprep *)oex);
	}
	return SLAP_CB_CONTINUE;
}

static int
opprep_get_modify_attrs( Operation *op, SlapReply *rs, opprep_info_mod *o_mod)
{
        Entry		*e = NULL;
        Attribute *secdesc_attribute = NULL;
        Attribute *objectclass_attribute = NULL;
        Attribute *instancetype_attribute = NULL;
        int rc = LDAP_SUCCESS;

        assert(o_mod != NULL);

        rc = be_entry_get_rw( op, &op->o_req_ndn, NULL, NULL, 0, &e );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}
        secdesc_attribute = samba_find_attribute(e->e_attrs, "nTSecurityDescriptor");
        objectclass_attribute = samba_find_attribute(e->e_attrs, "objectClass");
        instancetype_attribute = samba_find_attribute(e->e_attrs, "instanceType");

        /* it is theoretically possible to have no sd, although not likely,
         * the other attribuites should always be present */
        if ( secdesc_attribute == NULL) {
		o_mod->sd.bv_len = 0; 
        } else if ( secdesc_attribute->a_numvals !=1 ) {
		send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
				 "Incorrect read of attribute nTSecurityDescriptor" );
		goto done;
		rc = LDAP_OPERATIONS_ERROR;
        } else {
		ber_dupbv_x( &o_mod->sd, &(secdesc_attribute->a_vals[0]), op->o_tmpmemctx );
        }

        if (objectclass_attribute == NULL || objectclass_attribute->a_numvals < 1) {
		send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
				 "Incorrect read of attribute instanceType" );
		rc = LDAP_OPERATIONS_ERROR;
		goto done;
        } else {
		ber_dupbv_x( &o_mod->object_class,
			    &(objectclass_attribute->a_vals[objectclass_attribute->a_numvals-1]), op->o_tmpmemctx );
        }

        if ( instancetype_attribute == NULL || instancetype_attribute->a_numvals != 1 ) {
		send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
				 "Incorrect read of attribute objectClass" );
		rc = LDAP_OPERATIONS_ERROR;
		goto done;
        } else {
		ber_dupbv_x( &o_mod->instanceType, &(instancetype_attribute->a_vals[0]), op->o_tmpmemctx );
        }
done:
        be_entry_release_r( op, e );
	return rc;
}

static int
opprep_get_add_attrs( Operation *op, SlapReply *rs, opprep_info_add *o_add )
{
	Entry		*e = NULL;
	int rc = LDAP_SUCCESS;
	struct berval parent_dn = { 0, NULL };
	Attribute *secdesc_attribute = NULL;
	Attribute *objectguid_attribute = NULL;

	assert(o_add != NULL);

	rc = be_entry_get_rw( op, &parent_dn, NULL, NULL, 0, &e );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}
	secdesc_attribute = samba_find_attribute( e->e_attrs, "nTSecurityDescriptor" );
	objectguid_attribute = samba_find_attribute( e->e_attrs, "objectGUID" );
	/* it is theoretically possible to have no sd, although not likely,
	 * the other attribuites should always be present */
	if ( secdesc_attribute == NULL ) {
		o_add->parent_sd.bv_len = 0; 
	}
	else if ( secdesc_attribute->a_numvals !=1 ) {
		send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
				 "Incorrect read of attribute nTSecurityDescriptor" );
		rc = LDAP_OPERATIONS_ERROR;
		goto done;
	}
	else {
		ber_dupbv_x( &o_add->parent_sd, &(secdesc_attribute->a_vals[0]), op->o_tmpmemctx );
	}

	if ( objectguid_attribute == NULL || objectguid_attribute->a_numvals < 1 ) {
		send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
				 "Incorrect read of attribute objectGUID" );
		rc = LDAP_OPERATIONS_ERROR;
		goto done;
	}
	else {
		ber_dupbv_x( &o_add->object_guid, &(objectguid_attribute->a_vals[0]), op->o_tmpmemctx );
	}
done:
        be_entry_release_r( op, e );
	return rc;
}


static int
opprep_get_sd( Operation *op, SlapReply *rs, struct berval *dn, struct berval *sd)
{
	Entry		*e = NULL;
	int rc = LDAP_SUCCESS;
	Attribute *secdesc_attribute = NULL;
	BackendDB *db = select_backend( dn, 0 );
	if (db == NULL) {
		/* the dn does not point to a valid backend */
		return LDAP_OPERATIONS_ERROR;
	}

	rc = be_entry_get_rw( op, dn, NULL, NULL, 0, &e );
	if ( rc != LDAP_SUCCESS ) {
		return rc;
	}

	secdesc_attribute = samba_find_attribute( e->e_attrs, "nTSecurityDescriptor" );
	/* it is theoretically possible to have no sd, although not likely */
	if ( secdesc_attribute == NULL ) {
		sd->bv_len = 0; 
	} else if ( secdesc_attribute->a_numvals !=1 ) {
		send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
				 "Incorrect read of attribute nTSecurityDescriptor" );
		rc = LDAP_OPERATIONS_ERROR;
		goto done;
	} else {
		ber_dupbv_x( sd, &(secdesc_attribute->a_vals[0]), op->o_tmpmemctx );
	}
done:
	be_entry_release_r( op, e );
	return rc;
}

static int
opprep_get_parent_sd( Operation *op, SlapReply *rs, struct berval *sd)
{
	struct berval parent_dn = { 0, NULL };
	dnParent(&parent_dn, &op->o_req_dn);
	return opprep_get_sd( op, rs, &parent_dn, sd);
}

static int
opprep_get_new_parent_sd( Operation *op, SlapReply *rs, struct berval *sd)
{
	struct berval parent_dn = { 0, NULL };
	dnParent(&parent_dn, &op->o_req_ndn);
	return opprep_get_sd( op, rs, &parent_dn, sd);
}

static int opprep_set_extra( Operation *op, SlapReply *rs )
{
	/* allocate extra */
	OpExtraOpprep *o_prep = (OpExtraOpprep *)op->o_tmpalloc(sizeof(OpExtraOpprep),
								op->o_tmpmemctx );
	slap_callback *cb;
	int rc = LDAP_SUCCESS, rc2 = LDAP_SUCCESS;
	o_prep->oe_opi = (opprep_info_t *)op->o_tmpalloc(sizeof(opprep_info_t),
							 op->o_tmpmemctx );
	o_prep->oe_opi->sec_token = (DATA_BLOB*)op->o_ctrlsectoken;
	o_prep->oe_opi->sd_flags = op->o_sdflags;
	/*todo set flags if any */
	if (op->o_tag == LDAP_REQ_ADD) {
		int instanceType = samba_find_attribute_int(op->ora_e->e_attrs, "instanceType", 0, 0);
		if (instanceType & INSTANCE_TYPE_IS_NC_HEAD) {
			o_prep->oe_opi->un.add.parent_sd.bv_len = 0;
		} else {
			rc = opprep_get_add_attrs( op, rs, &o_prep->oe_opi->un.add);
		}
	}
	else if (op->o_tag == LDAP_REQ_MODIFY) {
		rc = opprep_get_modify_attrs( op, rs, &o_prep->oe_opi->un.mod);
	}
	else if (op->o_tag == LDAP_REQ_MODRDN) {
		rc = opprep_get_parent_sd( op, rs, &o_prep->oe_opi->un.modrdn.parent_sd);
		rc2 = opprep_get_new_parent_sd( op, rs, &o_prep->oe_opi->un.modrdn.new_parent_sd);
	}
	else if (op->o_tag == LDAP_REQ_DELETE) {
		rc = opprep_get_parent_sd( op, rs, &o_prep->oe_opi->un.del.parent_sd);
	}
	else if (op->o_tag == LDAP_REQ_SEARCH) {
		if (be_issuffix(op->o_bd, &op->o_req_ndn)) {
			/* this is the backend suffix, no parent */
			o_prep->oe_opi->un.search.parent_sd.bv_len = 0;
		} else {
			rc = opprep_get_parent_sd( op, rs, &o_prep->oe_opi->un.search.parent_sd);
		}
	}

	if (rc != LDAP_SUCCESS || rc2 != LDAP_SUCCESS) {
		send_ldap_error( op, rs, LDAP_OPERATIONS_ERROR,
				 "op_prep: Incorrect read of required attributes." );
		return rs->sr_err;
	}
	o_prep->oe.oe_key = (void *)opprep_id;
	LDAP_SLIST_INSERT_HEAD( &op->o_extra, &o_prep->oe, oe_next );
	cb = op->o_tmpcalloc( 1, sizeof( slap_callback ), op->o_tmpmemctx );
	cb->sc_response = slap_null_cb;
	cb->sc_private = NULL;
	cb->sc_cleanup = opprep_cleanup;
	cb->sc_next = op->o_callback;
	op->o_callback = cb;
	return SLAP_CB_CONTINUE;
}

int opprep_initialize(void)
{
	int rc;
	rc = register_supported_control( DSDB_CONTROL_SEC_TOKEN_OID,
					 SLAP_CTRL_SEARCH|SLAP_CTRL_ADD|SLAP_CTRL_DELETE|SLAP_CTRL_RENAME|SLAP_CTRL_MODIFY,
					 NULL,
					 sectoken_parseCtrl, &sectoken_cid );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
		       "op_prep_initialize: Failed to register control (%d)\n",
		       rc, 0, 0 );
		return -1;
	}

	rc = register_supported_control( LDB_CONTROL_SD_FLAGS_OID,
					 SLAP_CTRL_SEARCH|SLAP_CTRL_ADD|SLAP_CTRL_DELETE|SLAP_CTRL_RENAME|SLAP_CTRL_MODIFY,
					 NULL,
					 sdflags_parseCtrl, &sdflags_cid );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
		       "op_prep_initialize: Failed to register control (%d)\n",
		       rc, 0, 0 );
		return -1;
	}

	opprep.on_bi.bi_type = "opprep";
	opprep.on_bi.bi_op_add = opprep_set_extra;
/*	opprep.on_bi.bi_op_modrdn = opprep_set_extra;
	opprep.on_bi.bi_op_modify = opprep_set_extra;
	opprep.on_bi.bi_op_search = opprep_set_extra;
	opprep.on_bi.bi_op_delete = opprep_set_extra; */
	return overlay_register(&opprep);
}


#if SLAPD_OVER_OPPREP == SLAPD_MOD_DYNAMIC
int init_module( int argc, char *argv[] )
{
	return opprep_initialize();
}
#endif /* SLAPD_OVER_OPPREP == SLAPD_MOD_DYNAMIC */

#endif /*SLAPD_OVER_OPPREP*/
