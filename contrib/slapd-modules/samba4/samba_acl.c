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

#include "portable.h"

#ifdef SLAPD_OVER_SAMBA_ACL

#include <stdio.h>

#include "ac/string.h"
#include "ac/socket.h"

#include "slap.h"
#include "config.h"

#include "lutil.h"
#include "ldap_rq.h"
#include "flags.h"
#include "ldb.h"
#include <talloc.h>
#include "samba_security.h"
#include "samba_utils.h"
#include <ndr.h>
#include "ad_schema.h"

static slap_overinst 		samba_acl;

int acl_check_attribute_access(struct security_descriptor *sd,
			      struct dom_sid *rp_sid,
			      uint32_t access_mask,
			      const struct ad_schema_attribute *attr,
			      const struct ad_schema_class *objectclass,
			      struct security_token *token)
{
	int ret;
	NTSTATUS status;
	uint32_t access_granted;
	struct object_tree *root = NULL;
	struct object_tree *new_node = NULL;
	TALLOC_CTX *tmp_ctx = talloc_new(NULL);
	struct GUID oc_schemaIDGUID;
	struct GUID attr_schemaIDGUID;
	struct GUID attributeSecurityGUID;
	/*TODO fix ad_schema so that GUIDs are struct GUID rather than bv_val and avoid this every time */
	GUID_from_string(objectclass->schemaIDGUID.bv_val, &oc_schemaIDGUID);
	GUID_from_string(attr->attributeSecurityGUID.bv_val, &attributeSecurityGUID);
	GUID_from_string(attr->schemaIDGUID.bv_val, &attr_schemaIDGUID);
	if (!insert_in_object_tree(tmp_ctx,
				   &oc_schemaIDGUID,
				   access_mask, NULL,
				   &root)) {
		Debug(LDAP_DEBUG_TRACE, "acl_check_attribute_access: cannot add to object tree schemaIDGUID %s\n",
			      objectclass->schemaIDGUID.bv_val,0,0);
		goto fail;
	}
	new_node = root;

	if (!GUID_all_zero(&attributeSecurityGUID)) {
		if (!insert_in_object_tree(tmp_ctx,
					   &attributeSecurityGUID,
					   access_mask, new_node,
					   &new_node)) {
			Debug(LDAP_DEBUG_TRACE, "acl_check_attribute_access: cannot add to object tree securityGUID %s\n",
			      attr->attributeSecurityGUID.bv_val,0,0);
			goto fail;
		}
	}

	if (!insert_in_object_tree(tmp_ctx,
				   &attr_schemaIDGUID,
				   access_mask, new_node,
				   &new_node)) {
		Debug(LDAP_DEBUG_TRACE, "acl_check_attribute_access: cannot add to object tree attributeGUID %s\n",
			      attr->schemaIDGUID.bv_val,0,0);
		goto fail;
	}

	status = sec_access_check_ds(sd, token,
				     access_mask,
				     &access_granted,
				     root,
				     rp_sid);
	if (!NT_STATUS_IS_OK(status)) {
		ret = LDAP_INSUFFICIENT_ACCESS;
	}
	else {
		ret = LDAP_SUCCESS;
	}
	talloc_free(tmp_ctx);
	return ret;
fail:
	talloc_free(tmp_ctx);
	return LDAP_OPERATIONS_ERROR;
}

int acl_check_objectclass_access(struct security_descriptor *sd,
				struct dom_sid *rp_sid,
				uint32_t access_mask,
				const struct ad_schema_class *objectclass,
				 struct security_token *token,
				 TALLOC_CTX *mem_ctx)
{
	int ret;
	NTSTATUS status;
	uint32_t access_granted;
	struct object_tree *root = NULL;
	struct GUID oc_schemaIDGUID;

	/*TODO fix ad_schema so that GUIDs are struct GUID rather than bv_val and avoid this every time */
	GUID_from_string(objectclass->schemaIDGUID.bv_val, &oc_schemaIDGUID);

	if (!insert_in_object_tree(mem_ctx,
				   &oc_schemaIDGUID,
				   access_mask, NULL,
				   &root)) {
		Debug(LDAP_DEBUG_TRACE, "acl_check_objectclass_access: cannot add to object tree schemaIDGUID %s\n",
			      objectclass->schemaIDGUID.bv_val,0,0);
		goto fail;
	}

	status = sec_access_check_ds(sd, token,
				     access_mask,
				     &access_granted,
				     root,
				     rp_sid);
	if (!NT_STATUS_IS_OK(status)) {
		ret = LDAP_INSUFFICIENT_ACCESS;
	} else {
		ret = LDAP_SUCCESS;
	}
	return ret;
fail:
	return LDAP_OPERATIONS_ERROR;
}

int acl_check_extended_right( struct security_descriptor *sd,
			     struct security_token *token,
			     const char *ext_right,
			     uint32_t right_type,
			     struct dom_sid *sid)
{
	struct GUID right;
	NTSTATUS status;
	uint32_t access_granted;
	struct object_tree *root = NULL;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);

	GUID_from_string(ext_right, &right);

	if (!insert_in_object_tree(mem_ctx, &right, right_type,
				   NULL, &root)) {
		Debug(LDAP_DEBUG_TRACE, "acl_check_extended_right: cannot add to object tree %s\n",
			      ext_right,0,0);
		talloc_free(mem_ctx);
		return LDAP_OPERATIONS_ERROR;
	}
	status = sec_access_check_ds(sd, token,
				     right_type,
				     &access_granted,
				     root,
				     sid);

	if (!NT_STATUS_IS_OK(status)) {
		talloc_free(mem_ctx);
		return LDAP_INSUFFICIENT_ACCESS;
	}
	talloc_free(mem_ctx);
	return LDAP_SUCCESS;
}


int acl_check_access_on_object(struct security_token *token,
			      uint32_t access_mask,
			      struct security_descriptor *sd,
			      struct dom_sid *sid,
			       const struct GUID *guid,
			       TALLOC_CTX *mem_ctx)
{
	struct object_tree *root = NULL;
	NTSTATUS status;
	uint32_t access_granted;

	if (guid) {
		if (!insert_in_object_tree(mem_ctx, guid, access_mask, NULL,
					   &root)) {
			talloc_free(mem_ctx);
			return LDAP_OPERATIONS_ERROR;
		}
	}
	status = sec_access_check_ds(sd, token,
				     access_mask,
				     &access_granted,
				     root,
				     sid);
	if (!NT_STATUS_IS_OK(status)) {
		return LDAP_INSUFFICIENT_ACCESS;
	}
	return LDAP_SUCCESS;
}

static int
samba_acl_op_add( Operation *op, SlapReply *rs )
{
	struct ad_schema_class *objectclass;
	struct berval psd_bv;
	struct security_descriptor *parent_sd = NULL;
	struct dom_sid *sid;
	struct security_token *token;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	Attribute *instanceType = samba_find_attribute(op->ora_e->e_attrs, "instanceType");
	int rc;
	struct GUID oc_schemaIDGUID;

	if (samba_as_system(op)) {
		talloc_free(mem_ctx);
		return SLAP_CB_CONTINUE;
	}

	if (instanceType != NULL) {
		rc = samba_get_parent_sd(op, rs, &instanceType->a_vals[0], &psd_bv);
		unmarshall_sec_desc(mem_ctx, psd_bv.bv_val, psd_bv.bv_len,&parent_sd);
	}

	objectclass = samba_get_structural_class(op);
	/*TODO fix ad_schema so that GUIDs are struct GUID rather than bv_val and avoid this every time */
	GUID_from_string(objectclass->schemaIDGUID.bv_val, &oc_schemaIDGUID);

	token = samba_get_token_from_connection(op);
	sid = samba_get_domain_sid(op, rs, mem_ctx);
	rc = acl_check_access_on_object(token,
					SEC_ADS_CREATE_CHILD,
					parent_sd,
					sid,
					&oc_schemaIDGUID,
					mem_ctx);

	if (rc != LDAP_SUCCESS) {
		rs->sr_err = rc;
		send_ldap_result( op, rs );
		talloc_free(mem_ctx);
		return rc;
	}
	talloc_free(mem_ctx);
	return SLAP_CB_CONTINUE;
}


static int
samba_acl_op_delete( Operation *op, SlapReply *rs )
{

	struct ad_schema_class *objectclass;
	struct berval psd_bv;
	struct security_descriptor *parent_sd = NULL;
	struct security_descriptor *object_sd = NULL;
	struct dom_sid *sid;
	struct security_token *token;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	Attribute *instanceType = samba_find_attribute(op->ora_e->e_attrs, "instanceType");
	int rc1, rc2;
	struct GUID oc_schemaIDGUID;

	if (samba_as_system(op)) {
		talloc_free(mem_ctx);
		return SLAP_CB_CONTINUE;
	}

	if (instanceType != NULL) {
		rc1 = samba_get_parent_sd(op, rs, &instanceType->a_vals[0], &psd_bv);
		unmarshall_sec_desc(mem_ctx, psd_bv.bv_val, psd_bv.bv_len,&parent_sd);
	}

	objectclass = samba_get_structural_class(op);
	/*TODO fix ad_schema so that GUIDs are struct GUID rather than bv_val and avoid this every time */
	GUID_from_string(objectclass->schemaIDGUID.bv_val, &oc_schemaIDGUID);

	token = samba_get_token_from_connection(op);
	sid = samba_get_domain_sid(op, rs, mem_ctx);

	object_sd = samba_get_object_sd( op, rs, mem_ctx );

	rc1 = acl_check_access_on_object(token,
					 SEC_ADS_DELETE_CHILD,
					 parent_sd,
					 sid,
					 &oc_schemaIDGUID,
					 mem_ctx);

	rc2 = acl_check_access_on_object(token,
					 SEC_STD_DELETE,
					 object_sd,
					 sid,
					 NULL,
					 mem_ctx);

	if (rc1 != LDAP_SUCCESS && rc2 != LDAP_SUCCESS) {
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		send_ldap_result( op, rs );
		talloc_free(mem_ctx);
		return rs->sr_err;
	}
	talloc_free(mem_ctx);
	return SLAP_CB_CONTINUE;
}

static int
samba_acl_op_modify( Operation *op, SlapReply *rs )
{
	/* TODO */
	return SLAP_CB_CONTINUE;
}


static int
samba_acl_op_modrdn( Operation *op, SlapReply *rs )
{
	struct ad_schema_class *objectclass;
	struct berval psd_bv;
	struct security_descriptor *parent_sd = NULL;
	struct security_descriptor *new_parent_sd = NULL;
	struct dom_sid *sid;
	struct security_token *token;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	Attribute *instanceType = samba_find_attribute(op->ora_e->e_attrs, "instanceType");
	int rc1, rc2;
	struct GUID oc_schemaIDGUID;

	if (samba_as_system(op)) {
		talloc_free(mem_ctx);
		return SLAP_CB_CONTINUE;
	}

	if (instanceType != NULL) {
		rc1 = samba_get_parent_sd(op, rs, &instanceType->a_vals[0], &psd_bv);
		unmarshall_sec_desc(mem_ctx, psd_bv.bv_val, psd_bv.bv_len,&parent_sd);
	}

	objectclass = samba_get_structural_class(op);
	/*TODO fix ad_schema so that GUIDs are struct GUID rather than bv_val and avoid this every time */
	GUID_from_string(objectclass->schemaIDGUID.bv_val, &oc_schemaIDGUID);

	token = samba_get_token_from_connection(op);
	sid = samba_get_domain_sid(op, rs, mem_ctx);

	new_parent_sd = samba_get_new_parent_sd( op, rs, mem_ctx );
	
	rc1 = acl_check_access_on_object(token,
		SEC_ADS_DELETE_CHILD,
		parent_sd,
		sid,
		&oc_schemaIDGUID,
		mem_ctx);

	rc2 = acl_check_access_on_object(token,
		SEC_ADS_CREATE_CHILD,
		new_parent_sd,
		sid,
		&oc_schemaIDGUID,
		mem_ctx);

	if (rc1 != LDAP_SUCCESS || rc2 != LDAP_SUCCESS) {
		rs->sr_err = LDAP_INSUFFICIENT_ACCESS;
		send_ldap_result( op, rs );
		talloc_free(mem_ctx);
		return rs->sr_err;
	}
	talloc_free(mem_ctx);
	return SLAP_CB_CONTINUE;
	
}

/* TODO this only checks access on base, we need to implement a callback
to check return entry access */
static int
samba_acl_op_search( Operation *op, SlapReply *rs )
{
	struct ad_schema_class *objectclass;
	struct berval psd_bv;
	struct security_descriptor *parent_sd = NULL;
	struct dom_sid *sid;
	struct security_token *token;
	TALLOC_CTX *mem_ctx = talloc_new(NULL);
	Attribute *instanceType = samba_find_attribute(op->ora_e->e_attrs, "instanceType");
	int rc;
	struct GUID oc_schemaIDGUID;

	if (samba_as_system(op)) {
		talloc_free(mem_ctx);
		return SLAP_CB_CONTINUE;
	}

	if (instanceType != NULL) {
		rc = samba_get_parent_sd(op, rs, &instanceType->a_vals[0], &psd_bv);
		unmarshall_sec_desc(mem_ctx, psd_bv.bv_val, psd_bv.bv_len,&parent_sd);
	}

	objectclass = samba_get_structural_class(op);
	/*TODO fix ad_schema so that GUIDs are struct GUID rather than bv_val and avoid this every time */
	GUID_from_string(objectclass->schemaIDGUID.bv_val, &oc_schemaIDGUID);

	token = samba_get_token_from_connection(op);
	sid = samba_get_domain_sid(op, rs, mem_ctx);
	rc = acl_check_access_on_object(token,
					SEC_ADS_LIST,
					parent_sd,
					sid,
					&oc_schemaIDGUID,
					mem_ctx);

	if (rc != LDAP_SUCCESS) {
		rs->sr_err = rc;
		send_ldap_result( op, rs );
		talloc_free(mem_ctx);
		return rc;
	}
	talloc_free(mem_ctx);
	return SLAP_CB_CONTINUE;
}

int samba_acl_initialize(void)
{
	samba_acl.on_bi.bi_type = "samba_acl";
	samba_acl.on_bi.bi_op_add = samba_acl_op_add;
	samba_acl.on_bi.bi_op_modify = samba_acl_op_modify;
	samba_acl.on_bi.bi_op_delete = samba_acl_op_delete;
	samba_acl.on_bi.bi_op_modrdn = samba_acl_op_modrdn;
	samba_acl.on_bi.bi_op_search = samba_acl_op_search;
	Debug(LDAP_DEBUG_TRACE, "samba_acl_initialize\n",0,0,0);
	return overlay_register(&samba_acl);
}


#if SLAPD_OVER_SAMBA_ACL == SLAPD_MOD_DYNAMIC
int init_module( int argc, char *argv[] )
{
	return samba_acl_initialize();
}
#endif /* SLAPD_OVER_SAMBA_ACL == SLAPD_MOD_DYNAMIC */

#endif /*SLAPD_OVER_SAMBA_ACL*/
