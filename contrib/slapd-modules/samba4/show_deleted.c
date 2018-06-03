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

/* A tentative implementation of the "show deleted" and "show recycled" controls */

#include "portable.h"

#ifdef SLAPD_OVER_SHOWDELETED

#include <stdio.h>

#include "ac/string.h"
#include "ac/socket.h"

#include "slap.h"
#include "config.h"

#include "lutil.h"
#include "ldap_rq.h"
#include "ldb.h"

static slap_overinst 		show_deleted;
static int show_deleted_cid;
static int show_recycled_cid;
#define o_show_deleted			o_ctrlflag[show_deleted_cid]
#define o_ctrl_show_deleted		o_controls[show_deleted_cid]
#define o_show_recycled		        o_ctrlflag[show_recycled_cid]
#define o_ctrl_show_recycled		o_controls[show_recycled_cid]


static int
show_deleted_parseCtrl(
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	op->o_show_deleted = SLAP_CONTROL_NONCRITICAL;
	ctrl->ldctl_iscritical = 0;
	return LDAP_SUCCESS;
}

static int
show_recycled_parseCtrl(
	Operation *op,
	SlapReply *rs,
	LDAPControl *ctrl )
{
	op->o_show_recycled = SLAP_CONTROL_NONCRITICAL;
	ctrl->ldctl_iscritical = 0;
	return LDAP_SUCCESS;
}

static int
show_deleted_op_search( Operation *op, SlapReply *rs )
{

/*TODO Implement checking of partition settings, for now we assume
 *recycling is enabled */
	const char deleted_filter[ ] = "(!(isDeleted=TRUE))";
	const char recycled_filter[ ] = "(!(isRecycled=TRUE))";
	struct berval *old_fstring = &op->ors_filterstr;
	struct berval new_fstring;
	char *tmp_ptr;
	Debug( LDAP_DEBUG_ANY,
	       "show_deleted: old filter %s \n", op->ors_filterstr.bv_val, 0, 0 );
	new_fstring.bv_len = old_fstring->bv_len + STRLENOF( "(&" ) + STRLENOF( ")" );
	if ( op->o_show_deleted != 0 && op->o_show_recycled != 0 ) {
		/* nothing to do here, we display both */
		return SLAP_CB_CONTINUE;
	} else if ( op->o_show_recycled != 0 ) {
		/* show isRecycled = TRUE, hide isDeleted=TRUE */
		new_fstring.bv_len += STRLENOF( deleted_filter );
		new_fstring.bv_val = op->o_tmpalloc( new_fstring.bv_len+1, op->o_tmpmemctx );
		tmp_ptr = new_fstring.bv_val;
		tmp_ptr = lutil_strcopy( tmp_ptr, "(&" );
		if ( op->ors_filter && old_fstring->bv_len > 0 ) {
			tmp_ptr = lutil_strcopy( tmp_ptr, old_fstring->bv_val );
		}
		tmp_ptr = lutil_strcopy( tmp_ptr, deleted_filter );
		tmp_ptr = lutil_strcopy( tmp_ptr, ")" );
		*tmp_ptr = '\0';
	} else if ( op->o_show_deleted != 0 ) {
		/* show isDeleted = TRUE, hide isRecycled=TRUE */
		new_fstring.bv_len += STRLENOF( recycled_filter );
		new_fstring.bv_val = op->o_tmpalloc( new_fstring.bv_len+1, op->o_tmpmemctx );
		tmp_ptr = new_fstring.bv_val;
		tmp_ptr = lutil_strcopy( tmp_ptr, "(&" );
		if ( op->ors_filter && old_fstring->bv_len > 0 ) {
			tmp_ptr = lutil_strcopy( tmp_ptr, old_fstring->bv_val );
		}
		tmp_ptr = lutil_strcopy( tmp_ptr, recycled_filter );
		tmp_ptr = lutil_strcopy( tmp_ptr, ")" );
		*tmp_ptr = '\0';
	} else {
		new_fstring.bv_len += STRLENOF( deleted_filter ) + STRLENOF( recycled_filter );
		new_fstring.bv_val = op->o_tmpalloc( new_fstring.bv_len+1, op->o_tmpmemctx );
		tmp_ptr = new_fstring.bv_val;
		tmp_ptr = lutil_strcopy( tmp_ptr, "(&" );
		if ( op->ors_filter && old_fstring->bv_len > 0 ) {
			tmp_ptr = lutil_strcopy( tmp_ptr, old_fstring->bv_val );
		}
		tmp_ptr = lutil_strcopy( tmp_ptr, deleted_filter );
		tmp_ptr = lutil_strcopy( tmp_ptr, recycled_filter );
		tmp_ptr = lutil_strcopy( tmp_ptr, ")" );
		*tmp_ptr = '\0';
	}
	/* todo test later to ensure this does not leak*/
	/*if ( op->ors_filter != NULL) {
	  filter_free_x( op, op->ors_filter, 1 );
	  }*/
	if ( op->ors_filterstr.bv_val != NULL) {
		op->o_tmpfree( op->ors_filterstr.bv_val, op->o_tmpmemctx );
	}
	op->ors_filterstr.bv_len = new_fstring.bv_len;
	op->ors_filterstr.bv_val = new_fstring.bv_val;
	Debug( LDAP_DEBUG_ANY,
	       "show_deleted: new filter %s \n", op->ors_filterstr.bv_val, 0, 0 );
	op->ors_filter = str2filter_x( op, op->ors_filterstr.bv_val );
	assert( op->ors_filter != NULL );
	return SLAP_CB_CONTINUE;
}


int
show_deleted_initialize( void )
{
	int rc;
	rc = register_supported_control( LDB_CONTROL_SHOW_DELETED_OID ,
					 SLAP_CTRL_SEARCH,
					 NULL,
					 show_deleted_parseCtrl, &show_deleted_cid );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
		       "show_deleted_initialize: Failed to register control (%d)\n",
		       rc, 0, 0 );
		return -1;
	}

	rc = register_supported_control( LDB_CONTROL_SHOW_RECYCLED_OID,
					 SLAP_CTRL_SEARCH,
					 NULL,
					 show_recycled_parseCtrl, &show_recycled_cid );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
		       "show_deleted_initialize: Failed to register control (%d)\n",
		       rc, 0, 0 );
		return -1;
	}

	show_deleted.on_bi.bi_type = "show_deleted";
	show_deleted.on_bi.bi_op_search = show_deleted_op_search;
	Debug(LDAP_DEBUG_TRACE, "show_deleted_initialize\n",0,0,0);
	return overlay_register(&show_deleted);
}


#if SLAPD_OVER_SHOWDELETED == SLAPD_MOD_DYNAMIC
int init_module( int argc, char *argv[] )
{
	return show_deleted_initialize();
}
#endif /* SLAPD_OVER_SHOWDELETED == SLAPD_MOD_DYNAMIC */

#endif /*SLAPD_OVER_SHOWDELETED*/
