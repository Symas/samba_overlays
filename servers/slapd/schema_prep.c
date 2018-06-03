/* schema_prep.c - load builtin schema */
/* $OpenLDAP$ */
/* This work is part of OpenLDAP Software <http://www.openldap.org/>.
 *
 * Copyright 1998-2018 The OpenLDAP Foundation.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted only as authorized by the OpenLDAP
 * Public License.
 *
 * A copy of this license is available in the file LICENSE in the
 * top-level directory of the distribution or, alternatively, at
 * <http://www.OpenLDAP.org/license.html>.
 */

#include "portable.h"

#include <stdio.h>

#include <ac/ctype.h>
#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"

#define OCDEBUG 0

int schema_init_done = 0;

struct slap_internal_schema slap_schema;

static int
oidValidate(
	Syntax *syntax,
	struct berval *in )
{
	struct berval val = *in;

	if( val.bv_len == 0 ) {
		/* disallow empty strings */
		return LDAP_INVALID_SYNTAX;
	}

	if( DESC_LEADCHAR( val.bv_val[0] ) ) {
		val.bv_val++;
		val.bv_len--;
		if ( val.bv_len == 0 ) return LDAP_SUCCESS;

		while( DESC_CHAR( val.bv_val[0] ) ) {
			val.bv_val++;
			val.bv_len--;

			if ( val.bv_len == 0 ) return LDAP_SUCCESS;
		}

	} else {
		int sep = 0;
		while( OID_LEADCHAR( val.bv_val[0] ) ) {
			val.bv_val++;
			val.bv_len--;

			if ( val.bv_val[-1] != '0' ) {
				while ( OID_LEADCHAR( val.bv_val[0] )) {
					val.bv_val++;
					val.bv_len--;
				}
			}

			if( val.bv_len == 0 ) {
				if( sep == 0 ) break;
				return LDAP_SUCCESS;
			}

			if( !OID_SEPARATOR( val.bv_val[0] )) break;

			sep++;
			val.bv_val++;
			val.bv_len--;
		}
	}

	return LDAP_INVALID_SYNTAX;
}


static int objectClassPretty(
	Syntax *syntax,
	struct berval *in,
	struct berval *out,
	void *ctx )
{
	ObjectClass *oc;

	if( oidValidate( NULL, in )) return LDAP_INVALID_SYNTAX;

	oc = oc_bvfind( in );
	if( oc == NULL ) return LDAP_INVALID_SYNTAX;

	ber_dupbv_x( out, &oc->soc_cname, ctx );
	return LDAP_SUCCESS;
}

static int
attributeTypeMatch(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	struct berval *a = (struct berval *) assertedValue;
	AttributeType *at = at_bvfind( value );
	AttributeType *asserted = at_bvfind( a );

	if( asserted == NULL ) {
		if( OID_LEADCHAR( *a->bv_val ) ) {
			/* OID form, return FALSE */
			*matchp = 1;
			return LDAP_SUCCESS;
		}

		/* desc form, return undefined */
		return LDAP_INVALID_SYNTAX;
	}

	if ( at == NULL ) {
		/* unrecognized stored value */
		return LDAP_INVALID_SYNTAX;
	}

	*matchp = ( asserted != at );
	return LDAP_SUCCESS;
}

static int
matchingRuleMatch(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	struct berval *a = (struct berval *) assertedValue;
	MatchingRule *mrv = mr_bvfind( value );
	MatchingRule *asserted = mr_bvfind( a );

	if( asserted == NULL ) {
		if( OID_LEADCHAR( *a->bv_val ) ) {
			/* OID form, return FALSE */
			*matchp = 1;
			return LDAP_SUCCESS;
		}

		/* desc form, return undefined */
		return LDAP_INVALID_SYNTAX;
	}

	if ( mrv == NULL ) {
		/* unrecognized stored value */
		return LDAP_INVALID_SYNTAX;
	}

	*matchp = ( asserted != mrv );
	return LDAP_SUCCESS;
}

static int
objectClassMatch(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	struct berval *a = (struct berval *) assertedValue;
	ObjectClass *oc = oc_bvfind( value );
	ObjectClass *asserted = oc_bvfind( a );

	if( asserted == NULL ) {
		if( OID_LEADCHAR( *a->bv_val ) ) {
			/* OID form, return FALSE */
			*matchp = 1;
			return LDAP_SUCCESS;
		}

		/* desc form, return undefined */
		return LDAP_INVALID_SYNTAX;
	}

	if ( oc == NULL ) {
		/* unrecognized stored value */
		return LDAP_INVALID_SYNTAX;
	}

	*matchp = ( asserted != oc );
	return LDAP_SUCCESS;
}

static int
objectSubClassMatch(
	int *matchp,
	slap_mask_t flags,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *value,
	void *assertedValue )
{
	struct berval *a = (struct berval *) assertedValue;
	ObjectClass *oc = oc_bvfind( value );
	ObjectClass *asserted = oc_bvfind( a );

	if( asserted == NULL ) {
		if( OID_LEADCHAR( *a->bv_val ) ) {
			/* OID form, return FALSE */
			*matchp = 1;
			return LDAP_SUCCESS;
		}

		/* desc form, return undefined */
		return LDAP_INVALID_SYNTAX;
	}

	if ( oc == NULL ) {
		/* unrecognized stored value */
		return LDAP_INVALID_SYNTAX;
	}

	if( SLAP_MR_IS_VALUE_OF_ATTRIBUTE_SYNTAX( flags ) ) {
		*matchp = ( asserted != oc );
	} else {
		*matchp = !is_object_subclass( asserted, oc );
	}

	return LDAP_SUCCESS;
}

static int objectSubClassIndexer( 
	slap_mask_t use,
	slap_mask_t mask,
	Syntax *syntax,
	MatchingRule *mr,
	struct berval *prefix,
	BerVarray values,
	BerVarray *keysp,
	void *ctx )
{
	int rc, noc, i;
	BerVarray ocvalues;
	ObjectClass **socs;
	
	for( noc=0; values[noc].bv_val != NULL; noc++ ) {
		/* just count em */;
	}

	/* over allocate */
	socs = slap_sl_malloc( (noc+16) * sizeof( ObjectClass * ), ctx );

	/* initialize */
	for( i=0; i<noc; i++ ) {
		socs[i] = oc_bvfind( &values[i] );
	}

	/* expand values */
	for( i=0; i<noc; i++ ) {
		int j;
		ObjectClass *oc = socs[i];
		if( oc == NULL || oc->soc_sups == NULL ) continue;
		
		for( j=0; oc->soc_sups[j] != NULL; j++ ) {
			int found = 0;
			ObjectClass *sup = oc->soc_sups[j];
			int k;

			for( k=0; k<noc; k++ ) {
				if( sup == socs[k] ) {
					found++;
					break;
				}
			}

			if( !found ) {
				socs = slap_sl_realloc( socs,
					sizeof( ObjectClass * ) * (noc+2), ctx );

				assert( k == noc );
				socs[noc++] = sup;
			}
		}
	}

	ocvalues = slap_sl_malloc( sizeof( struct berval ) * (noc+1), ctx );
	/* copy values */
	for( i=0; i<noc; i++ ) {
		if ( socs[i] )
			ocvalues[i] = socs[i]->soc_cname;
		else
			ocvalues[i] = values[i];
	}
	BER_BVZERO( &ocvalues[i] );

	rc = octetStringIndexer( use, mask, syntax, mr,
		prefix, ocvalues, keysp, ctx );

	slap_sl_free( ocvalues, ctx );
	slap_sl_free( socs, ctx );
	return rc;
}

#ifdef ENABLE_SAMBA_COMPATIBILITY
static int normalize_to_int32(
    slap_mask_t use,
    Syntax *syntax,
    MatchingRule *mr,
    struct berval *val,
    struct berval *out,
    void *ctx)
{
	int32_t i, len;
	char val_buf[ LDAP_PVT_INTTYPE_CHARS( unsigned long ) ];
	struct berval tmp;
	i = (int32_t) strtoll((char *)val->bv_val, NULL, 0);
	len = sprintf(val_buf, "%d", i);

	tmp.bv_len = len;
	tmp.bv_val = &val_buf;
	ber_dupbv_x( out, &tmp, ctx );
	return LDAP_SUCCESS;
}

static int
validate_dSHeuristics(
	Syntax *syntax,
	struct berval *in )
{
	int i;
	for (i = 10; i <=90; i+=10) {
		char ch[3];
		snprintf(ch, 2, "%d", (i/10));
		if ((in->bv_len >= i) &&
		    (in->bv_val[i-1] != ch[0])) {
			return LDAP_CONSTRAINT_VIOLATION;
		}
	}
	return LDAP_SUCCESS;
}
#endif

#define objectSubClassFilter octetStringFilter

static ObjectClassSchemaCheckFN rootDseObjectClass;
static ObjectClassSchemaCheckFN aliasObjectClass;
static ObjectClassSchemaCheckFN referralObjectClass;
static ObjectClassSchemaCheckFN subentryObjectClass;
#ifdef LDAP_DYNAMIC_OBJECTS
static ObjectClassSchemaCheckFN dynamicObjectClass;
#endif

static struct slap_schema_oc_map {
	char *ssom_name;
	char *ssom_defn;
	ObjectClassSchemaCheckFN *ssom_check;
	slap_mask_t ssom_flags;
	size_t ssom_offset;
} oc_map[] = {
#ifndef ENABLE_SAMBA_COMPATIBILITY
	{ "top", "( 2.5.6.0 NAME 'top' "
			"DESC 'top of the superclass chain' "
			"ABSTRACT MUST objectClass )",
		0, 0, offsetof(struct slap_internal_schema, si_oc_top) },
#else
	{ "top", "( 2.5.6.0 NAME 'top' "
			"DESC 'top of the superclass chain' "
			"ABSTRACT MUST ( objectClass ) "
                        "MAY ( instanceType $ nTSecurityDescriptor $ objectCategory $ adminDescription $ "
	  "adminDisplayName $ allowedAttributes $ allowedAttributesEffective $ allowedChildClasses $ "
	  "allowedChildClassesEffective $ bridgeheadServerListBL $ canonicalName $ cn $ description $ "
	  "directReports $ displayName $ displayNamePrintable $ dSASignature $ dSCorePropagationData $ "
	  "extensionName $ flags $ fromEntry $ frsComputerReferenceBL $ fRSMemberReferenceBL $ "
	  "fSMORoleOwner $ isCriticalSystemObject $ isDeleted $ isPrivilegeHolder $ lastKnownParent $ "
	  "managedObjects $ masteredBy $ mS-DS-ConsistencyChildCount $ mS-DS-ConsistencyGuid $ "
	  "msCOM-PartitionSetLink $ msCOM-UserLink $ msDS-Approx-Immed-Subordinates $ msDs-masteredBy $ "
	  "msDS-MembersForAzRoleBL $ msDS-NCReplCursors $ msDS-NCReplInboundNeighbors $ msDS-NCReplOutboundNeighbors $ "
	  "msDS-NcType $ msDS-NonMembersBL $ msDS-ObjectReferenceBL $ msDS-OperationsForAzRoleBL $ "
	  "msDS-OperationsForAzTaskBL $ msDS-ReplAttributeMetaData $ msDS-ReplValueMetaData $ msDS-TasksForAzRoleBL $ "
	  "msDS-TasksForAzTaskBL $ name $ netbootSCPBL $ nonSecurityMemberBL $ objectVersion $ otherWellKnownObjects $ "
	  "ownerBL $ parentGUID $ partialAttributeDeletionList $ partialAttributeSet $ possibleInferiors $ "
	  "proxiedObjectName $ proxyAddresses $ queryPolicyBL $ replPropertyMetaData $ replUpToDateVector $ "
	  "repsFrom $ repsTo $ revision $ sDRightsEffective $ serverReferenceBL $ showInAdvancedViewOnly $ "
	  "siteObjectBL $ subRefs $ systemFlags $ url $ uSNDSALastObjRemoved $ USNIntersite $ uSNLastObjRem $ "
	  "uSNSource $ wbemPath $ wellKnownObjects $ wWWHomePage $ msSFU30PosixMemberOf $ "
	  "msDFSR-ComputerReferenceBL $ msDFSR-MemberReferenceBL $ msDS-EnabledFeatureBL $ "
	  "msDS-LastKnownRDN $ msDS-HostServiceAccountBL $ msDS-OIDToGroupLinkBl $ msDS-LocalEffectiveRecycleTime $ "
	  "msDS-LocalEffectiveDeletionTime $ isRecycled $ msDS-PSOApplied $ msDS-PrincipalName $ "
	  "msDS-RevealedListBL $ msDS-AuthenticatedToAccountlist $ msDS-IsPartialReplicaFor $ msDS-IsDomainFor $ "
	  "msDS-IsFullReplicaFor $ msDS-RevealedDSAs $ msDS-KrbTgtLinkBl $ whenCreated $ whenChanged $ "
	  "uSNCreated $ uSNChanged $ subschemaSubEntry $ structuralObjectClass $ objectGUID $ distinguishedName $ "
	  "modifyTimeStamp $ memberOf $ createTimeStamp $ msDS-NC-RO-Replica-Locations-BL ) )",
		0, 0, offsetof(struct slap_internal_schema, si_oc_top) },
#endif /*LDAP_AD_COMPATIBILITY*/
	{ "extensibleObject", "( 1.3.6.1.4.1.1466.101.120.111 "
			"NAME 'extensibleObject' "
			"DESC 'RFC4512: extensible object' "
			"SUP top AUXILIARY )",
		0, SLAP_OC_OPERATIONAL,
		offsetof(struct slap_internal_schema, si_oc_extensibleObject) },
	{ "alias", "( 2.5.6.1 NAME 'alias' "
			"DESC 'RFC4512: an alias' "
			"SUP top STRUCTURAL "
			"MUST aliasedObjectName )",
		aliasObjectClass, SLAP_OC_ALIAS|SLAP_OC_OPERATIONAL,
		offsetof(struct slap_internal_schema, si_oc_alias) },
	{ "referral", "( 2.16.840.1.113730.3.2.6 NAME 'referral' "
			"DESC 'namedref: named subordinate referral' "
			"SUP top STRUCTURAL MUST ref )",
		referralObjectClass, SLAP_OC_REFERRAL|SLAP_OC_OPERATIONAL,
		offsetof(struct slap_internal_schema, si_oc_referral) },
	{ "LDAProotDSE", "( 1.3.6.1.4.1.4203.1.4.1 "
			"NAME ( 'OpenLDAProotDSE' 'LDAProotDSE' ) "
			"DESC 'OpenLDAP Root DSE object' "
			"SUP top STRUCTURAL MAY cn )",
		rootDseObjectClass, SLAP_OC_OPERATIONAL,
		offsetof(struct slap_internal_schema, si_oc_rootdse) },
	{ "subentry", "( 2.5.17.0 NAME 'subentry' "
			"DESC 'RFC3672: subentry' "
			"SUP top STRUCTURAL "
			"MUST ( cn $ subtreeSpecification ) )",
		subentryObjectClass, SLAP_OC_SUBENTRY|SLAP_OC_OPERATIONAL,
		offsetof(struct slap_internal_schema, si_oc_subentry) },
#ifndef ENABLE_SAMBA_COMPATIBILITY
	{ "subschema", "( 2.5.20.1 NAME 'subschema' "
		"DESC 'RFC4512: controlling subschema (sub)entry' "
		"AUXILIARY "
		"MAY ( dITStructureRules $ nameForms $ dITContentRules $ "
			"objectClasses $ attributeTypes $ matchingRules $ "
			"matchingRuleUse ) )",
		subentryObjectClass, SLAP_OC_OPERATIONAL,
		offsetof(struct slap_internal_schema, si_oc_subschema) },
#else /* temporarily (maybe) butchered so provisioning could pass, got to fix it later */
	{ "subschema", "( 2.5.20.1 NAME 'subschema' "
		"DESC 'RFC4512: controlling subschema (sub)entry' "
		"MAY ( dITStructureRules $ nameForms $ dITContentRules $ "
			"objectClasses $ attributeTypes $ matchingRules $ "
			"matchingRuleUse $ modifyTimeStamp $ extendedAttributeInfo $ extendedClassInfo ) )",
		0, SLAP_OC_OPERATIONAL,
		offsetof(struct slap_internal_schema, si_oc_subschema) },
#endif /*LDAP_AD_COMPATIBILITY*/
#ifdef LDAP_COLLECTIVE_ATTRIBUTES
	{ "collectiveAttributeSubentry", "( 2.5.17.2 "
			"NAME 'collectiveAttributeSubentry' "
			"DESC 'RFC3671: collective attribute subentry' "
			"AUXILIARY )",
		subentryObjectClass,
		SLAP_OC_COLLECTIVEATTRIBUTESUBENTRY|SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
		offsetof( struct slap_internal_schema,
			si_oc_collectiveAttributeSubentry) },
#endif
#ifdef LDAP_DYNAMIC_OBJECTS
	{ "dynamicObject", "( 1.3.6.1.4.1.1466.101.119.2 "
			"NAME 'dynamicObject' "
			"DESC 'RFC2589: Dynamic Object' "
			"SUP top AUXILIARY )",
		dynamicObjectClass, SLAP_OC_DYNAMICOBJECT,
		offsetof(struct slap_internal_schema, si_oc_dynamicObject) },
#endif
	{ "glue", "( 1.3.6.1.4.1.4203.666.3.4 "
			"NAME 'glue' "
			"DESC 'Glue Entry' "
			"SUP top STRUCTURAL )",
		0, SLAP_OC_GLUE|SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
		offsetof(struct slap_internal_schema, si_oc_glue) },
	{ "syncConsumerSubentry", "( 1.3.6.1.4.1.4203.666.3.5 "
			"NAME 'syncConsumerSubentry' "
			"DESC 'Persistent Info for SyncRepl Consumer' "
			"AUXILIARY "
			"MAY syncreplCookie )",
		0, SLAP_OC_SYNCCONSUMERSUBENTRY|SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
		offsetof(struct slap_internal_schema, si_oc_syncConsumerSubentry) },
	{ "syncProviderSubentry", "( 1.3.6.1.4.1.4203.666.3.6 "
			"NAME 'syncProviderSubentry' "
			"DESC 'Persistent Info for SyncRepl Producer' "
			"AUXILIARY "
			"MAY contextCSN )",
		0, SLAP_OC_SYNCPROVIDERSUBENTRY|SLAP_OC_OPERATIONAL|SLAP_OC_HIDE,
		offsetof(struct slap_internal_schema, si_oc_syncProviderSubentry) },

	{ NULL, NULL, NULL, 0, 0 }
};

static AttributeTypeSchemaCheckFN rootDseAttribute;
static AttributeTypeSchemaCheckFN aliasAttribute;
static AttributeTypeSchemaCheckFN referralAttribute;
static AttributeTypeSchemaCheckFN subentryAttribute;
static AttributeTypeSchemaCheckFN administrativeRoleAttribute;
#ifdef LDAP_DYNAMIC_OBJECTS
static AttributeTypeSchemaCheckFN dynamicAttribute;
#endif

static struct slap_schema_ad_map {
	char *ssam_name;
	char *ssam_defn;
	AttributeTypeSchemaCheckFN *ssam_check;
	slap_mask_t ssam_flags;
	slap_syntax_validate_func *ssam_syn_validate;
	slap_syntax_transform_func *ssam_syn_pretty;
	slap_mr_convert_func *ssam_mr_convert;
	slap_mr_normalize_func *ssam_mr_normalize;
	slap_mr_match_func *ssam_mr_match;
	slap_mr_indexer_func *ssam_mr_indexer;
	slap_mr_filter_func *ssam_mr_filter;
	size_t ssam_offset;
} ad_map[] = {
	{ "objectClass", "( 2.5.4.0 NAME 'objectClass' "
			"DESC 'RFC4512: object classes of the entity' "
			"EQUALITY objectIdentifierMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		NULL, SLAP_AT_FINAL,
		oidValidate, objectClassPretty,
		NULL, NULL, objectSubClassMatch,
			objectSubClassIndexer, objectSubClassFilter,
		offsetof(struct slap_internal_schema, si_ad_objectClass) },

	/* user entry operational attributes */
	{ "structuralObjectClass", "( 2.5.21.9 NAME 'structuralObjectClass' "
			"DESC 'RFC4512: structural object class of entry' "
			"EQUALITY objectIdentifierMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 "
#ifndef ENABLE_SAMBA_COMPATIBILITY
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
#else
	  "SINGLE-VALUE )",
#endif /* todo this will be restored to no-user-modificartion eventually when we adapt provisioning */
		NULL, 0,
		oidValidate, objectClassPretty,
		NULL, NULL, objectSubClassMatch,
			objectSubClassIndexer, objectSubClassFilter,
		offsetof(struct slap_internal_schema, si_ad_structuralObjectClass) },
	{ "createTimestamp", "( 2.5.18.1 NAME 'createTimestamp' "
			"DESC 'RFC4512: time which object was created' "
			"EQUALITY generalizedTimeMatch "
			"ORDERING generalizedTimeOrderingMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 "
#ifndef ENABLE_SAMBA_COMPATIBILITY
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
#else
	  "SINGLE-VALUE )",
#endif /* todo this will be restored to no-user-modificartion eventually */
		NULL, SLAP_AT_MANAGEABLE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_createTimestamp) },
	{ "modifyTimestamp", "( 2.5.18.2 NAME 'modifyTimestamp' "
			"DESC 'RFC4512: time which object was last modified' "
			"EQUALITY generalizedTimeMatch "
			"ORDERING generalizedTimeOrderingMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 "
#ifndef ENABLE_SAMBA_COMPATIBILITY
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
#else
	  "SINGLE-VALUE )",
#endif /* todo this will be restored to no-user-modificartion eventually */
		NULL, SLAP_AT_MANAGEABLE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_modifyTimestamp) },
	{ "creatorsName", "( 2.5.18.3 NAME 'creatorsName' "
			"DESC 'RFC4512: name of creator' "
			"EQUALITY distinguishedNameMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		NULL, SLAP_AT_MANAGEABLE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_creatorsName) },
	{ "modifiersName", "( 2.5.18.4 NAME 'modifiersName' "
			"DESC 'RFC4512: name of last modifier' "
			"EQUALITY distinguishedNameMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		NULL, SLAP_AT_MANAGEABLE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_modifiersName) },
	{ "hasSubordinates", "( 2.5.18.9 NAME 'hasSubordinates' "
			"DESC 'X.501: entry has children' "
			"EQUALITY booleanMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		NULL, SLAP_AT_DYNAMIC,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_hasSubordinates) },
	{ "subschemaSubentry", "( 2.5.18.10 NAME 'subschemaSubentry' "
			"DESC 'RFC4512: name of controlling subschema entry' "
			"EQUALITY distinguishedNameMatch "
#ifndef ENABLE_SAMBA_COMPATIBILITY
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE "
			"NO-USER-MODIFICATION USAGE directoryOperation )",
#else
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )",
#endif /* todo probably remove this in the future */
		NULL, SLAP_AT_DYNAMIC,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_subschemaSubentry) },
#ifdef LDAP_COLLECTIVE_ATTRIBUTES
	{ "collectiveAttributeSubentries", "( 2.5.18.12 "
			"NAME 'collectiveAttributeSubentries' "
			"DESC 'RFC3671: collective attribute subentries' "
			"EQUALITY distinguishedNameMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
			"NO-USER-MODIFICATION USAGE directoryOperation )",
		NULL, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_collectiveSubentries) },
	{ "collectiveExclusions", "( 2.5.18.7 NAME 'collectiveExclusions' "
			"DESC 'RFC3671: collective attribute exclusions' "
			"EQUALITY objectIdentifierMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 "
			"USAGE directoryOperation )",
		NULL, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_collectiveExclusions) },
#endif

	{ "entryDN", "( 1.3.6.1.1.20 NAME 'entryDN' "   
			"DESC 'DN of the entry' "
			"EQUALITY distinguishedNameMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		NULL, SLAP_AT_DYNAMIC,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_entryDN) },
	{ "entryUUID", "( 1.3.6.1.1.16.4 NAME 'entryUUID' "   
			"DESC 'UUID of the entry' "
			"EQUALITY UUIDMatch "
			"ORDERING UUIDOrderingMatch "
			"SYNTAX 1.3.6.1.1.16.1 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		NULL, SLAP_AT_MANAGEABLE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_entryUUID) },
	{ "entryCSN", "( 1.3.6.1.4.1.4203.666.1.7 NAME 'entryCSN' "
			"DESC 'change sequence number of the entry content' "
			"EQUALITY CSNMatch "
			"ORDERING CSNOrderingMatch "
			"SYNTAX 1.3.6.1.4.1.4203.666.11.2.1{64} "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		NULL, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_entryCSN) },
	{ "namingCSN", "( 1.3.6.1.4.1.4203.666.1.13 NAME 'namingCSN' "
			"DESC 'change sequence number of the entry naming (RDN)' "
			"EQUALITY CSNMatch "
			"ORDERING CSNOrderingMatch "
			"SYNTAX 1.3.6.1.4.1.4203.666.11.2.1{64} "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		NULL, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_namingCSN) },

#ifdef LDAP_SUPERIOR_UUID
	{ "superiorUUID", "( 1.3.6.1.4.1.4203.666.1.11 NAME 'superiorUUID' "   
			"DESC 'UUID of the superior entry' "
			"EQUALITY UUIDMatch "
			"ORDERING UUIDOrderingMatch "
			"SYNTAX 1.3.6.1.1.16.1 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE directoryOperation )",
		NULL, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_superiorUUID) },
#endif

	{ "syncreplCookie", "( 1.3.6.1.4.1.4203.666.1.23 "
			"NAME 'syncreplCookie' "
			"DESC 'syncrepl Cookie for shadow copy' "
			"EQUALITY octetStringMatch "
			"ORDERING octetStringOrderingMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
		NULL, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_syncreplCookie) },

	{ "contextCSN", "( 1.3.6.1.4.1.4203.666.1.25 "
			"NAME 'contextCSN' "
			"DESC 'the largest committed CSN of a context' "
			"EQUALITY CSNMatch "
			"ORDERING CSNOrderingMatch "
			"SYNTAX 1.3.6.1.4.1.4203.666.11.2.1{64} "
			"NO-USER-MODIFICATION USAGE dSAOperation )",
		NULL, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_contextCSN) },

#ifdef LDAP_SYNC_TIMESTAMP
	{ "syncTimestamp", "( 1.3.6.1.4.1.4203.666.1.26 NAME 'syncTimestamp' "
			"DESC 'Time which object was replicated' "
			"EQUALITY generalizedTimeMatch "
			"ORDERING generalizedTimeOrderingMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_syncTimestamp) },
#endif

	/* root DSE attributes */
	{ "altServer", "( 1.3.6.1.4.1.1466.101.120.6 NAME 'altServer' "
			"DESC 'RFC4512: alternative servers' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26 USAGE dSAOperation )",
		rootDseAttribute, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_altServer) },
	{ "namingContexts", "( 1.3.6.1.4.1.1466.101.120.5 "
			"NAME 'namingContexts' "
			"DESC 'RFC4512: naming contexts' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 USAGE dSAOperation )",
		rootDseAttribute, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_namingContexts) },
	{ "supportedControl", "( 1.3.6.1.4.1.1466.101.120.13 "
			"NAME 'supportedControl' "
			"DESC 'RFC4512: supported controls' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )",
		rootDseAttribute, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedControl) },
	{ "supportedExtension", "( 1.3.6.1.4.1.1466.101.120.7 "
			"NAME 'supportedExtension' "
			"DESC 'RFC4512: supported extended operations' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 USAGE dSAOperation )",
		rootDseAttribute, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedExtension) },
	{ "supportedLDAPVersion", "( 1.3.6.1.4.1.1466.101.120.15 "
			"NAME 'supportedLDAPVersion' "
			"DESC 'RFC4512: supported LDAP versions' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 USAGE dSAOperation )",
		rootDseAttribute, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedLDAPVersion) },
	{ "supportedSASLMechanisms", "( 1.3.6.1.4.1.1466.101.120.14 "
			"NAME 'supportedSASLMechanisms' "
			"DESC 'RFC4512: supported SASL mechanisms'"
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 USAGE dSAOperation )",
		rootDseAttribute, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedSASLMechanisms) },
	{ "supportedFeatures", "( 1.3.6.1.4.1.4203.1.3.5 "
			"NAME 'supportedFeatures' "
			"DESC 'RFC4512: features supported by the server' "
			"EQUALITY objectIdentifierMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 "
			"USAGE dSAOperation )",
		rootDseAttribute, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_supportedFeatures) },
	{ "monitorContext", "( 1.3.6.1.4.1.4203.666.1.10 "
			"NAME 'monitorContext' "
			"DESC 'monitor context' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
			"EQUALITY distinguishedNameMatch "
			"SINGLE-VALUE NO-USER-MODIFICATION "
			"USAGE dSAOperation )",
		rootDseAttribute, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_monitorContext) },
	{ "configContext", "( 1.3.6.1.4.1.4203.1.12.2.1 "
			"NAME 'configContext' "
			"DESC 'config context' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
			"EQUALITY distinguishedNameMatch "
			"SINGLE-VALUE NO-USER-MODIFICATION "
			"USAGE dSAOperation )",
		rootDseAttribute, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_configContext) },
	{ "vendorName", "( 1.3.6.1.1.4 NAME 'vendorName' "
			"DESC 'RFC3045: name of implementation vendor' "
			"EQUALITY caseExactMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
			"SINGLE-VALUE NO-USER-MODIFICATION "
			"USAGE dSAOperation )",
		rootDseAttribute, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_vendorName) },
	{ "vendorVersion", "( 1.3.6.1.1.5 NAME 'vendorVersion' "
			"DESC 'RFC3045: version of implementation' "
			"EQUALITY caseExactMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
			"SINGLE-VALUE NO-USER-MODIFICATION "
			"USAGE dSAOperation )",
		rootDseAttribute, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_vendorVersion) },

	/* subentry attributes */
	{ "administrativeRole", "( 2.5.18.5 NAME 'administrativeRole' "
			"DESC 'RFC3672: administrative role' "
			"EQUALITY objectIdentifierMatch "
			"USAGE directoryOperation "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.38 )",
		administrativeRoleAttribute, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_administrativeRole) },
	{ "subtreeSpecification", "( 2.5.18.6 NAME 'subtreeSpecification' "
			"DESC 'RFC3672: subtree specification' "
			"SINGLE-VALUE "
			"USAGE directoryOperation "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.45 )",
		subentryAttribute, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_subtreeSpecification) },

	/* subschema subentry attributes */
	{ "dITStructureRules", "( 2.5.21.1 NAME 'dITStructureRules' "
			"DESC 'RFC4512: DIT structure rules' "
			"EQUALITY integerFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.17 "
			"USAGE directoryOperation ) ",
		subentryAttribute, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_ditStructureRules) },
	{ "dITContentRules", "( 2.5.21.2 NAME 'dITContentRules' "
			"DESC 'RFC4512: DIT content rules' "
			"EQUALITY objectIdentifierFirstComponentMatch "
#ifndef ENABLE_SAMBA_COMPATIBILITY /* temporary, to be removed */
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.16 USAGE directoryOperation )",
#else
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.16 )",
#endif
		subentryAttribute, SLAP_AT_HIDE,
		oidValidate, NULL,
		NULL, NULL, objectClassMatch, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_ditContentRules) },
	{ "matchingRules", "( 2.5.21.4 NAME 'matchingRules' "
			"DESC 'RFC4512: matching rules' "
			"EQUALITY objectIdentifierFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.30 USAGE directoryOperation )",
		subentryAttribute, 0,
		oidValidate, NULL,
		NULL, NULL, matchingRuleMatch, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_matchingRules) },
	{ "attributeTypes", "( 2.5.21.5 NAME 'attributeTypes' "
			"DESC 'RFC4512: attribute types' "
			"EQUALITY objectIdentifierFirstComponentMatch "
#ifndef ENABLE_SAMBA_COMPATIBILITY /* temporary, to be removed */
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.3 USAGE directoryOperation )",
#else
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.3 )",
#endif
		subentryAttribute, 0,
		oidValidate, NULL,
		NULL, NULL, attributeTypeMatch, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_attributeTypes) },
	{ "objectClasses", "( 2.5.21.6 NAME 'objectClasses' "
			"DESC 'RFC4512: object classes' "
			"EQUALITY objectIdentifierFirstComponentMatch "
#ifndef ENABLE_SAMBA_COMPATIBILITY /* temporary, to be removed */
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.37 USAGE directoryOperation )",
#else
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.37 )",
#endif
		subentryAttribute, 0,
		oidValidate, NULL,
		NULL, NULL, objectClassMatch, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_objectClasses) },
	{ "nameForms", "( 2.5.21.7 NAME 'nameForms' "
			"DESC 'RFC4512: name forms ' "
			"EQUALITY objectIdentifierFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.35 USAGE directoryOperation )",
		subentryAttribute, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_nameForms) },
	{ "matchingRuleUse", "( 2.5.21.8 NAME 'matchingRuleUse' "
			"DESC 'RFC4512: matching rule uses' "
			"EQUALITY objectIdentifierFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.31 USAGE directoryOperation )",
		subentryAttribute, 0,
		oidValidate, NULL,
		NULL, NULL, matchingRuleMatch, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_matchingRuleUse) },

	{ "ldapSyntaxes", "( 1.3.6.1.4.1.1466.101.120.16 NAME 'ldapSyntaxes' "
			"DESC 'RFC4512: LDAP syntaxes' "
			"EQUALITY objectIdentifierFirstComponentMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.54 USAGE directoryOperation )",
		subentryAttribute, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_ldapSyntaxes) },

	/* knowledge information */
	{ "aliasedObjectName", "( 2.5.4.1 "
			"NAME ( 'aliasedObjectName' 'aliasedEntryName' ) "
			"DESC 'RFC4512: name of aliased object' "
			"EQUALITY distinguishedNameMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )",
		aliasAttribute, SLAP_AT_FINAL,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_aliasedObjectName) },
#ifndef ENABLE_SAMBA_COMPATIBILITY
	{ "ref", "( 2.16.840.1.113730.3.1.34 NAME 'ref' "
#else
	  { "ref", "( 2.16.840.1.113730.3.1.250 NAME 'ref' "
#endif 
			"DESC 'RFC3296: subordinate referral URL' "
			"EQUALITY caseExactMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
			"USAGE distributedOperation )",
		referralAttribute, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_ref) },

	/* access control internals */
	{ "entry", "( 1.3.6.1.4.1.4203.1.3.1 "
			"NAME 'entry' "
			"DESC 'OpenLDAP ACL entry pseudo-attribute' "
			"SYNTAX 1.3.6.1.4.1.4203.1.1.1 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
		NULL, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_entry) },
	{ "children", "( 1.3.6.1.4.1.4203.1.3.2 "
			"NAME 'children' "
			"DESC 'OpenLDAP ACL children pseudo-attribute' "
			"SYNTAX 1.3.6.1.4.1.4203.1.1.1 "
			"SINGLE-VALUE NO-USER-MODIFICATION USAGE dSAOperation )",
		NULL, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_children) },

	/* access control externals */
	{ "authzTo", "( 1.3.6.1.4.1.4203.666.1.8 "
			"NAME ( 'authzTo' 'saslAuthzTo' ) "
			"DESC 'proxy authorization targets' "
			"EQUALITY authzMatch "
			"SYNTAX 1.3.6.1.4.1.4203.666.2.7 "
			"X-ORDERED 'VALUES' "
			"USAGE distributedOperation )",
		NULL, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_saslAuthzTo) },
	{ "authzFrom", "( 1.3.6.1.4.1.4203.666.1.9 "
			"NAME ( 'authzFrom' 'saslAuthzFrom' ) "
			"DESC 'proxy authorization sources' "
			"EQUALITY authzMatch "
			"SYNTAX 1.3.6.1.4.1.4203.666.2.7 "
			"X-ORDERED 'VALUES' "
			"USAGE distributedOperation )",
		NULL, SLAP_AT_HIDE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_saslAuthzFrom) },

#ifdef LDAP_DYNAMIC_OBJECTS
	{ "entryTtl", "( 1.3.6.1.4.1.1466.101.119.3 NAME 'entryTtl' "
			"DESC 'RFC2589: entry time-to-live' "
#ifndef ENABLE_SAMBA_COMPATIBILITY
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE "
			"NO-USER-MODIFICATION USAGE dSAOperation )",
#else
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
#endif /* restore this later */
		dynamicAttribute, SLAP_AT_MANAGEABLE,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_entryTtl) },
	{ "dynamicSubtrees", "( 1.3.6.1.4.1.1466.101.119.4 "
			"NAME 'dynamicSubtrees' "
			"DESC 'RFC2589: dynamic subtrees' "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 NO-USER-MODIFICATION "
			"USAGE dSAOperation )",
		rootDseAttribute, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_dynamicSubtrees) },
#endif

	/* userApplication attributes (which system schema depends upon) */
	{ "distinguishedName", "( 2.5.4.49 NAME 'distinguishedName' "
			"DESC 'RFC4519: common supertype of DN attributes' "
			"EQUALITY distinguishedNameMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		NULL, SLAP_AT_ABSTRACT,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_distinguishedName) },
#ifndef ENABLE_SAMBA_COMPATIBILITY
	{ "name", "( 2.5.4.41 NAME 'name' "
			"DESC 'RFC4519: common supertype of name attributes' "
			"EQUALITY caseIgnoreMatch "
			"SUBSTR caseIgnoreSubstringsMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{32768} )",
		NULL, SLAP_AT_ABSTRACT,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_name) },
#else
	  /* this is RDN in AD/Samba */
	{ "name", "( 1.2.840.113556.1.4.1 NAME 'name' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_name) },
#endif
	{ "cn", "( 2.5.4.3 NAME ( 'cn' 'commonName' ) "
			"DESC 'RFC4519: common name(s) for which the entity is known by' "
			"SUP name )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_cn) },
	{ "uid", "( 0.9.2342.19200300.100.1.1 NAME ( 'uid' 'userid' ) "
			"DESC 'RFC4519: user identifier' "
			"EQUALITY caseIgnoreMatch "
			"SUBSTR caseIgnoreSubstringsMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{256} )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_uid) },
	{ "uidNumber", /* for ldapi:// */
		"( 1.3.6.1.1.1.1.0 NAME 'uidNumber' "
    		"DESC 'RFC2307: An integer uniquely identifying a user "
				"in an administrative domain' "
    		"EQUALITY integerMatch "
    		"ORDERING integerOrderingMatch "
    		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_uidNumber) },
	{ "gidNumber", /* for ldapi:// */
		"( 1.3.6.1.1.1.1.1 NAME 'gidNumber' "
    		"DESC 'RFC2307: An integer uniquely identifying a group "
				"in an administrative domain' "
    		"EQUALITY integerMatch "
    		"ORDERING integerOrderingMatch "
    		"SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_gidNumber) },
	{ "userPassword", "( 2.5.4.35 NAME 'userPassword' "
			"DESC 'RFC4519/2307: password of user' "
			"EQUALITY octetStringMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.40{128} )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_userPassword) },

	{ "labeledURI", "( 1.3.6.1.4.1.250.1.57 NAME 'labeledURI' "
			"DESC 'RFC2079: Uniform Resource Identifier with optional label' "
			"EQUALITY caseExactMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_labeledURI) },

#ifdef SLAPD_AUTHPASSWD
	{ "authPassword", "( 1.3.6.1.4.1.4203.1.3.4 "
			"NAME 'authPassword' "
			"DESC 'RFC3112: authentication password attribute' "
			"EQUALITY 1.3.6.1.4.1.4203.1.2.2 "
			"SYNTAX 1.3.6.1.4.1.4203.1.1.2 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_authPassword) },
	{ "supportedAuthPasswordSchemes", "( 1.3.6.1.4.1.4203.1.3.3 "
			"NAME 'supportedAuthPasswordSchemes' "
			"DESC 'RFC3112: supported authPassword schemes' "
			"EQUALITY caseExactIA5Match "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.26{32} "
			"USAGE dSAOperation )",
		subschemaAttribute, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_authPasswordSchemes) },
#endif

	{ "description", "( 2.5.4.13 NAME 'description' "
			"DESC 'RFC4519: descriptive information' "
			"EQUALITY caseIgnoreMatch "
			"SUBSTR caseIgnoreSubstringsMatch "
			"SYNTAX 1.3.6.1.4.1.1466.115.121.1.15{1024} )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_description) },

	{ "seeAlso", "( 2.5.4.34 NAME 'seeAlso' "
			"DESC 'RFC4519: DN of related object' "
			"SUP distinguishedName )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_seeAlso) },

	{ "x509PrivateKey", "( 1.3.6.1.4.1.4203.666.1.60 "
			"NAME 'x509PrivateKey' "
			"DESC 'X.509 private key, use ;binary' "
			"EQUALITY privateKeyMatch "
			"SYNTAX 1.3.6.1.4.1.4203.666.2.13 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_x509PrivateKey) },

#ifdef ENABLE_SAMBA_COMPATIBILITY
	  	/* samba attributes for top */
	{ "instanceType", "( 1.2.840.113556.1.2.1 NAME 'instanceType' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_instanceType) },

	{ "nTSecurityDescriptor", "( 1.2.840.113556.1.2.281 NAME 'nTSecurityDescriptor' "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.5 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_nTSecurityDescriptor) },
	
       { "objectCategory", "( 1.2.840.113556.1.4.782 NAME 'objectCategory' "
         "EQUALITY distinguishedNameMatch "
	 "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_objectCategory) },

	{ "adminDescription", "( 1.2.840.113556.1.2.226 NAME 'adminDescription' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_adminDescription) },

	{ "adminDisplayName", "( 1.2.840.113556.1.2.194 NAME 'adminDisplayName' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_adminDisplayName) },

	{ "allowedAttributes", "( 1.2.840.113556.1.4.913 NAME 'allowedAttributes' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_allowedAttributes) },

	{ "allowedAttributesEffective", "( 1.2.840.113556.1.4.914 NAME 'allowedAttributesEffective' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_allowedAttributesEffective) },

	{ "allowedChildClasses", "( 1.2.840.113556.1.4.911 NAME 'allowedChildClasses' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_allowedChildClasses) },

	{ "allowedChildClassesEffective", "( 1.2.840.113556.1.4.912 NAME 'allowedChildClassesEffective' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_allowedChildClassesEffective) },

	{ "bridgeheadServerListBL", "( 1.2.840.113556.1.4.820 NAME 'bridgeheadServerListBL' "
	  "EQUALITY distinguishedNameMatch " 
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_bridgeheadServerListBL) },

	{ "canonicalName", "( 1.2.840.113556.1.4.916 NAME 'canonicalName' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_canonicalName) },

	{ "directReports", "( 1.2.840.113556.1.2.436 NAME 'directReports' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_directReports) },

	{ "displayName", "( 1.2.840.113556.1.2.13 NAME 'displayName' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_displayName) },

	{ "displayNamePrintable", "( 1.2.840.113556.1.2.353 NAME 'displayNamePrintable' "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_displayNamePrintable) },
	
	{ "dSASignature", "(1.2.840.113556.1.2.74 NAME 'dSASignature' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_dSASignature) },

	{ "dSCorePropagationData", "(1.2.840.113556.1.4.1357 NAME 'dSCorePropagationData' "
	  "EQUALITY generalizedTimeMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_dSCorePropagationData) },

	{ "extensionName", "( 1.2.840.113556.1.2.227 NAME 'extensionName' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_extensionName) },
	
	{ "flags", "( 1.2.840.113556.1.4.38 NAME 'flags' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_flags) },

	{ "fromEntry", "( 1.2.840.113556.1.4.910 NAME 'fromEntry' "
	  "EQUALITY booleanMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_fromEntry) },

	{ "frsComputerReferenceBL", "( 1.2.840.113556.1.4.870 NAME 'frsComputerReferenceBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_frsComputerReferenceBL) },

	{ "fRSMemberReferenceBL", "( 1.2.840.113556.1.4.876 NAME 'fRSMemberReferenceBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_fRSMemberReferenceBL) },

	{ "fSMORoleOwner", "( 1.2.840.113556.1.4.369 NAME 'fSMORoleOwner' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_fSMORoleOwner) },

	{ "isCriticalSystemObject", "( 1.2.840.113556.1.4.868 NAME 'isCriticalSystemObject' "
	  "EQUALITY booleanMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_isCriticalSystemObject) },

	{ "isDeleted", "( 1.2.840.113556.1.2.48 NAME 'isDeleted' "
	  "EQUALITY booleanMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_isDeleted) },

	{ "isPrivilegeHolder", "( 1.2.840.113556.1.4.638 NAME 'isPrivilegeHolder' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_isPrivilegeHolder) },

	{ "lastKnownParent", "( 1.2.840.113556.1.4.781 NAME 'lastKnownParent' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_lastKnownParent) },

	{ "managedObjects", "( 1.2.840.113556.1.4.654 NAME 'managedObjects' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_managedObjects) },

	{ "masteredBy", "( 1.2.840.113556.1.4.1409 NAME 'masteredBy' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_masteredBy) },
	
	{ "mS-DS-ConsistencyChildCount", "( 1.2.840.113556.1.4.1361 NAME 'mS-DS-ConsistencyChildCount' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_mS_DS_ConsistencyChildCount) },

	{ "mS-DS-ConsistencyGuid", "( 1.2.840.113556.1.4.1360 NAME 'mS-DS-ConsistencyGuid' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_mS_DS_ConsistencyGuid) },

	{ "msCOM-PartitionSetLink", "( 1.2.840.113556.1.4.1424 NAME 'msCOM-PartitionSetLink' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_msCOM_PartitionSetLink) },

	{ "msCOM-UserLink", "( 1.2.840.113556.1.4.1425 NAME 'msCOM-UserLink' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_msCOM_UserLink) },

	{ "msDS-Approx-Immed-Subordinates", "( 1.2.840.113556.1.4.1669 NAME 'msDS-Approx-Immed-Subordinates' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_msDS_Approx_Immed_Subordinates) },

	{ "msDs-masteredBy", "( 1.2.840.113556.1.4.1837 NAME 'msDs-masteredBy' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_msDs_masteredBy) },

	{ "msDS-MembersForAzRoleBL", "( 1.2.840.113556.1.4.1807 NAME 'msDS-MembersForAzRoleBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_msDS_MembersForAzRoleBL) },

	{ "msDS-NCReplCursors", "( 1.2.840.113556.1.4.1704 NAME 'msDS-NCReplCursors' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_msDS_NCReplCursors) },

	{ "msDS-NCReplInboundNeighbors", "( 1.2.840.113556.1.4.1705 NAME 'msDS-NCReplInboundNeighbors' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
		NULL, 0,
		NULL, NULL,
		NULL, NULL, NULL, NULL, NULL,
		offsetof(struct slap_internal_schema, si_ad_msDS_NCReplInboundNeighbors) },

	{ "msDS-NCReplOutboundNeighbors", "( 1.2.840.113556.1.4.1706 NAME 'msDS-NCReplOutboundNeighbors' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_NCReplOutboundNeighbors) },

	{ "msDS-NcType", "( 1.2.840.113556.1.4.2024 NAME 'msDS-NcType' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_NcType) },
   
	{ "msDS-NonMembersBL", "( 1.2.840.113556.1.4.1794 NAME 'msDS-NonMembersBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_NonMembersBL) },

	{ "msDS-ObjectReferenceBL", "( 1.2.840.113556.1.4.1841 NAME 'msDS-ObjectReferenceBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_ObjectReferenceBL) },

	{ "msDS-OperationsForAzRoleBL", "( 1.2.840.113556.1.4.1813 NAME 'msDS-OperationsForAzRoleBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_OperationsForAzRoleBL) },

	{ "msDS-OperationsForAzTaskBL", "( 1.2.840.113556.1.4.1809 NAME 'msDS-OperationsForAzTaskBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_OperationsForAzTaskBL) },

	{ "msDS-ReplAttributeMetaData", "( 1.2.840.113556.1.4.1707 NAME 'msDS-ReplAttributeMetaData' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_ReplAttributeMetaData) },

	{ "msDS-ReplValueMetaData", "( 1.2.840.113556.1.4.1708 NAME 'msDS-ReplValueMetaData' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema,si_ad_msDS_ReplValueMetaData ) },


	{ "msDS-TasksForAzRoleBL", "( 1.2.840.113556.1.4.1815 NAME 'msDS-TasksForAzRoleBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_TasksForAzRoleBL) },

	{ "msDS-TasksForAzTaskBL", "( 1.2.840.113556.1.4.1811 NAME 'msDS-TasksForAzTaskBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_TasksForAzTaskBL) },

	{ "netbootSCPBL", "( 1.2.840.113556.1.4.864 NAME 'netbootSCPBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_netbootSCPBL) },

	{ "nonSecurityMemberBL", "( 1.2.840.113556.1.4.531 NAME 'nonSecurityMemberBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_nonSecurityMemberBL) },

	{ "objectVersion", "( 1.2.840.113556.1.2.76 NAME 'objectVersion' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_objectVersion) },

	{ "otherWellKnownObjects", "( 1.2.840.113556.1.4.1359 NAME 'otherWellKnownObjects' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_otherWellKnownObjects) },

	{ "ownerBL", "( 1.2.840.113556.1.2.104 NAME 'ownerBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_ownerBL) },

	{ "parentGUID", "( 1.2.840.113556.1.4.1224 NAME 'parentGUID' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_parentGUID) },

	{ "partialAttributeDeletionList", "( 1.2.840.113556.1.4.663 NAME 'partialAttributeDeletionList' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_partialAttributeDeletionList) },

	{ "partialAttributeSet", "( 1.2.840.113556.1.4.640 NAME 'partialAttributeSet' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_partialAttributeSet) },

	{ "possibleInferiors", "( 1.2.840.113556.1.4.915 NAME 'possibleInferiors' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_possibleInferiors) },

	{ "proxiedObjectName", "( 1.2.840.113556.1.4.1249 NAME 'proxiedObjectName' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_proxiedObjectName) },

       { "proxyAddresses", "( 1.2.840.113556.1.2.210 NAME 'proxyAddresses' "
	 "EQUALITY caseIgnoreMatch "
	 "SUBSTR caseIgnoreSubstringsMatch "
	 "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_proxyAddresses) },

	{ "queryPolicyBL", "( 1.2.840.113556.1.4.608 NAME 'queryPolicyBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_queryPolicyBL) },

	{ "replPropertyMetaData", "( 1.2.840.113556.1.4.3 NAME 'replPropertyMetaData' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_replPropertyMetaData) },

	{ "replUpToDateVector", "( 1.2.840.113556.1.4.4 NAME 'replUpToDateVector' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_replUpToDateVector) },

	{ "repsFrom", "( 1.2.840.113556.1.2.91 NAME 'repsFrom' "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_repsFrom) },

	{ "repsTo", "( 1.2.840.113556.1.2.83 NAME 'repsTo' "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_repsTo) },

	{ "revision", "( 1.2.840.113556.1.4.145 NAME 'revision' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_revision) },

	{ "sDRightsEffective", "( 1.2.840.113556.1.4.1304 NAME 'sDRightsEffective' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_sDRightsEffective) },


	{ "serverReferenceBL", "( 1.2.840.113556.1.4.516 NAME 'serverReferenceBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_serverReferenceBL) },

	{ "showInAdvancedViewOnly", "( 1.2.840.113556.1.2.169 NAME 'showInAdvancedViewOnly' "
	  "EQUALITY booleanMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_showInAdvancedViewOnly) },

	{ "siteObjectBL", "( 1.2.840.113556.1.4.513 NAME 'siteObjectBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_siteObjectBL) },

	{ "subRefs", "( 1.2.840.113556.1.2.7 NAME 'subRefs' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_subRefs) },

	{ "systemFlags", "( 1.2.840.113556.1.4.375 NAME 'systemFlags' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, normalize_to_int32, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_systemFlags) },


	{ "url", "( 1.2.840.113556.1.4.749 NAME 'url' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_url) },

	{ "uSNDSALastObjRemoved", "( 1.2.840.113556.1.2.267 NAME 'uSNDSALastObjRemoved' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_uSNDSALastObjRemoved) },

	{ "USNIntersite", "( 1.2.840.113556.1.2.469 NAME 'USNIntersite' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_USNIntersite) },

	{ "uSNLastObjRem", "( 1.2.840.113556.1.2.121 NAME 'uSNLastObjRem' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_uSNLastObjRem) },

	{ "uSNSource", "( 1.2.840.113556.1.4.896 NAME 'uSNSource' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_uSNSource) },

	{ "wbemPath", "( 1.2.840.113556.1.4.301 NAME 'wbemPath' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_wbemPath) },

	{ "wellKnownObjects", "( 1.2.840.113556.1.4.618 NAME 'wellKnownObjects' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_wellKnownObjects) },

	{ "wWWHomePage", "( 1.2.840.113556.1.2.464 NAME 'wWWHomePage' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_wWWHomePage) },

	{ "msSFU30PosixMemberOf", "( 1.2.840.113556.1.6.18.1.347 NAME 'msSFU30PosixMemberOf' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msSFU30PosixMemberOf) },

	{ "msDFSR-ComputerReferenceBL", "( 1.2.840.113556.1.6.13.3.103 NAME 'msDFSR-ComputerReferenceBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDFSR_ComputerReferenceBL) },

	  { "msDFSR-MemberReferenceBL", "( 1.2.840.113556.1.6.13.3.102 NAME 'msDFSR-MemberReferenceBL' "
	    "EQUALITY distinguishedNameMatch "
	    "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDFSR_MemberReferenceBL) },

	{ "msDS-EnabledFeatureBL", "( 1.2.840.113556.1.4.2069 NAME 'msDS-EnabledFeatureBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_EnabledFeatureBL) },

	{ "msDS-LastKnownRDN", "( 1.2.840.113556.1.4.2067 NAME 'msDS-LastKnownRDN' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_LastKnownRDN) },

	{ "msDS-HostServiceAccountBL", "( 1.2.840.113556.1.4.2057 NAME 'msDS-HostServiceAccountBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_HostServiceAccountBL) },

	{ "msDS-OIDToGroupLinkBl", "( 1.2.840.113556.1.4.2052 NAME 'msDS-OIDToGroupLinkBl' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_OIDToGroupLinkBl) },

	{ "msDS-LocalEffectiveRecycleTime", "( 1.2.840.113556.1.4.2060 NAME 'msDS-LocalEffectiveRecycleTime' "
	  "EQUALITY generalizedTimeMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_LocalEffectiveRecycleTime) },

	{ "msDS-LocalEffectiveDeletionTime", "( 1.2.840.113556.1.4.2059 NAME 'msDS-LocalEffectiveDeletionTime' "
	  "EQUALITY generalizedTimeMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_LocalEffectiveDeletionTime) },

	{ "isRecycled", "( 1.2.840.113556.1.4.2058 NAME 'isRecycled' "
	  "EQUALITY booleanMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 SINGLE-VALUE)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_isRecycled) },

	{ "msDS-PSOApplied", "( 1.2.840.113556.1.4.2021 NAME 'msDS-PSOApplied' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_PSOApplied) },

	{ "msDS-PrincipalName", "( 1.2.840.113556.1.4.1865 NAME 'msDS-PrincipalName' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 SINGLE-VALUE)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_PrincipalName) },

	{ "msDS-RevealedListBL", "( 1.2.840.113556.1.4.1975 NAME 'msDS-RevealedListBL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_RevealedListBL) },

	{ "msDS-AuthenticatedToAccountlist", "( 1.2.840.113556.1.4.1957 NAME 'msDS-AuthenticatedToAccountlist' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_AuthenticatedToAccountlist) },

	{ "msDS-IsPartialReplicaFor", "( 1.2.840.113556.1.4.1934 NAME 'msDS-IsPartialReplicaFor' "
	   "EQUALITY distinguishedNameMatch "
	   "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_IsPartialReplicaFor) },

	{ "msDS-IsDomainFor", "( 1.2.840.113556.1.4.1933 NAME 'msDS-IsDomainFor' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_IsDomainFor) },

	{ "msDS-IsFullReplicaFor", "(1.2.840.113556.1.4.1932 NAME 'msDS-IsFullReplicaFor' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_IsFullReplicaFor) },

	{ "msDS-RevealedDSAs", "( 1.2.840.113556.1.4.1930 NAME 'msDS-RevealedDSAs' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_RevealedDSAs) },

       { "msDS-KrbTgtLinkBl", "(1.2.840.113556.1.4.1931 NAME 'msDS-KrbTgtLinkBl' "
	 "EQUALITY distinguishedNameMatch "
	 "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_KrbTgtLinkBl) },

	{ "whenCreated", "( 1.2.840.113556.1.2.2 NAME 'whenCreated' "
	  "EQUALITY generalizedTimeMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_whenCreated) },

	{ "whenChanged", "(  1.2.840.113556.1.2.3 NAME 'whenChanged' "
	  "EQUALITY generalizedTimeMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 SINGLE-VALUE)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_whenChanged) },

	{ "uSNCreated", "( 1.2.840.113556.1.2.19 NAME 'uSNCreated' "
	  "EQUALITY integerMatch "
	  "SYNTAX  1.3.6.1.4.1.1466.115.121.1.27 SINGLE-VALUE)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_uSNCreated) },

	{ "uSNChanged", "( 1.2.840.113556.1.2.120 NAME 'uSNChanged' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27  SINGLE-VALUE)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_uSNChanged) },

	{ "objectGUID", "( 1.2.840.113556.1.4.2 NAME 'objectGUID' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 SINGLE-VALUE)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_objectGUID) },

	{ "msDS-NC-RO-Replica-Locations-BL", "( 1.2.840.113556.1.4.1968 NAME 'msDS-NC-RO-Replica-Locations-BL' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_msDS_NC_RO_Replica_Locations_BL) },

	{ "memberOf", "( 1.2.840.113556.1.2.102 NAME 'memberOf' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_memberOf) },

	  { "extendedClassInfo", "( 1.2.840.113556.1.4.908 NAME 'extendedClassInfo' "
	    "EQUALITY caseIgnoreMatch "
	    "SUBSTR caseIgnoreSubstringsMatch "
	    "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_extendedClassInfo) },

	  { "extendedAttributeInfo", "( 1.2.840.113556.1.4.909 NAME 'extendedAttributeInfo' "
	    "EQUALITY caseIgnoreMatch "
	    "SUBSTR caseIgnoreSubstringsMatch "
	    "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15)",
	  NULL, 0,
	  NULL, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_extendedAttributeInfo) },

	  { "groupType", "( 1.2.840.113556.1.4.750 NAME 'groupType' "
	    "EQUALITY integerMatch "
	    "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	    "SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, normalize_to_int32, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_groupType) },

	  { "primaryGroupID", "( 1.2.840.113556.1.4.98 NAME 'primaryGroupID' "
	    "EQUALITY integerMatch "
	    "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	    "SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, normalize_to_int32, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_primaryGroupID) },

	  { "userAccountControl", "( 1.2.840.113556.1.4.8 NAME 'userAccountControl' "
	    "EQUALITY integerMatch "
	    "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	    "SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, normalize_to_int32, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_userAccountControl) },

	   { "sAMAccountType", "( 1.2.840.113556.1.4.302 NAME 'sAMAccountType' "
	    "EQUALITY integerMatch "
	    "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	    "SINGLE-VALUE )",
	  NULL, 0,
	  NULL, NULL,
	  NULL, normalize_to_int32, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_sAMAccountType) },

	  { "dSHeuristics", "( 1.2.840.113556.1.2.212 NAME 'dSHeuristics' "
	    "EQUALITY caseIgnoreMatch "
	    "SUBSTR caseIgnoreSubstringsMatch "
	    "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
	    "SINGLE-VALUE )",
	  NULL, 0,
	  validate_dSHeuristics, NULL,
	  NULL, NULL, NULL, NULL, NULL,
	  offsetof(struct slap_internal_schema, si_ad_dSHeuristics) },
#endif /*ENABLE_SAMBA_COMPATIBILITY */

	{ NULL, NULL, NULL, 0, NULL, NULL, NULL, NULL, NULL, NULL, NULL, 0 }
};

static AttributeType slap_at_undefined = {
	{ "1.1.1", NULL, "Catchall for undefined attribute types", 1, NULL,
		NULL, NULL, NULL, NULL,
		0, 0, 0, 1, LDAP_SCHEMA_DSA_OPERATION, NULL }, /* LDAPAttributeType */
	BER_BVC("UNDEFINED"), /* cname */
	NULL, /* sup */
	NULL, /* subtypes */
	NULL, NULL, NULL, NULL,	/* matching rules routines */
	NULL, /* syntax (will be set later to "octetString") */
	NULL, /* schema check function */
	NULL, /* oidmacro */
	NULL, /* soidmacro */
	SLAP_AT_ABSTRACT|SLAP_AT_FINAL,	/* mask */
	{ NULL }, /* next */
	NULL /* attribute description */
	/* mutex (don't know how to initialize it :) */
};

static AttributeType slap_at_proxied = {
	{ "1.1.1", NULL, "Catchall for undefined proxied attribute types", 1, NULL,
		NULL, NULL, NULL, NULL,
		0, 0, 0, 0, LDAP_SCHEMA_USER_APPLICATIONS, NULL }, /* LDAPAttributeType */
	BER_BVC("PROXIED"), /* cname */
	NULL, /* sup */
	NULL, /* subtypes */
	NULL, NULL, NULL, NULL,	/* matching rules routines (will be set later) */
	NULL, /* syntax (will be set later to "octetString") */
	NULL, /* schema check function */
	NULL, /* oidmacro */
	NULL, /* soidmacro */
	SLAP_AT_ABSTRACT|SLAP_AT_FINAL,	/* mask */
	{ NULL }, /* next */
	NULL /* attribute description */
	/* mutex (don't know how to initialize it :) */
};

static struct slap_schema_mr_map {
	char *ssmm_name;
	size_t ssmm_offset;
} mr_map[] = {
	{ "caseExactIA5Match",
		offsetof(struct slap_internal_schema, si_mr_caseExactIA5Match) },
	{ "caseExactMatch",
		offsetof(struct slap_internal_schema, si_mr_caseExactMatch) },
	{ "caseExactSubstringsMatch",
		offsetof(struct slap_internal_schema, si_mr_caseExactSubstringsMatch) },
	{ "distinguishedNameMatch",
		offsetof(struct slap_internal_schema, si_mr_distinguishedNameMatch) },
	{ "dnSubtreeMatch",
		offsetof(struct slap_internal_schema, si_mr_dnSubtreeMatch) },
	{ "dnOneLevelMatch",
		offsetof(struct slap_internal_schema, si_mr_dnOneLevelMatch) },
	{ "dnSubordinateMatch",
		offsetof(struct slap_internal_schema, si_mr_dnSubordinateMatch) },
	{ "dnSuperiorMatch",
		offsetof(struct slap_internal_schema, si_mr_dnSuperiorMatch) },
	{ "integerMatch",
		offsetof(struct slap_internal_schema, si_mr_integerMatch) },
	{ "integerFirstComponentMatch",
		offsetof(struct slap_internal_schema,
			si_mr_integerFirstComponentMatch) },
	{ "objectIdentifierFirstComponentMatch",
		offsetof(struct slap_internal_schema,
			si_mr_objectIdentifierFirstComponentMatch) },
	{ "caseIgnoreMatch",
		offsetof(struct slap_internal_schema, si_mr_caseIgnoreMatch) },
	{ "caseIgnoreListMatch",
		offsetof(struct slap_internal_schema, si_mr_caseIgnoreListMatch) },
	{ NULL, 0 }
};

static struct slap_schema_syn_map {
	char *sssm_name;
	size_t sssm_offset;
} syn_map[] = {
	{ "1.3.6.1.4.1.1466.115.121.1.15",
		offsetof(struct slap_internal_schema, si_syn_directoryString) },
	{ "1.3.6.1.4.1.1466.115.121.1.12",
		offsetof(struct slap_internal_schema, si_syn_distinguishedName) },
	{ "1.3.6.1.4.1.1466.115.121.1.27",
		offsetof(struct slap_internal_schema, si_syn_integer) },
	{ "1.3.6.1.4.1.1466.115.121.1.40",
		offsetof(struct slap_internal_schema, si_syn_octetString) },
	{ "1.3.6.1.4.1.1466.115.121.1.3",
		offsetof(struct slap_internal_schema, si_syn_attributeTypeDesc) },
	{ "1.3.6.1.4.1.1466.115.121.1.16",
		offsetof(struct slap_internal_schema, si_syn_ditContentRuleDesc) },
	{ "1.3.6.1.4.1.1466.115.121.1.54",
		offsetof(struct slap_internal_schema, si_syn_ldapSyntaxDesc) },
	{ "1.3.6.1.4.1.1466.115.121.1.30",
		offsetof(struct slap_internal_schema, si_syn_matchingRuleDesc) },
	{ "1.3.6.1.4.1.1466.115.121.1.31",
		offsetof(struct slap_internal_schema, si_syn_matchingRuleUseDesc) },
	{ "1.3.6.1.4.1.1466.115.121.1.35",
		offsetof(struct slap_internal_schema, si_syn_nameFormDesc) },
	{ "1.3.6.1.4.1.1466.115.121.1.37",
		offsetof(struct slap_internal_schema, si_syn_objectClassDesc) },
	{ "1.3.6.1.4.1.1466.115.121.1.17",
		offsetof(struct slap_internal_schema, si_syn_ditStructureRuleDesc) },
	{ NULL, 0 }
};

int
slap_schema_load( void )
{
	int i;

	for( i=0; syn_map[i].sssm_name; i++ ) {
		Syntax ** synp = (Syntax **)
			&(((char *) &slap_schema)[syn_map[i].sssm_offset]);

		assert( *synp == NULL );

		*synp = syn_find( syn_map[i].sssm_name );

		if( *synp == NULL ) {
			fprintf( stderr, "slap_schema_load: Syntax: "
				"No syntax \"%s\" defined in schema\n",
				syn_map[i].sssm_name );
			return LDAP_INVALID_SYNTAX;
		}
	}

	for( i=0; mr_map[i].ssmm_name; i++ ) {
		MatchingRule ** mrp = (MatchingRule **)
			&(((char *) &slap_schema)[mr_map[i].ssmm_offset]);

		assert( *mrp == NULL );

		*mrp = mr_find( mr_map[i].ssmm_name );

		if( *mrp == NULL ) {
			fprintf( stderr, "slap_schema_load: MatchingRule: "
				"No matching rule \"%s\" defined in schema\n",
				mr_map[i].ssmm_name );
			return LDAP_INAPPROPRIATE_MATCHING;
		}
	}

	slap_at_undefined.sat_syntax = slap_schema.si_syn_octetString;
	slap_schema.si_at_undefined = &slap_at_undefined;

	slap_at_proxied.sat_equality = mr_find( "octetStringMatch" );
	slap_at_proxied.sat_approx = mr_find( "octetStringMatch" );
	slap_at_proxied.sat_ordering = mr_find( "octetStringOrderingMatch" );
	slap_at_proxied.sat_substr = mr_find( "octetStringSubstringsMatch" );
	slap_at_proxied.sat_syntax = slap_schema.si_syn_octetString;
	slap_schema.si_at_proxied = &slap_at_proxied;

	ldap_pvt_thread_mutex_init( &ad_index_mutex );
	ldap_pvt_thread_mutex_init( &ad_undef_mutex );
	ldap_pvt_thread_mutex_init( &oc_undef_mutex );

	for( i=0; ad_map[i].ssam_name; i++ ) {
		assert( ad_map[i].ssam_defn != NULL );
		{
			LDAPAttributeType *at;
			int		code;
			const char	*err;

			at = ldap_str2attributetype( ad_map[i].ssam_defn,
				&code, &err, LDAP_SCHEMA_ALLOW_ALL );
			if ( !at ) {
				fprintf( stderr,
					"slap_schema_load: AttributeType \"%s\": %s before %s\n",
					 ad_map[i].ssam_name, ldap_scherr2str(code), err );
				return code;
			}

			if ( at->at_oid == NULL ) {
				fprintf( stderr, "slap_schema_load: "
					"AttributeType \"%s\": no OID\n",
					ad_map[i].ssam_name );
				ldap_attributetype_free( at );
				return LDAP_OTHER;
			}

			code = at_add( at, 0, NULL, NULL, &err );
			if ( code ) {
				ldap_attributetype_free( at );
				fprintf( stderr, "slap_schema_load: AttributeType "
					"\"%s\": %s: \"%s\"\n",
					 ad_map[i].ssam_name, scherr2str(code), err );
				return code;
			}
			ldap_memfree( at );
		}
		{
			int rc;
			const char *text;
			Syntax *syntax = NULL;

			AttributeDescription ** adp = (AttributeDescription **)
				&(((char *) &slap_schema)[ad_map[i].ssam_offset]);

			assert( *adp == NULL );

			rc = slap_str2ad( ad_map[i].ssam_name, adp, &text );
			if( rc != LDAP_SUCCESS ) {
				fprintf( stderr, "slap_schema_load: AttributeType \"%s\": "
					"not defined in schema\n",
					ad_map[i].ssam_name );
				return rc;
			}

			if( ad_map[i].ssam_check ) {
				/* install check routine */
				(*adp)->ad_type->sat_check = ad_map[i].ssam_check;
			}
			/* install flags */
			(*adp)->ad_type->sat_flags |= ad_map[i].ssam_flags;

			/* install custom syntax routines */
			if( ad_map[i].ssam_syn_validate ||
				ad_map[i].ssam_syn_pretty )
			{
				Syntax *syn;

				syntax = (*adp)->ad_type->sat_syntax;

				syn = ch_malloc( sizeof( Syntax ) );
				*syn = *syntax;

				if( ad_map[i].ssam_syn_validate ) {
					syn->ssyn_validate = ad_map[i].ssam_syn_validate;
				}
				if( ad_map[i].ssam_syn_pretty ) {
					syn->ssyn_pretty = ad_map[i].ssam_syn_pretty;
				}

				(*adp)->ad_type->sat_syntax = syn;
			}

			/* install custom rule routines */
			if( syntax != NULL ||
				ad_map[i].ssam_mr_convert ||
				ad_map[i].ssam_mr_normalize ||
				ad_map[i].ssam_mr_match ||
				ad_map[i].ssam_mr_indexer ||
				ad_map[i].ssam_mr_filter )
			{
				MatchingRule *mr = ch_malloc( sizeof( MatchingRule ) );
				*mr = *(*adp)->ad_type->sat_equality;

				if ( syntax != NULL ) {
					mr->smr_syntax = (*adp)->ad_type->sat_syntax;
				}
				if ( ad_map[i].ssam_mr_convert ) {
					mr->smr_convert = ad_map[i].ssam_mr_convert;
				}
				if ( ad_map[i].ssam_mr_normalize ) {
					mr->smr_normalize = ad_map[i].ssam_mr_normalize;
				}
				if ( ad_map[i].ssam_mr_match ) {
					mr->smr_match = ad_map[i].ssam_mr_match;
				}
				if ( ad_map[i].ssam_mr_indexer ) {
					mr->smr_indexer = ad_map[i].ssam_mr_indexer;
				}
				if ( ad_map[i].ssam_mr_filter ) {
					mr->smr_filter = ad_map[i].ssam_mr_filter;
				}

				(*adp)->ad_type->sat_equality = mr;
			}
		}
	}

	for( i=0; oc_map[i].ssom_name; i++ ) {
		assert( oc_map[i].ssom_defn != NULL );
		{
			LDAPObjectClass *oc;
			int		code;
			const char	*err;

			oc = ldap_str2objectclass( oc_map[i].ssom_defn, &code, &err,
				LDAP_SCHEMA_ALLOW_ALL );
			if ( !oc ) {
				fprintf( stderr, "slap_schema_load: ObjectClass "
					"\"%s\": %s before %s\n",
				 	oc_map[i].ssom_name, ldap_scherr2str(code), err );
				return code;
			}

			if ( oc->oc_oid == NULL ) {
				fprintf( stderr, "slap_schema_load: ObjectClass "
					"\"%s\": no OID\n",
					oc_map[i].ssom_name );
				ldap_objectclass_free( oc );
				return LDAP_OTHER;
			}

			code = oc_add(oc,0,NULL,NULL,&err);
			if ( code ) {
				ldap_objectclass_free( oc );
				fprintf( stderr, "slap_schema_load: ObjectClass "
					"\"%s\": %s: \"%s\"\n",
				 	oc_map[i].ssom_name, scherr2str(code), err);
				return code;
			}
			ldap_memfree(oc);

		}
		{
			ObjectClass ** ocp = (ObjectClass **)
				&(((char *) &slap_schema)[oc_map[i].ssom_offset]);

			assert( *ocp == NULL );

			*ocp = oc_find( oc_map[i].ssom_name );
			if( *ocp == NULL ) {
				fprintf( stderr, "slap_schema_load: "
					"ObjectClass \"%s\": not defined in schema\n",
					oc_map[i].ssom_name );
				return LDAP_OBJECT_CLASS_VIOLATION;
			}

			if( oc_map[i].ssom_check ) {
				/* install check routine */
				(*ocp)->soc_check = oc_map[i].ssom_check;
			}
			/* install flags */
			(*ocp)->soc_flags |= oc_map[i].ssom_flags;
		}
	}

	return LDAP_SUCCESS;
}

int
slap_schema_check( void )
{
	/* we should only be called once after schema_init() was called */
	assert( schema_init_done == 1 );

	/*
	 * cycle thru attributeTypes to build matchingRuleUse
	 */
	if ( matching_rule_use_init() ) {
		return LDAP_OTHER;
	}

	++schema_init_done;
	return LDAP_SUCCESS;
}

static int rootDseObjectClass (
	Backend *be,
	Entry *e,
	ObjectClass *oc,
	const char** text,
	char *textbuf, size_t textlen )
{
	*text = textbuf;

	if( e->e_nname.bv_len ) {
		snprintf( textbuf, textlen,
			"objectClass \"%s\" only allowed in the root DSE",
			oc->soc_oid );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	/* we should not be called for the root DSE */
	assert( 0 );
	return LDAP_SUCCESS;
}

static int aliasObjectClass (
	Backend *be,
	Entry *e,
	ObjectClass *oc,
	const char** text,
	char *textbuf, size_t textlen )
{
	*text = textbuf;

	if( !SLAP_ALIASES(be) ) {
		snprintf( textbuf, textlen,
			"objectClass \"%s\" not supported in context",
			oc->soc_oid );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	return LDAP_SUCCESS;
}

static int referralObjectClass (
	Backend *be,
	Entry *e,
	ObjectClass *oc,
	const char** text,
	char *textbuf, size_t textlen )
{
	*text = textbuf;

	if( !SLAP_REFERRALS(be) ) {
		snprintf( textbuf, textlen,
			"objectClass \"%s\" not supported in context",
			oc->soc_oid );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	return LDAP_SUCCESS;
}

static int subentryObjectClass (
	Backend *be,
	Entry *e,
	ObjectClass *oc,
	const char** text,
	char *textbuf, size_t textlen )
{
	*text = textbuf;

	if( !SLAP_SUBENTRIES(be) ) {
		snprintf( textbuf, textlen,
			"objectClass \"%s\" not supported in context",
			oc->soc_oid );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	if( oc != slap_schema.si_oc_subentry && !is_entry_subentry( e ) ) {
		snprintf( textbuf, textlen,
			"objectClass \"%s\" only allowed in subentries",
			oc->soc_oid );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	return LDAP_SUCCESS;
}

#ifdef LDAP_DYNAMIC_OBJECTS
static int dynamicObjectClass (
	Backend *be,
	Entry *e,
	ObjectClass *oc,
	const char** text,
	char *textbuf, size_t textlen )
{
	*text = textbuf;

	if( !SLAP_DYNAMIC(be) ) {
		snprintf( textbuf, textlen,
			"objectClass \"%s\" not supported in context",
			oc->soc_oid );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	return LDAP_SUCCESS;
}
#endif /* LDAP_DYNAMIC_OBJECTS */

static int rootDseAttribute (
	Backend *be,
	Entry *e,
	Attribute *attr,
	const char** text,
	char *textbuf, size_t textlen )
{
	*text = textbuf;

	if( e->e_nname.bv_len ) {
		snprintf( textbuf, textlen,
			"attribute \"%s\" only allowed in the root DSE",
			attr->a_desc->ad_cname.bv_val );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	/* we should not be called for the root DSE */
	assert( 0 );
	return LDAP_SUCCESS;
}

static int aliasAttribute (
	Backend *be,
	Entry *e,
	Attribute *attr,
	const char** text,
	char *textbuf, size_t textlen )
{
	*text = textbuf;

	if( !SLAP_ALIASES(be) ) {
		snprintf( textbuf, textlen,
			"attribute \"%s\" not supported in context",
			attr->a_desc->ad_cname.bv_val );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	if( !is_entry_alias( e ) ) {
		snprintf( textbuf, textlen,
			"attribute \"%s\" only allowed in the alias",
			attr->a_desc->ad_cname.bv_val );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	return LDAP_SUCCESS;
}

static int referralAttribute (
	Backend *be,
	Entry *e,
	Attribute *attr,
	const char** text,
	char *textbuf, size_t textlen )
{
	*text = textbuf;

	if( !SLAP_REFERRALS(be) ) {
		snprintf( textbuf, textlen,
			"attribute \"%s\" not supported in context",
			attr->a_desc->ad_cname.bv_val );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	if( !is_entry_referral( e ) ) {
		snprintf( textbuf, textlen,
			"attribute \"%s\" only allowed in the referral",
			attr->a_desc->ad_cname.bv_val );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	return LDAP_SUCCESS;
}

static int subentryAttribute (
	Backend *be,
	Entry *e,
	Attribute *attr,
	const char** text,
	char *textbuf, size_t textlen )
{
	*text = textbuf;

	if( !SLAP_SUBENTRIES(be) ) {
		snprintf( textbuf, textlen,
			"attribute \"%s\" not supported in context",
			attr->a_desc->ad_cname.bv_val );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	if( !is_entry_subentry( e ) ) {
		snprintf( textbuf, textlen,
			"attribute \"%s\" only allowed in the subentry",
			attr->a_desc->ad_cname.bv_val );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	return LDAP_SUCCESS;
}

static int administrativeRoleAttribute (
	Backend *be,
	Entry *e,
	Attribute *attr,
	const char** text,
	char *textbuf, size_t textlen )
{
	*text = textbuf;

	if( !SLAP_SUBENTRIES(be) ) {
		snprintf( textbuf, textlen,
			"attribute \"%s\" not supported in context",
			attr->a_desc->ad_cname.bv_val );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	snprintf( textbuf, textlen,
		"attribute \"%s\" not supported!",
		attr->a_desc->ad_cname.bv_val );
	return LDAP_OBJECT_CLASS_VIOLATION;
}

#ifdef LDAP_DYNAMIC_OBJECTS
static int dynamicAttribute (
	Backend *be,
	Entry *e,
	Attribute *attr,
	const char** text,
	char *textbuf, size_t textlen )
{
	*text = textbuf;

	if( !SLAP_DYNAMIC(be) ) {
		snprintf( textbuf, textlen,
			"attribute \"%s\" not supported in context",
			attr->a_desc->ad_cname.bv_val );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	if( !is_entry_dynamicObject( e ) ) {
		snprintf( textbuf, textlen,
			"attribute \"%s\" only allowed in dynamic object",
			attr->a_desc->ad_cname.bv_val );
		return LDAP_OBJECT_CLASS_VIOLATION;
	}

	return LDAP_SUCCESS;
}
#endif /* LDAP_DYNAMIC_OBJECTS */
