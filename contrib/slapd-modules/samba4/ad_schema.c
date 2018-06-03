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

#ifdef SLAPD_OVER_AD_SCHEMA

#include <stdio.h>

#include <ac/string.h>
#include <ac/socket.h>

#include "slap.h"
#include "config.h"
#include "ad_schema.h"
#include "flags.h"
#include "ldb.h"
#include "samba_security.h"
#include "ndr.h"

static ObjectClass *oc_attributeSchema;
static ObjectClass *oc_classSchema;
static ObjectClass *oc_container;
static ObjectClass *oc_person;
static ObjectClass *oc_dMD;

static AttributeDescription *ad_defaultObjectCategory;
static AttributeDescription *ad_governsID;
static AttributeDescription *ad_objectClassCategory;
static AttributeDescription *ad_schemaIDGUID;
static AttributeDescription *ad_subClassOf;
static AttributeDescription *ad_auxiliaryClass;
static AttributeDescription *ad_classDisplayName;
static AttributeDescription *ad_defaultHidingValue;
static AttributeDescription *ad_defaultSecurityDescriptor;
static AttributeDescription *ad_isDefunct;
static AttributeDescription *ad_lDAPDisplayName;
static AttributeDescription *ad_mayContain;
static AttributeDescription *ad_msDS_IntId;
static AttributeDescription *ad_msDs_Schema_Extensions;
static AttributeDescription *ad_mustContain;
static AttributeDescription *ad_possSuperiors;
static AttributeDescription *ad_rDNAttID;
static AttributeDescription *ad_schemaFlagsEx;
static AttributeDescription *ad_systemAuxiliaryClass;
static AttributeDescription *ad_systemMayContain;
static AttributeDescription *ad_systemMustContain;
static AttributeDescription *ad_systemOnly;
static AttributeDescription *ad_systemPossSuperiors;
static AttributeDescription *ad_attributeID;
static AttributeDescription *ad_attributeSyntax;
static AttributeDescription *ad_isSingleValued;
static AttributeDescription *ad_oMSyntax;
static AttributeDescription *ad_attributeSecurityGUID;
static AttributeDescription *ad_extendedCharsAllowed;
static AttributeDescription *ad_isEphemeral;
static AttributeDescription *ad_isMemberOfPartialAttributeSet;
static AttributeDescription *ad_linkID;
static AttributeDescription *ad_mAPIID;
static AttributeDescription *ad_oMObjectClass;
static AttributeDescription *ad_rangeLower;
static AttributeDescription *ad_rangeUpper;
static AttributeDescription *ad_searchFlags;
static AttributeDescription *ad_defaultClassStore;
static AttributeDescription *ad_schemaVersion;
static AttributeDescription *ad_attributeCertificateAttribute;
static AttributeDescription *ad_serialNumber;
static AttributeDescription *ad_telephoneNumber;
static AttributeDescription *ad_sn;
static AttributeDescription *ad_dmdName;
static AttributeDescription *ad_msDS_USNLastSyncSuccess;
static AttributeDescription *ad_prefixMap;
static AttributeDescription *ad_schemaUpdate;
static AttributeDescription *ad_schemaInfo;
static AttributeDescription *ad_msDS_ObjectReference;

static slap_overinst ad_schema;

/*Todo - syntax validation functions*/
static int
dummySyntaxValidate(
	Syntax		*syntax,
	struct berval	*val )
{
	return LDAP_SUCCESS;
}

static char	*octetMRs[] = {
	"octetStringMatch",
	NULL
};

static char	*caseignoreMRs[] = {
	"caseIgnoreMatch",
	NULL
};

static char	*intMRs[] = {
	"integerMatch",
	NULL
};

static char	*caseexactMRs[] = {
	"caseExactMatch",
	NULL
};

/* for some reason samba has generalizedTimeMatch rule on UTC syntax
 * so we redefine the syntax instead of using the deprecated one
 * TODO investigate */
static char	*timeMRs[] = {
	"generalizedTimeMatch",
	NULL
};

/* some AD syntaxes - draft-armijo-ldap-syntax-00.txt and 3.1.1.3.1.1.2 Syntaxes */
static struct {
	char			*oid;
	slap_syntax_defs_rec	syn;
	char			**mrs;
} ad_syntaxes[] = {
	{ "1.2.840.113556.1.4.903" ,
	  { "( 1.2.840.113556.1.4.903 DESC 'String + DN' )",
	    0,
	    NULL,
	    dummySyntaxValidate,
	    NULL },
	  octetMRs },
	{ "1.2.840.113556.1.4.904" ,
	  { "( 1.2.840.113556.1.4.904 DESC 'Binary + DN' )",
	    0,
	    NULL,
	    dummySyntaxValidate,
	    NULL },
	  octetMRs },
	/*encoded as Printable String */
	{ "1.2.840.113556.1.4.905" ,
	  { "( 1.2.840.113556.1.4.905 DESC 'CaseIgnoreString, String(Teletext)' )",
	    0,
	    NULL,
	    dummySyntaxValidate,
	    NULL },
	  caseignoreMRs },
	{ "1.2.840.113556.1.4.906" ,
	  { "( 1.2.840.113556.1.4.906 DESC 'LargeInteger - guaranteed 64 bit support' )",
	    0,
	    NULL,
	   dummySyntaxValidate ,
	    NULL },
	  intMRs },
	/* encoded as Octet-String */
	{ "1.2.840.113556.1.4.907" ,
	  { "( 1.2.840.113556.1.4.907 DESC 'Security Descriptor' )",
	    0,
	    NULL,
	    dummySyntaxValidate,
	    NULL },
	  octetMRs },
	{ "1.2.840.113556.1.4.1221" ,
	  { "( 1.2.840.113556.1.4.1221 DESC 'DN | X400: ORaddress #X500: DN | X400:ORaddress' )",
	    0,
	    NULL,
	    dummySyntaxValidate,
	    NULL },
	  caseignoreMRs },
	{ "1.2.840.113556.1.4.1362" ,
	  { "( 1.2.840.113556.1.4.1362 DESC 'Case-sensitive string' )",
	    0,
	    NULL,
	    dummySyntaxValidate,
	    NULL },
	  caseexactMRs },
	{ "1.3.6.1.4.1.1466.115.121.1.53",
	    {"( 1.3.6.1.4.1.1466.115.121.1.53 DESC 'UTC Time' )",
		0, NULL, NULL, NULL},
	  timeMRs },
	{ NULL }
};

static struct {
	char *desc;
	AttributeDescription **adp;
} as[] = {
	{ "( 1.2.840.113556.1.4.783 "
	  "NAME 'defaultObjectCategory' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 "
	  "SINGLE-VALUE )",
	  &ad_defaultObjectCategory },
	{ "( 1.2.840.113556.1.2.22 "
	  "NAME 'governsID' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 "
	  "SINGLE-VALUE )",
	  &ad_governsID },
	{ "( 1.2.840.113556.1.2.370 "
	  "NAME 'objectClassCategory' "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	  "SINGLE-VALUE )",
	  &ad_objectClassCategory },
	{ "( 1.2.840.113556.1.4.148 "
	  "NAME 'schemaIDGUID' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 "
	  "SINGLE-VALUE )",
	  &ad_schemaIDGUID },
	{ "( 1.2.840.113556.1.2.21 "
	  "NAME 'subClassOf' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 "
	  "SINGLE-VALUE )",
	  &ad_subClassOf },
	{ "( 1.2.840.113556.1.2.351 "
	  "NAME 'auxiliaryClass' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )",
	  &ad_auxiliaryClass },
	{ "( 1.2.840.113556.1.4.610 "
	  "NAME 'classDisplayName' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 )",
	  &ad_classDisplayName },
	{ "( 1.2.840.113556.1.4.518 "
	 "NAME 'defaultHidingValue' "
	 "EQUALITY booleanMatch "
	 "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
	 "SINGLE-VALUE )",
	 &ad_defaultHidingValue },
	{ "( 1.2.840.113556.1.4.224 "
	  "NAME 'defaultSecurityDescriptor' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
	  "SINGLE-VALUE )",
	  &ad_defaultSecurityDescriptor },
	{ "( 1.2.840.113556.1.4.661 "
	  "NAME 'isDefunct' "
	  "EQUALITY booleanMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
	  "SINGLE-VALUE )",
	  &ad_isDefunct },
	{ "( 1.2.840.113556.1.2.460 "
	  "NAME 'lDAPDisplayName' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
	  "SINGLE-VALUE )",
	  &ad_lDAPDisplayName },
	{ "( 1.2.840.113556.1.2.25 "
	  "NAME 'mayContain' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )",
	  &ad_mayContain },
	{ "( 1.2.840.113556.1.4.1716 "
	  "NAME 'msDS-IntId' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	  "SINGLE-VALUE )",
	  &ad_msDS_IntId },
	{ "( 1.2.840.113556.1.4.1440 "
	  "NAME 'msDs-Schema-Extensions' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
	  &ad_msDs_Schema_Extensions },
	{ "( 1.2.840.113556.1.2.24 "
	  "NAME 'mustContain' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )",
	  &ad_mustContain },
	{ "( 1.2.840.113556.1.2.8 "
	  "NAME 'possSuperiors' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )",
	  &ad_possSuperiors },
	{ "( 1.2.840.113556.1.2.26 "
	  "NAME 'rDNAttID' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 "
	  "SINGLE-VALUE )",
	  &ad_rDNAttID },
	{ "( 1.2.840.113556.1.4.120 "
	  "NAME 'schemaFlagsEx' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	  "SINGLE-VALUE )",
	  &ad_schemaFlagsEx },
	{ "( 1.2.840.113556.1.4.198 "
	  "NAME 'systemAuxiliaryClass' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )",
	  &ad_systemAuxiliaryClass },
	{ "( 1.2.840.113556.1.4.196 "
	  "NAME 'systemMayContain' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )",
	  &ad_systemMayContain },
	{ "( 1.2.840.113556.1.4.197 "
	  "NAME 'systemMustContain' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )",
	  &ad_systemMustContain },
	{ "( 1.2.840.113556.1.4.170 "
	  "NAME 'systemOnly' "
	  "EQUALITY booleanMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
	  "SINGLE-VALUE )",
	  &ad_systemOnly },
	{ "( 1.2.840.113556.1.4.195 "
	  "NAME 'systemPossSuperiors' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )",
	  &ad_systemPossSuperiors },
	{ "( 1.2.840.113556.1.2.30 "
	  "NAME 'attributeID' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 "
	  "SINGLE-VALUE )",
	  &ad_attributeID },
	{ "( 1.2.840.113556.1.2.32 "
	  "NAME 'attributeSyntax' "
	  "EQUALITY caseIgnoreMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 "
	  "SINGLE-VALUE )",
	  &ad_attributeSyntax },
	{ "( 1.2.840.113556.1.2.33 "
	  "NAME 'isSingleValued' "
	  "EQUALITY booleanMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
	  "SINGLE-VALUE )",
	  &ad_isSingleValued },
	{ "( 1.2.840.113556.1.2.231 "
	  "NAME 'oMSyntax' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	  "SINGLE-VALUE )",
	  &ad_oMSyntax },
	{ "( 1.2.840.113556.1.4.149 "
	  "NAME 'attributeSecurityGUID' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 "
	  "SINGLE-VALUE )",
	  &ad_attributeSecurityGUID },
	{ "( 1.2.840.113556.1.2.380 "
	  "NAME 'extendedCharsAllowed' "
	  "EQUALITY booleanMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
	  "SINGLE-VALUE )",
	  &ad_extendedCharsAllowed },
	{ "( 1.2.840.113556.1.4.1212 "
	  "NAME 'isEphemeral' "
	  "EQUALITY booleanMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
	  "SINGLE-VALUE )",
	  &ad_isEphemeral },
	{ "( 1.2.840.113556.1.4.639 "
	  "NAME 'isMemberOfPartialAttributeSet' "
	  "EQUALITY booleanMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7 "
	  "SINGLE-VALUE )",
	  &ad_isMemberOfPartialAttributeSet },
	{ "( 1.2.840.113556.1.2.50 "
	  "NAME 'linkID' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	  "SINGLE-VALUE )",
	  &ad_linkID },
	{ "( 1.2.840.113556.1.2.49 "
	  "NAME 'mAPIID' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	  "SINGLE-VALUE )",
	  &ad_mAPIID },
	{ "( 1.2.840.113556.1.2.218 "
	  "NAME 'oMObjectClass' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 "
	  "SINGLE-VALUE )",
	  &ad_oMObjectClass },
	{ "( 1.2.840.113556.1.2.35 "
	  "NAME 'rangeUpper' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	  "SINGLE-VALUE )",
	  &ad_rangeUpper },
	{ "( 1.2.840.113556.1.2.34 "
	  "NAME 'rangeLower' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	  "SINGLE-VALUE )",
	  &ad_rangeLower },
	{ "( 1.2.840.113556.1.2.334 "
	  "NAME 'searchFlags' "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 "
	  "SINGLE-VALUE )",
	  &ad_searchFlags },
	{ "( 1.2.840.113556.1.4.213 "
	  "NAME 'defaultClassStore' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12 )",
	  &ad_defaultClassStore },
	{ "( 1.2.840.113556.1.2.471 "
	  "NAME 'schemaVersion' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27 )",
	  &ad_schemaVersion },
	 { "( 2.5.4.58 "
	   "NAME 'attributeCertificateAttribute' "
	   "EQUALITY octetStringMatch "
	   "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 )",
	   &ad_attributeCertificateAttribute },
	{ "( 2.5.4.5 "
	  "NAME 'serialNumber' "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44 )",
	  &ad_serialNumber },
	{ "( 2.5.4.20 "
	  "NAME 'telephoneNumber' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
	  "SINGLE-VALUE )",
	  &ad_telephoneNumber },
	{ "( 2.5.4.4 "
	  "NAME 'sn' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
	  "SINGLE-VALUE )",
	  &ad_sn },
	{ "( 1.2.840.113556.1.2.598 "
	  "NAME 'dmdName' "
	  "EQUALITY caseIgnoreMatch "
	  "SUBSTR caseIgnoreSubstringsMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15 "
	  "SINGLE-VALUE )",
	  &ad_dmdName },
	{ "( 1.2.840.113556.1.4.2055 "
	  "NAME 'msDS-USNLastSyncSuccess' "
	  "EQUALITY integerMatch "
	  "SYNTAX 1.2.840.113556.1.4.906 "
	  "SINGLE-VALUE )",
	  &ad_msDS_USNLastSyncSuccess },
	{ "( 1.2.840.113556.1.4.538 "
	  "NAME 'prefixMap' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40 "
	  "SINGLE-VALUE )",
	  &ad_prefixMap },
	{ "( 1.2.840.113556.1.4.481 "
	  "NAME 'schemaUpdate' "
	  "EQUALITY generalizedTimeMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.24 "
	  "SINGLE-VALUE )",
	  &ad_schemaUpdate},
	{ "( 1.2.840.113556.1.4.1358 "
	  "NAME 'schemaInfo' "
	  "EQUALITY octetStringMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40) ",
	  &ad_schemaInfo},
	{ "( 1.2.840.113556.1.4.1840 "
	  "NAME 'msDS-ObjectReference' "
	  "EQUALITY distinguishedNameMatch "
	  "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12) ",
	  &ad_msDS_ObjectReference},
	{NULL, NULL},
};

static struct {
	char *ot;
	ObjectClass **oc;
} schema_ocs[] = {
	{ "( 1.2.840.113556.1.3.13 NAME 'classSchema' "
	  "SUP top "
	  "STRUCTURAL "
	  "MUST ( cn $ defaultObjectCategory $ governsID $ objectClassCategory $ "
	  "schemaIDGUID $ subClassOf $ lDAPDisplayName) "
	  "MAY ( auxiliaryClass $ classDisplayName $ defaultHidingValue $ defaultSecurityDescriptor $ isDefunct $ "
	  "mayContain $ msDS-IntId $ msDs-Schema-Extensions $ mustContain $ "
	  "possSuperiors $ rDNAttID $ schemaFlagsEx $ systemAuxiliaryClass $ systemMayContain $ "
	  "systemMustContain $ systemOnly $ systemPossSuperiors ) )", &oc_classSchema },
	{ "( 1.2.840.113556.1.3.14 NAME 'attributeSchema' "
	  "SUP top "
	  "STRUCTURAL "
	  "MUST ( attributeID $ attributeSyntax $ cn $ isSingleValued $ lDAPDisplayName $ "
	  "oMSyntax $ schemaIDGUID ) "
	  "MAY ( attributeSecurityGUID $ classDisplayName $ extendedCharsAllowed $ isDefunct $ isEphemeral $ "
	  "isMemberOfPartialAttributeSet $ linkID $ mAPIID $ msDS-IntId $ msDs-Schema-Extensions $ "
	  "oMObjectClass $ rangeLower $ rangeUpper $ schemaFlagsEx $ searchFlags $ systemOnly ) )",  &oc_attributeSchema },
	{ "( 1.2.840.113556.1.3.23 NAME 'container' "
	  "SUP top "
	  "STRUCTURAL "
	  "MUST ( cn ) "
	  "MAY ( defaultClassStore $ msDS-ObjectReference $ schemaVersion ) )", &oc_container },
	{ "( 2.5.6.6 NAME 'person' "
	  "SUP top "
	  "STRUCTURAL "
	  "MUST ( cn ) "
	  "MAY ( attributeCertificateAttribute $ seeAlso $ serialNumber $ sn $ telephoneNumber $ userPassword ) )", &oc_person },
	{ "( 1.2.840.113556.1.3.9 NAME 'dMD' "
	  "SUP top "
	  "STRUCTURAL "
	  "MUST ( cn ) "
	  "MAY ( dmdName $ msDS-IntId $ msDs-Schema-Extensions $ msDS-USNLastSyncSuccess $ prefixMap $  "
	  "schemaInfo $ schemaUpdate ) )", &oc_dMD },
	{ NULL, NULL }
};


/* syntax mapping according to 3.1.1.3.1.1.1 subSchema and 3.1.1.2.2.2 LDAP Representations*/
static struct {
	int oMSyntax;
	char *ldap_syntax;
	char *equality;
} ad_syntax[] = {
	/* AD syntax 2.5.5.8, Boolean */
	{1, "SYNTAX 1.3.6.1.4.1.1466.115.121.1.7", "EQUALITY booleanMatch"},
        /*2.5.5.9, Integer */
	{2, "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27", "EQUALITY integerMatch"},
	/*2.5.5.10 String(Octet) and 2.5.5.17 String(Sid)*/
	{4, "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40", "EQUALITY octetStringMatch"},
	/*2.5.5.2 String(Object-Identifier) */ 
	/* This should be "SYNTAX 1.3.6.1.4.1.1466.115.121.1.38", "EQUALITY objectIdentifierMatch",
	 * but AD allows and heavily uses attribute and class names
	 * Correct syntax actually depends on the attribute type, so we will need specific validation.
	 * It's not fatal for now, as the attributes that require a numeric oid are hardcoded. An additional check must be
	 * added in the future to check that any values of a 2.5.5.2 attribute that are not numeric, are valid objectClass
	 * or attribute names */
	{6, "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44", "EQUALITY caseIgnoreMatch"},
	/*2.5.5.9 Enumeration */
	{10, "SYNTAX 1.3.6.1.4.1.1466.115.121.1.27", "EQUALITY integerMatch"},
	/*2.5.5.6 String(Numeric) */
	{18, "SYNTAX 1.3.6.1.4.1.1466.115.121.1.36", "EQUALITY numericStringMatch SUBSTR numericStringSubstringsMatch"},
	/*2.5.5.5 String(Printable) */
	{19, "SYNTAX 1.3.6.1.4.1.1466.115.121.1.44", NULL},
	 /*2.5.5.4 String(Teletext) */
	{20,  "SYNTAX 1.2.840.113556.1.4.905", "EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch"},
	 /*2.5.5.5 String(IA5) */
	{22, "SYNTAX 1.3.6.1.4.1.1466.115.121.1.26", "EQUALITY caseExactIA5Match"},
	/*2.5.5.11 String(UTC-Time) */
	{23, "SYNTAX 1.3.6.1.4.1.1466.115.121.1.53", "EQUALITY generalizedTimeMatch"},
	/*2.5.5.11 String(Generalized-Time) */
	{24, "SYNTAX 1.3.6.1.4.1.1466.115.121.1.24", "EQUALITY generalizedTimeMatch"},
	/*2.5.5.3 String(Case) */
	{27, "SYNTAX 1.2.840.113556.1.4.1362", "EQUALITY caseExactMatch SUBSTR caseExactSubstringsMatch"},
	/* 2.5.5.12 String(Unicode) */
	{64, "SYNTAX 1.3.6.1.4.1.1466.115.121.1.15", "EQUALITY caseIgnoreMatch SUBSTR caseIgnoreSubstringsMatch"},
	/*2.5.5.16 LargeInteger*/
	{65, "SYNTAX 1.2.840.113556.1.4.906", "EQUALITY integerMatch"},
	/*2.5.5.15 String(NT-Sec-Desc) */
	{66, "SYNTAX 1.2.840.113556.1.4.907", NULL},
	{0, NULL, NULL}
};

static struct {
	int om_len;
	char om_buf[10];
	char *ldap_syntax;
	char *equality;
} ad_om_syntax[] = {
	/*2.5.5.14 Object(Access-Point) */
	{9, {0x2B,0x0C,0x02,0x87,0x73,0x1C,0x00,0x85,0x3E}, "SYNTAX 1.3.6.1.4.1.1466.115.121.1.2", NULL},
	/*2.5.5.14 Object(DN-String) */
	{10, {0x2A,0x86,0x48,0x86,0xF7,0x14,0x01,0x01,0x01,0x0C}, "SYNTAX 1.2.840.113556.1.4.904", "EQUALITY octetStringMatch"},
	/* 2.5.5.7 Object(OR-Name) */
	{7, {0x56,0x06,0x01,0x02,0x05,0x0B,0x1D}, "SYNTAX 1.2.840.113556.1.4.1221", "EQUALITY caseIgnoreMatch"},
	/* 2.5.5.7 Object(DN-Binary) */
	{10, {0x2A,0x86,0x48,0x86,0xF7,0x14,0x01,0x01,0x01,0x0B}, "SYNTAX 1.2.840.113556.1.4.903", "EQUALITY octetStringMatch"},
	/*2.5.5.1 Object(DS-DN)*/
	{9, {0x2B,0x0C,0x02,0x87,0x73,0x1C,0x00,0x85,0x4A}, "SYNTAX 1.3.6.1.4.1.1466.115.121.1.12", "EQUALITY distinguishedNameMatch"},
	/* 2.5.5.13 Object(Presentation-Address) */
	{9, {0x2B,0x0C,0x02,0x87,0x73,0x1C,0x00,0x85,0x5C}, "SYNTAX 1.3.6.1.4.1.1466.115.121.1.43", NULL},
	/* 2.5.5.10 Object(Replica-Link) */
	{10, {0x2A,0x86,0x48,0x86,0xF7,0x14,0x01,0x01,0x01,0x06}, "SYNTAX 1.3.6.1.4.1.1466.115.121.1.40", NULL},
	{0, {0x0}, NULL, NULL}
};


#define DB_DN_MAXLEN 128

static int
ad_schema_add_index(struct berval *displayName)
{
	struct berval val;
	AttributeDescription *ad = NULL;
	const char *text;
	int rc;
	void *ctx = ldap_pvt_thread_pool_context();
	Connection conn = { 0 };
	OperationBuffer opbuf;
	Operation *new_op;
	SlapReply new_rs = { REP_RESULT };
	struct berval db_dn;
	struct berval index_val;
	Modifications * modlist;
	char *idx;
	/* 0 is config, 1 is Samba */
	int i = 2;

	connection_fake_init2( &conn, &opbuf, ctx, 0 );
	new_op = &opbuf.ob_op;
	new_op->o_tag = LDAP_REQ_MODIFY;
	memset( &new_op->oq_modify, 0, sizeof( new_op->oq_modify ) );

	db_dn.bv_val = ch_calloc( 1, DB_DN_MAXLEN);

	rc = slap_str2ad("olcDbIndex", &ad, &text);
	modlist = (Modifications *)ch_calloc( 1, sizeof( Modifications ));
	modlist->sml_values = (struct berval *)ch_calloc( 2, sizeof( struct berval ));
	modlist->sml_numvals = 1;
	modlist->sml_op = LDAP_MOD_ADD;
	modlist->sml_desc = ad;
	new_op->orm_modlist = modlist;
	idx = ch_calloc( sizeof(char), displayName->bv_len + 4);
	snprintf(idx, displayName->bv_len + 4, "%s eq", displayName->bv_val);
	index_val.bv_val = idx;
	index_val.bv_len = strlen(index_val.bv_val);
	ber_dupbv(&modlist->sml_values[0],&index_val);
	modlist->sml_nvalues = modlist->sml_values;

	while (new_rs.sr_err != LDAP_NO_SUCH_OBJECT) {
		memset( db_dn.bv_val, 0, DB_DN_MAXLEN );
		memset( &new_rs, 0, sizeof(SlapReply));
		sprintf(db_dn.bv_val, "olcDatabase={%d}mdb,cn=config", i);
		db_dn.bv_len = strlen(db_dn.bv_val);
		new_op->o_bd = select_backend(&db_dn, 1);
		new_op->o_dn = new_op->o_bd->be_rootdn;
		new_op->o_ndn = new_op->o_bd->be_rootndn;
		new_op->o_req_dn = db_dn;
		new_op->o_req_ndn = db_dn;
		new_op->o_bd->be_modify( new_op, &new_rs );
		i++;
	}

	free(idx);
	free(modlist->sml_values);
	free(modlist);
	free(db_dn.bv_val);
	return LDAP_SUCCESS;
}

void ad_schema_add_refint(struct berval *displayName)
{
/*Create a refint config based on linkID*/
	struct berval val;
	AttributeDescription *ad = NULL;
	const char *text;
	int rc;
	void *ctx = ldap_pvt_thread_pool_context();
	Connection conn = { 0 };
	OperationBuffer opbuf;
	Operation *new_op;
	SlapReply new_rs = { REP_RESULT };
	struct berval db_dn;
	Modifications * modlist;

	connection_fake_init2( &conn, &opbuf, ctx, 0 );
	new_op = &opbuf.ob_op;
	new_op->o_tag = LDAP_REQ_MODIFY;
	memset( &new_op->oq_modify, 0, sizeof( new_op->oq_modify ) );

	db_dn.bv_val = ch_calloc( 1, DB_DN_MAXLEN);

	rc = slap_str2ad("olcRefintAttribute", &ad, &text);
	modlist = (Modifications *)ch_calloc( 1, sizeof( Modifications ));
	modlist->sml_values = (struct berval *)ch_calloc( 2, sizeof( struct berval ));
	modlist->sml_numvals = 1;
	modlist->sml_op = LDAP_MOD_ADD;
	modlist->sml_desc = ad;
	new_op->orm_modlist = modlist;
	ber_dupbv(&modlist->sml_values[0],displayName);
	modlist->sml_nvalues = modlist->sml_values;
	sprintf(db_dn.bv_val, "olcOverlay={2}refint,olcDatabase={-1}frontend,cn=config");
	db_dn.bv_len = strlen(db_dn.bv_val);
	new_op->o_bd = select_backend(&db_dn, 1);
	new_op->o_dn = new_op->o_bd->be_rootdn;
	new_op->o_ndn = new_op->o_bd->be_rootndn;
	new_op->o_req_dn = db_dn;
	new_op->o_req_ndn = db_dn;
	new_op->o_bd->be_modify( new_op, &new_rs );
	      
	free(modlist->sml_values);
	free(modlist);
	free(db_dn.bv_val);
}

void ad_schema_add_attr_to_config(char *attr_def)
{
/*Create a refint config based on linkID*/
	struct berval val;
	AttributeDescription *ad = NULL;
	const char *text;
	int rc;
	void *ctx = ldap_pvt_thread_pool_context();
	Connection conn = { 0 };
	OperationBuffer opbuf;
	Operation *new_op;
	SlapReply new_rs = { REP_RESULT };
	struct berval db_dn;
	Modifications * modlist;
	struct berval def;

	connection_fake_init2( &conn, &opbuf, ctx, 0 );
	new_op = &opbuf.ob_op;
	new_op->o_tag = LDAP_REQ_MODIFY;
	memset( &new_op->oq_modify, 0, sizeof( new_op->oq_modify ) );

	db_dn.bv_val = ch_calloc( 1, DB_DN_MAXLEN);
	def.bv_val = attr_def;
	def.bv_len = strlen(attr_def);
	rc = slap_str2ad("olcAttributeTypes", &ad, &text);
	modlist = (Modifications *)ch_calloc( 1, sizeof( Modifications ));
	modlist->sml_values = (struct berval *)ch_calloc( 2, sizeof( struct berval ));
	modlist->sml_numvals = 1;
	modlist->sml_op = LDAP_MOD_ADD;
	modlist->sml_desc = ad;
	new_op->orm_modlist = modlist;
	ber_dupbv(&modlist->sml_values[0], &def);
	modlist->sml_nvalues = modlist->sml_values;
	sprintf(db_dn.bv_val, "cn=config");
	db_dn.bv_len = strlen(db_dn.bv_val);
	new_op->o_bd = select_backend(&db_dn, 1);
	new_op->o_dn = new_op->o_bd->be_rootdn;
	new_op->o_ndn = new_op->o_bd->be_rootndn;
	new_op->o_req_dn = db_dn;
	new_op->o_req_ndn = db_dn;
	new_op->o_bd->be_modify( new_op, &new_rs );
	      
	free(modlist->sml_values);
	free(modlist);
	free(db_dn.bv_val);
	return LDAP_SUCCESS;
}


#if 0
/*Create a memberof config based on linkID*/
void ad_schema_add_memberof(Operation *op, int linkID, struct berval *displayName)
{
	struct berval forward;
	struct berval backlink;
	int forwardID = 0, backID = 0;
	void *ctx = ldap_pvt_thread_pool_context();
	Connection conn = { 0 };
	OperationBuffer opbuf;
	Operation *new_op;
	SlapReply new_rs = { REP_RESULT };
	AttributeName an[2];
	char filterstring[DB_DN_MAXLEN];
	Attribute *attr;
	AttributeDescription *ad_olcMemberOfDN;
	AttributeDescription *ad_olcMemberOfDangling;
	AttributeDescription *ad_olcMemberOfMemberAD;
	AttributeDescription *ad_olcMemberOfMemberOfAD;
	AttributeDescription *ad_olcMemberOfDN;
	AttributeDescription *ad_olcMemberOfDanglingError;
	AttributeDescription *ad_olcMemberOfGroupOC;
	AttributeDescription *ad_olcMemberOfRefint;
	AttributeDescription *ad_olcOverlay;
	const char *text;
	int rc;
	Entry *e;
	
	connection_fake_init2( &conn, &opbuf, ctx, 0 );
	new_op = &opbuf.ob_op;
	new_op->o_tag = LDAP_REQ_SEARCH;
	memset( &new_op->oq_search, 0, sizeof( new_op->oq_search ) );
	an[0].an_desc = ad_lDAPDisplayName;
	an[0].an_name.bv_val = "lDAPDisplayName";
	an[0].an_name.bv_len = strlen(an[0].an_name.bv_val);
	an[1].an_desc = NULL;

	new_op->ors_attrsonly = 1;
	new_op->ors_attrs = an;
	new_op->ors_slimit =  SLAP_NO_LIMIT;
	new_op->ors_deref = LDAP_DEREF_NEVER;
	new_op->ors_scope = LDAP_SCOPE_SUBTREE;
	new_op->o_req_dn = op->o_bd->be_nsuffix[0];
	new_op->o_req_ndn = new_op->o_req_dn;
	new_op->o_bd = select_backend(op->o_req_dn, 1);
	new_op->o_dn = new_op->o_bd->be_rootdn;
	new_op->o_ndn = new_op->o_bd->be_rootndn;

	(void)op->o_bd->be_search(op, &new_rs);
	if (new_rs.sr_err != LDAP_SUCCESS) {
		return new_rs.sr_err;
	}
	if (linkID % 2 > 0) {
		/* this is the back link, find the forward */
		backlink = *displayName;
		forwardID = linkID-1;
		backID = linkID;
		sprintf(filterstring, "(&(objectclass=attributeSchema)(linkID=%d)", forwardID);
		new_op->ors_filterstring.bv_val = filterstring;
		new_op->ors_filterstring.bv_len = strlen(filterstring);
	} else {
		forward = *displayName;
		forwardID = linkID;
		backID = linkID+1;
		sprintf(filterstring, "(&(objectclass=attributeSchema)(linkID=%d)", backID);
		new_op->ors_filterstring.bv_val = filterstring;
		new_op->ors_filterstring.bv_len = strlen(filterstring);
	}

	new_op->ors_filter = str2filter_x( &new_op, new_op->ors_filterstring.bv_val );
	(void)new_op->o_bd->be_search(op, &new_rs);
	if (new_rs.sr_err != LDAP_SUCCESS) {
		Debug( LDAP_DEBUG_ANY,
		       "ad_schema_add_memberof: Failed to find linked attribute for(%d)\n",
		       linkID, 0, 0 );
		return LDAP_SUCCESS;
	} else {
		Debug( LDAP_DEBUG_ANY,
		       "ad_schema_add_memberof: Found linked attribute for(%d)\n",
		       linkID, 0, 0 );
	}

	attr = attr_find( &new_rs.sr_entry, ad_lDAPDisplayName);
	if (!attr) {
		Debug( LDAP_DEBUG_ANY,
		       "ad_schema_add_memberof: Failed to find linked attribute for(%d)\n",
		       linkID, 0, 0 );
		return LDAP_SUCCESS;
	}

	if (forward.bv_len == 0) {
		forward = attr->a_vals[0];
	} else {
		backlink = attr->a_vals[0];
	}

	new_op->o_tag = LDAP_REQ_ADD;
	memset( &new_op->oq_add, 0, sizeof( new_op->oq_add ) );
	rc = slap_str2ad("olcMemberOfDN", &ad_olcMemberOfDN, &text);
	rc = slap_str2ad("olcMemberOfDangling", &ad_olcMemberOfDangling, &text);
	rc = slap_str2ad("olcMemberOfMemberAD", &ad_olcMemberOfMemberAD, &text);
	rc = slap_str2ad("olcMemberOfMemberOfAD", &ad_olcMemberOfMemberOfAD, &text);
	rc = slap_str2ad("olcMemberOfDanglingError", &ad_olcMemberOfDanglingError, &text);
	rc = slap_str2ad("olcMemberOfGroupOC", &ad_olcMemberOfGroupOC, &text);
	rc = slap_str2ad("olcMemberOfRefint", &ad_olcMemberOfRefint, &text);
	rc = slap_str2ad("olcOverlay", &ad_olcOverlay, &text);
	return LDAP_SUCCESS;
}
#endif

static void ad_schema_load_extended_attribute(AttributeType *at,
					      Entry *e,
					      struct berval *ldapDisplayName,
					      int no_config)
{	
	int rc;
	Attribute *attr = NULL;
	struct ad_schema_attribute *ads_at;
	AttributeDescription *ad_systemFlags = NULL;

	if (at->at_private != NULL) {
		Debug( LDAP_DEBUG_ANY,
		       "ad_schema_load_extended_attribute: data already present\n",
		       0, 0, 0 );
		return;
	}

	rc = slap_str2ad( "systemFlags", &ad_systemFlags, NULL );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
		       "ad_schema_load_extended_attribute: Failed to find description systemFlags(%d)\n",
		       rc, 0, 0 );
		return;
	}

	ads_at = ch_calloc(1, sizeof(struct ad_schema_attribute));

	attr = attr_find( e->e_attrs, ad_attributeID);
	if (attr != NULL) {
		ber_dupbv( &ads_at->attributeID, &attr->a_vals[0]);
	}
	attr = attr_find( e->e_attrs, ad_attributeSyntax);
	if (attr != NULL) {
		ber_dupbv( &ads_at->attributeSyntax, &attr->a_vals[0]);
	}
	attr = attr_find( e->e_attrs, ad_schemaIDGUID);
	if (attr != NULL) {
		ber_dupbv( &ads_at->schemaIDGUID, &attr->a_vals[0]);
	}
	attr = attr_find( e->e_attrs, ad_oMObjectClass);
	if (attr != NULL) {
		ber_dupbv( &ads_at->oMObjectClass, &attr->a_vals[0]);
	}

	attr = attr_find (e->e_attrs, ad_attributeSecurityGUID);
	if (attr != NULL) {
		ber_dupbv( &ads_at->attributeSecurityGUID, &attr->a_vals[0]);
	}

	attr = attr_find( e->e_attrs, ad_systemFlags);
	if (attr != NULL) {
		ads_at->systemFlags = (int)strtol(attr->a_vals[0].bv_val,0,0);
	}
	attr = attr_find( e->e_attrs, ad_searchFlags);
	if (attr != NULL) {
		ads_at->searchFlags = (int)strtol(attr->a_vals[0].bv_val,0,0);
	}

	attr = attr_find( e->e_attrs, ad_schemaFlagsEx);
	if (attr != NULL) {
		ads_at->schemaFlagsEx = (int)strtol(attr->a_vals[0].bv_val,0,0);
	}
	attr = attr_find( e->e_attrs, ad_msDS_IntId);
	if (attr != NULL) {
		ads_at->msDS_IntId = (int)strtol(attr->a_vals[0].bv_val,0,0);
	}
	attr = attr_find( e->e_attrs, ad_linkID);
	if (attr != NULL) {
		ads_at->linkID = (int)strtol(attr->a_vals[0].bv_val,0,0);
	}
	attr = attr_find( e->e_attrs, ad_mAPIID);
	if (attr != NULL) {
		ads_at->mAPIID = (int)strtol(attr->a_vals[0].bv_val,0,0);
	}
	attr = attr_find( e->e_attrs, ad_oMSyntax);
	if (attr != NULL) {
		ads_at->oMSyntax = (int)strtol(attr->a_vals[0].bv_val,0,0);
	}
	attr = attr_find( e->e_attrs, ad_systemOnly);
	if (attr != NULL) {
		if ((strcmp("TRUE", attr->a_vals[0].bv_val) == 0)) {
			ads_at->systemOnly++;
		}
	}
	attr = attr_find( e->e_attrs, ad_rangeLower);
	if (attr != NULL) {
		ads_at->rangeLower = (int)strtol(attr->a_vals[0].bv_val,0,0);
	}
	attr = attr_find( e->e_attrs, ad_rangeUpper);
	if (attr != NULL) {
		ads_at->rangeUpper = (int)strtol(attr->a_vals[0].bv_val,0,0);
	}
	attr = attr_find( e->e_attrs, ad_isMemberOfPartialAttributeSet);
	if ( attr && (strcmp("TRUE", attr->a_vals[0].bv_val) == 0)) {
		ads_at->isMemberOfPartialAttributeSet++;
	}

	if (no_config != 0) {
	
		if (ads_at->linkID > 0) {
	if (ads_at->linkID % 2 == 0) {
	ad_schema_add_refint(ldapDisplayName);
}
}
}
#if 0
		if (ads_at->searchFlags & SEARCH_FLAG_ATTINDEX) {
			ad_schema_add_index(ldapDisplayName);
		}
		
		if (ads_at->linkID > 0) {
			if (ads_at->linkID % 2 == 0) {
				ad_schema_add_refint(ldapDisplayName);
			}
//		ad_schema_add_memberof(ads_at->linkID, ldapDisplayName);
		}
	}
#endif
	at->at_private = ads_at;
}

static void ad_schema_load_extended_class(ObjectClass *oc, Entry *e)
{
	int rc = SLAP_CB_CONTINUE;
	Attribute *attr = NULL;
	struct ad_schema_class *ads_oc;
	AttributeDescription *ad_systemFlags = NULL;
	AttributeDescription *ad_showInAdvancedViewOnly = NULL;

	if (oc->oc_private != NULL) {
		Debug( LDAP_DEBUG_ANY,
		       "ad_schema_load_extended_class: data already present\n",
		       0, 0, 0 );
		return;
	}

	rc = slap_str2ad( "systemFlags", &ad_systemFlags, NULL );
	if ( rc != LDAP_SUCCESS ) {
		Debug( LDAP_DEBUG_ANY,
		       "ad_schema_load_extended_class: Failed to find description of systemFlags (%d)\n",
		       rc, 0, 0 );
		return;
	}
	rc = slap_str2ad( "showInAdvancedViewOnly", &ad_showInAdvancedViewOnly, NULL );
	ads_oc = ch_calloc(1, sizeof(struct ad_schema_class));

	attr = attr_find( e->e_attrs, ad_governsID);
	if (attr != NULL) {
		ber_dupbv( &ads_oc->governsID, &attr->a_vals[0]);
	}
	attr = attr_find( e->e_attrs, ad_schemaIDGUID);
	if (attr != NULL) {
		ber_dupbv( &ads_oc->schemaIDGUID, &attr->a_vals[0]);
	}
	attr = attr_find( e->e_attrs, ad_defaultSecurityDescriptor);
	if (attr != NULL) {
		ber_dupbv( &ads_oc->defaultSecurityDescriptor, &attr->a_vals[0]);
	}
	attr = attr_find( e->e_attrs, ad_msDS_IntId);
	if (attr != NULL) {
		ads_oc->msDS_IntId = (int)strtol(attr->a_vals[0].bv_val,0,0);
	}
	attr = attr_find( e->e_attrs, ad_systemFlags);
	if (attr != NULL) {
		ads_oc->systemFlags = (int)strtol(attr->a_vals[0].bv_val,0,0);
	}
	attr = attr_find( e->e_attrs, ad_systemOnly);
	if (attr != NULL) {
		if ((strcmp("TRUE", attr->a_vals[0].bv_val) == 0)) {
			ads_oc->systemOnly++;
		}
	}					
	attr = attr_find( e->e_attrs, ad_showInAdvancedViewOnly);
	if (attr != NULL) {
		if ((strcmp("TRUE", attr->a_vals[0].bv_val) == 0)) {
			ads_oc->showInAdvancedViewOnly++;
		}
	}
	attr = attr_find( e->e_attrs, ad_defaultHidingValue);
	if (attr != NULL) {
		ads_oc->defaultHidingValue = (int)strtol(attr->a_vals[0].bv_val,0,0);
	}

	attr = attr_find( e->e_attrs, ad_objectClassCategory);
	if (attr != NULL) {
		ads_oc->objectClassCategory = (int)strtol(attr->a_vals[0].bv_val,0,0);
	}
	oc->oc_private = ads_oc;
}

static int ad_schema_register_attribute(Entry *e, char *err_text, size_t err_len, int no_config)
{
	/*TODO - handle operational later, at this point some of those are still
	  generated by samba modules, so here they are not operational yet */
	struct berval *ldapDisplayName;
	int isSingleValued = 0;
	struct berval *oMObjectClass = NULL;
	struct berval *attributeId;
	int oMSyntax;
	char *equality = NULL;
	char *syntax = NULL;
	size_t def_len = 0;
	char *attr_def = NULL;
	char *p;
	int rc = SLAP_CB_CONTINUE, rc2, i;
	Attribute *attr = NULL;
	AttributeType *at = NULL;
	int remaining;

	attr = attr_find( e->e_attrs, ad_lDAPDisplayName);
	ldapDisplayName = &attr->a_vals[0];
	/* should not happen */
	if (!ldapDisplayName) {
		rc = LDAP_OTHER;
		snprintf(err_text, err_len, 
			 "ad_schema_register_attribute: displayName missing." );
		return rc;
	}

	at = at_bvfind(ldapDisplayName);
	if (at != NULL) {
		ad_schema_load_extended_attribute(at, e, ldapDisplayName, 1);
		Debug( LDAP_DEBUG_ANY,
		       "ad_schema_register_attribute: Attribute %s already present\n", ldapDisplayName->bv_val, 0, 0 );
		return SLAP_CB_CONTINUE;
	}

	attr = attr_find( e->e_attrs, ad_oMSyntax);
	oMSyntax = (int)strtol(attr->a_vals[0].bv_val,0,0);
	if (oMSyntax <= 0) { /* Todo error code */
		rc = LDAP_CONSTRAINT_VIOLATION;
		snprintf(err_text, err_len, 
			 "Invalid oMSyntax value." );
		return rc;
	}

	attr = attr_find( e->e_attrs, ad_isSingleValued);

	if ( attr && (strcmp("TRUE", attr->a_vals[0].bv_val) == 0)) {
		isSingleValued ++;
	}

	attr = attr_find( e->e_attrs, ad_attributeID);
	attributeId = &attr->a_vals[0];

	attr = attr_find( e->e_attrs, ad_oMObjectClass);
	if (attr != NULL) {
		oMObjectClass = &attr->a_vals[0];
	}

	if (oMSyntax == 127) {
		for (i = 0; ad_om_syntax[i].om_len != 0; i++) {
			if (oMObjectClass != NULL && oMObjectClass->bv_len == ad_om_syntax[i].om_len
			    && memcmp(oMObjectClass->bv_val, ad_om_syntax[i].om_buf,oMObjectClass->bv_len) == 0) {
				equality = ad_om_syntax[i].equality;
				syntax = ad_om_syntax[i].ldap_syntax;
				break;
			}
		}
	} else {
		for (i = 0; ad_syntax[i].oMSyntax != 0; i++) {
			if (oMSyntax == ad_syntax[i].oMSyntax) {
				equality = ad_syntax[i].equality;
				syntax = ad_syntax[i].ldap_syntax;
				break;	
			}
		}
	}

	if (syntax == NULL) {
		rc = LDAP_CONSTRAINT_VIOLATION;
		snprintf(err_text, err_len, 
			  "Invalid attribute syntax." );
		return rc;
	}

	def_len = strlen ("(   )") + attributeId->bv_len + strlen("NAME '' ") + ldapDisplayName->bv_len \
		+ strlen(syntax) + 2;

	if (equality != NULL) {
		def_len += strlen(equality) + 2;
	}
	if (isSingleValued > 0) {
		def_len += strlen("SINGLE-VALUE") + 2;
	}
	remaining = def_len;

	attr_def = ch_calloc(def_len, sizeof(char));
	p = attr_def;
	
	snprintf(p, def_len, "( %s NAME '%s' ", attributeId->bv_val, ldapDisplayName->bv_val);
	remaining -= strlen(p);
	p += strlen(p);
	
	if (equality != NULL) {
		snprintf(p, remaining, "%s ", equality);
	}
	remaining -= strlen(p);
	p += strlen(p);
	
	snprintf(p, remaining, "%s ", syntax);
	remaining -= strlen(p);
	p += strlen(p);
	if (isSingleValued > 0) {
		snprintf(p, remaining, "SINGLE-VALUE )");
	} else {
		snprintf(p, remaining," )");
	}
	Debug( LDAP_DEBUG_ANY,
		       "ad_schema_register_attribute:  %s \n", attr_def, 0, 0 );
	rc2 = register_at( attr_def, NULL, 0 );
	if ( rc2 ) {
		if (rc2 == SLAP_SCHERR_ATTR_DUP) {
			Debug( LDAP_DEBUG_ANY,
			       "ad_schema_register_attribute: attribute %s already registered\n", attr_def, 0, 0 );
		} else {
			Debug( LDAP_DEBUG_ANY,
			       "ad_schema_register_attribute: register_at %s failed\n", attr_def, 0, 0 );
			/* todo proper error, LDAP_OTHER or constraint violation? */
			rc = LDAP_OTHER;
			snprintf(err_text, err_len, 
				 "Unable to register attribute." );
		}
	}
	free(attr_def);

	at = at_bvfind(ldapDisplayName);
	if (at != NULL) {
		ad_schema_load_extended_attribute(at, e, ldapDisplayName, no_config);
	}
	return rc;
}

static int ad_schema_add_attribute(
	Operation *op,
	SlapReply *rs )
{
	int rc;
	char err_text[200];

	rc = ad_schema_register_attribute(op->ora_e, err_text, 200, 1);
	if (rc != SLAP_CB_CONTINUE) {
		send_ldap_error( op, rs, rc, err_text );
	}

	return rc;
}

static void ad_schema_merge_may(Attribute *attr, char **def)
{
	int i;
	int len = 0;
	char *p;
	if (attr && attr->a_numvals > 0) {
		for (i = 0; i < attr->a_numvals; i++) {
			struct berval *val = &attr->a_vals[i];
			len += val->bv_len + 4;
		}
	}

	if ( len > 0) {
		if (*def == NULL) {
			*def = ch_calloc(len, sizeof(char));
		} else {
			*def = realloc(*def, strlen(*def) + len);
		}
		if (attr && attr->a_numvals > 0) {
			for (i = 0; i < attr->a_numvals; i++) {
				struct berval *val = &attr->a_vals[i];
				p = *def;
				p+= strlen(*def);
				if (strlen(*def) != 0) {
					snprintf(p , val->bv_len + 4, " $ %s", val->bv_val);	
				} else {
					snprintf(p , val->bv_len + 1, "%s", val->bv_val);	
				}
			}
		}
	}
}

static int ad_schema_merge_auxiliary(Attribute *attr, char **def_may, char **def_must)
{
	int i;
	if (attr && attr->a_numvals > 0) {
		for (i = 0; i < attr->a_numvals; i++) {
			int j;
			struct berval *val = &attr->a_vals[i];
			char *p;
			AttributeType	*at;
			ObjectClass *oc = oc_bvfind(val);
			if (oc == NULL) {
				return LDAP_OTHER;
			}
			if (oc->soc_allowed) {
				for(j = 0; oc->soc_allowed[j] != NULL; j++) {
					at = oc->soc_allowed[j];
					if (*def_may == NULL) {
						*def_may = ch_calloc(at->sat_ad->ad_cname.bv_len+4, sizeof(char));
					} else {
						*def_may = realloc(*def_may, strlen(*def_may) + at->sat_ad->ad_cname.bv_len+4);
					}
					p = *def_may + strlen(*def_may);
					if (strlen(*def_may) != 0) {
						snprintf(p , at->sat_ad->ad_cname.bv_len + 4, " $ %s",  at->sat_ad->ad_cname.bv_val);	
					} else {
						snprintf(p , at->sat_ad->ad_cname.bv_len + 1, "%s", at->sat_ad->ad_cname.bv_val);	
					}
				}
			}

			if (oc->soc_required) {
				for(j = 0; oc->soc_required[j] != NULL; j++) {
					at = oc->soc_required[j];
					if (*def_must == NULL) {
						*def_must = ch_calloc(at->sat_ad->ad_cname.bv_len+4, sizeof(char));
					} else {
						*def_must = realloc(*def_must, strlen(*def_must) + at->sat_ad->ad_cname.bv_len+4);
					}
					p = *def_must + strlen(*def_must);
					if (strlen(*def_must) != 0) {
						snprintf(p , at->sat_ad->ad_cname.bv_len + 4, " $ %s",  at->sat_ad->ad_cname.bv_val);	
					} else {
						snprintf(p , at->sat_ad->ad_cname.bv_len + 1, "%s", at->sat_ad->ad_cname.bv_val);	
					}
				}
			}
		}
	}
	return LDAP_SUCCESS;
}


static struct {
	int oc_category;
	char *type;
} oc_types[] = {{0, "STRUCTURAL"}, {1, "STRUCTURAL"}, {2, "ABSTRACT"}, {3, "AUXILIARY"}};

static int ad_schema_register_class( Entry *e, char *err_text, size_t err_len)
{
	struct berval *ldapDisplayName;
	struct berval *governsID;
	struct berval *subclassOf = NULL;
	int objectClassCategory = 0;
	int rc = SLAP_CB_CONTINUE, rc2;
	Attribute *attr = NULL;
	Attribute *mustContain = NULL;
	Attribute *systemMustContain = NULL;
	Attribute *mayContain;
	Attribute *systemMayContain;
	Attribute *systemAuxiliaryClass;
	Attribute *auxiliaryClass;

	ObjectClass *oc;
	char *class_def = NULL;
	char *def_may = NULL;
	char *def_must = NULL;
	int len, remaining;
	char *p;
	char *type = NULL;

	attr = attr_find( e->e_attrs, ad_lDAPDisplayName);
	ldapDisplayName = &attr->a_vals[0];
	/* should not happen */
	if (!ldapDisplayName) {
		rc = LDAP_OTHER;
		snprintf(err_text, err_len, "ad_schema_register_class: displayName missing.");
		return rc;
	}
	oc = oc_bvfind(ldapDisplayName);
	if (oc != NULL) {
		ad_schema_load_extended_class(oc, e);
		/* todo gather and copy extra data here */
		Debug( LDAP_DEBUG_ANY,
		       "ad_schema_register_class: class %s already present\n", ldapDisplayName->bv_val, 0, 0 );
		return SLAP_CB_CONTINUE;
	}

	attr = attr_find( e->e_attrs, ad_governsID);
	governsID = &attr->a_vals[0];

	attr = attr_find( e->e_attrs, ad_subClassOf);
	if (attr != NULL) {
		subclassOf = &attr->a_vals[0];
	}
	attr = attr_find( e->e_attrs, ad_objectClassCategory);
	objectClassCategory = (int)strtol(attr->a_vals[0].bv_val,0,0);

	mustContain = attr_find( e->e_attrs, ad_mustContain);
	mayContain = attr_find( e->e_attrs, ad_mayContain);
	systemMustContain = attr_find( e->e_attrs, ad_systemMustContain);
	systemMayContain = attr_find( e->e_attrs, ad_systemMayContain);
	systemAuxiliaryClass = attr_find( e->e_attrs, ad_systemAuxiliaryClass);
	auxiliaryClass = attr_find( e->e_attrs, ad_auxiliaryClass);
	
	len = strlen("(  NAME '' )") + governsID->bv_len + ldapDisplayName->bv_len + \
		strlen(" MAY (  ) ") + strlen(" MUST (  ) ") + strlen("SUP  ");
	if (subclassOf) {
		len += subclassOf->bv_len +1;
	}

	ad_schema_merge_may(mustContain, &def_must);
	ad_schema_merge_may(mayContain, &def_may);
	ad_schema_merge_may(systemMayContain, &def_may);
	ad_schema_merge_may(systemMustContain, &def_may);
	if (ad_schema_merge_auxiliary(systemAuxiliaryClass, &def_may, &def_must) != LDAP_SUCCESS) {
		goto error;
	}

	if (ad_schema_merge_auxiliary(auxiliaryClass, &def_may, &def_must) != LDAP_SUCCESS) {
		goto error;
	}

	if (def_may) {
		len += strlen(def_may) + 4;
	}

	if (def_must) {
		len += strlen(def_must) + 4;
	}

	if (objectClassCategory >= 0 && objectClassCategory <= 3) {
		type = oc_types[objectClassCategory].type;
		len += strlen(type) + 3;
	}

	remaining = len;
	class_def = ch_calloc(len + 1, sizeof(char));
	snprintf(class_def, remaining, "( %s NAME '%s' ", governsID->bv_val, ldapDisplayName->bv_val);
	p = class_def + strlen(class_def);
	remaining -= strlen(class_def);
	if (subclassOf) {
		snprintf(p, remaining, "SUP %s ", subclassOf->bv_val);
		remaining -= strlen(p);
		p += strlen(p);
	}
	
	if (type != NULL) {
		snprintf(p, remaining, " %s", type);
		remaining -= strlen(p);
		p += strlen(p);
	}

	if (def_must) {
		snprintf(p, remaining, " MUST ( %s )", def_must);
		remaining -= strlen(p);
		p += strlen(p);
	}

	if (def_may) {
		snprintf(p, remaining, " MAY ( %s )", def_may);
		remaining -= strlen(p);
		p += strlen(p);
	}

	snprintf(p, remaining, " )");

	rc2 = register_oc( class_def, NULL, 0 );
	if ( rc2 ) {
error:
		Debug( LDAP_DEBUG_ANY,
		       "ad_schema_register_class: register_oc %s failed\n", class_def, 0, 0 );
		/* todo proper error, LDAP_OTHER or constraint violation? */
		rc = LDAP_OTHER;
		snprintf(err_text, err_len, 
			 "Unable to register class. %s", ldapDisplayName->bv_val);
	}

	if (class_def) {
		free(class_def);
	}
	if (def_may) {
		free(def_may);
	}
	if (def_must) {
		free(def_must);
	}
	oc = oc_bvfind(ldapDisplayName);
	if (oc != NULL) {
		ad_schema_load_extended_class(oc, e);
	}
	
	return rc;

}

static int ad_schema_add_class(
	Operation *op,
	SlapReply *rs )
{
	int rc;
	char err_text[200];
	rc = ad_schema_register_class(op->ora_e, err_text, 200);
	if (rc != SLAP_CB_CONTINUE) {
		send_ldap_error( op, rs, rc, err_text );
	}
	
	return rc;
}

static int ad_schema_add(
	Operation *op,
	SlapReply *rs )
{
	int i;
	Attribute *at_objectClass = attr_find( op->ora_e->e_attrs, slap_schema.si_ad_objectClass);
	assert (at_objectClass != 0);
	for (i = 0; i < at_objectClass->a_numvals; i++) {
		if (strcmp("attributeSchema", at_objectClass->a_vals[i].bv_val) == 0) {
			return ad_schema_add_attribute(op,rs);
		} else if (strcmp("classSchema", at_objectClass->a_vals[i].bv_val) == 0) {
			return ad_schema_add_class(op,rs);
		} else if (strcmp("dMD", at_objectClass->a_vals[i].bv_val) == 0) {
			return SLAP_CB_CONTINUE;
		} else if (strcmp("subSchema", at_objectClass->a_vals[i].bv_val) == 0) {
			return SLAP_CB_CONTINUE;
		} else { /* Todo temporary hack - figure out all object classes that belong here later */
			continue;
		}
	}
//neither classSchema nor attributeSchema return error (check the correct error)
/*	rc = LDAP_CONSTRAINT_VIOLATION;
	send_ldap_error( op, rs, rc,
	"Invalid object class for object in cn=Schema" ); */
	return SLAP_CB_CONTINUE;
//	return rc;
}
/*AttributeTypeDescriptionExtended = "(" whsp
numericoid whsp
; attributeID
[ "NAME" qdescrs ]
; lDAPDisplayName
[ "RANGE-LOWER" whsp numericstring ] ; rangeLower
[ "RANGE-UPPER" whsp numericstring ] ; rangeUpper
[ "PROPERTY-GUID" whsp guid ]
; schemaIDGUID
[ "PROPERTY-SET-GUID" whsp guid ]
; attributeSecurityGUID
[ "INDEXED" whsp ]
; fATTINDEX in searchFlags
[ "SYSTEM-ONLY" whsp ]
; systemOnly
whsp ")" */

static int ad_schema_at_extended(AttributeType *at, struct berval *val, TALLOC_CTX *talloc_mem_ctx)
{
	struct ad_schema_attribute *ads_at = at->at_private;
	char *ext_def;
	char *p;
	int def_len;
	struct GUID property_guid;
	struct GUID property_set_guid;
	char *property;
	char *property_set;
	if (ads_at == NULL) {
		return 0;
	}
	def_len = strlen ("(   )") + strlen("NAME '' ") + at->sat_cname.bv_len \
		+ ads_at->attributeID.bv_len + 4 \
		+ (strlen("RANGE-LOWER  ") + 12) + (strlen("RANGE-UPPER  ") + 12) \
		+ strlen("INDEXED ") + strlen("SYSTEM_ONLY");
	if (ads_at->schemaIDGUID.bv_len > 0) {
		def_len += ads_at->schemaIDGUID.bv_len *2 + strlen("PROPERTY-GUID  ")+2;
	}
	if (ads_at->attributeSecurityGUID.bv_len > 0) {
		def_len += ads_at->attributeSecurityGUID.bv_len *2 + strlen("PROPERTY-SET-GUID  ")+2;
	}
       
	ext_def = ch_calloc(def_len, sizeof(char));
	p = ext_def;
	sprintf(p, "( '%s' NAME '%s' ", ads_at->attributeID.bv_val, at->sat_cname.bv_val);
	p += strlen(p);
	if (ads_at->rangeLower > 0) {
		sprintf(p, "RANGE-LOWER '%u' ", ads_at->rangeLower);
		p += strlen(p);
	}
	if (ads_at->rangeUpper > 0) {
		sprintf(p, "RANGE-UPPER '%u' ", ads_at->rangeUpper);
		p += strlen(p);
	}

	if (ads_at->schemaIDGUID.bv_len > 0) {
		DATA_BLOB blob_val;
		blob_val.length = ads_at->schemaIDGUID.bv_len;
		blob_val.data = (uint8_t*)ads_at->schemaIDGUID.bv_val;
		GUID_from_ndr_blob(&blob_val, &property_guid);
		property = GUID_hexstring(talloc_mem_ctx, &property_guid),
		sprintf(p, "PROPERTY-GUID '%s' ", property);
		p += strlen(p);
	}
	if (ads_at->attributeSecurityGUID.bv_len > 0) {
		DATA_BLOB blob_val;
		blob_val.length = ads_at->attributeSecurityGUID.bv_len;
		blob_val.data = (uint8_t*)ads_at->attributeSecurityGUID.bv_val;
		GUID_from_ndr_blob(&blob_val, &property_set_guid);
		property_set = GUID_hexstring(talloc_mem_ctx, &property_set_guid),
		sprintf(p, "PROPERTY-SET-GUID '%s' ", property_set);
		p += strlen(p);
	}
	if (ads_at->searchFlags & SEARCH_FLAG_ATTINDEX) {
		sprintf(p, "INDEXED ");
		p += strlen(p);
	}
	if (ads_at->systemOnly > 0) {
		sprintf(p, "SYSTEM-ONLY ");
		p += strlen(p);
	}
	sprintf(p, ")");

	val->bv_val = ext_def;
	val->bv_len = strlen(ext_def);
	return 0;
}
/*ObjectClassDescriptionExtended = "(" whsp
numericoid whsp ; governsID
[ "NAME" qdescrs ] ; lDAPDisplayName
[ "CLASS-GUID" whsp guid ] ; schemaIDGUID
whsp ")" */
static int ad_schema_oc_extended(ObjectClass *oc, struct berval *val, TALLOC_CTX *talloc_mem_ctx)
{
	struct ad_schema_class *ads_oc = oc->oc_private;
	char *ext_def;
	int def_len;
	struct GUID class_guid;
	char *guid;
	if (ads_oc == NULL) {
		return 0;
	}
	def_len = strlen ("(   )") + strlen("NAME '' ") + oc->soc_cname.bv_len \
		+ ads_oc->governsID.bv_len + 2;
	if (ads_oc->schemaIDGUID.bv_len > 0) {
		DATA_BLOB blob_val;
		blob_val.length = ads_oc->schemaIDGUID.bv_len;
		blob_val.data = (uint8_t*)ads_oc->schemaIDGUID.bv_val;
		GUID_from_ndr_blob(&blob_val, &class_guid);
		guid = GUID_hexstring(talloc_mem_ctx, &class_guid),
			def_len += strlen(guid) *2 + strlen("CLASS-GUID  ");
	}
	ext_def = ch_calloc(def_len, sizeof(char));
	sprintf(ext_def, "( '%s' NAME '%s' CLASS-GUID '%s' )", ads_oc->governsID.bv_val,
		oc->soc_cname.bv_val, guid );

	val->bv_val = ext_def;
	val->bv_len = strlen(ext_def);
	return 0;
}

static int
ad_schema_at_info( Entry *e )
{
	AttributeDescription *ad_extendedAttributeInfo = slap_schema.si_ad_extendedAttributeInfo;
	AttributeType	*at;
	struct berval	val;
	struct berval	nval;
	TALLOC_CTX *talloc_mem_ctx = talloc_new(NULL);
	for ( at_start( &at ); at; at_next( &at ) ) {
		if( at->sat_flags & SLAP_AT_HIDE ) continue;
		ad_schema_at_extended(at, &val, talloc_mem_ctx);
		nval = val;

		if( attr_merge_one( e, ad_extendedAttributeInfo, &val, &nval ) )
		{
			talloc_free(talloc_mem_ctx);
			return -1;
		}
		//	free( val.bv_val );
	}
	talloc_free(talloc_mem_ctx);
	return 0;
}

static int
ad_schema_oc_info( Entry *e )
{
	AttributeDescription *ad_extendedClassInfo = slap_schema.si_ad_extendedClassInfo;
	ObjectClass	*oc;
	struct berval	val;
	struct berval	nval;
	TALLOC_CTX *talloc_mem_ctx = talloc_new(NULL);

        for ( oc_start( &oc ); oc != NULL; oc_next( &oc ) ) {
		if( oc->soc_flags & SLAP_OC_HIDE ) continue;
		
		ad_schema_oc_extended(oc, &val, talloc_mem_ctx);
		nval = val;

		if( attr_merge_one( e, ad_extendedClassInfo, &val, &nval ) ) {
			talloc_free(talloc_mem_ctx);
			return -1;
		}
		//	free( val.bv_val );
	}
	talloc_free(talloc_mem_ctx);
	return 0;
}

static int
ad_schema_info_cb( Operation *op, SlapReply *rs )
{
	if ( rs->sr_type == REP_SEARCH ) {
		struct berval rdn;
		dnRdn(&rs->sr_entry->e_nname, &rdn );
		if (strncmp(rdn.bv_val, "cn=aggregate", rdn.bv_len) != 0) {
			return SLAP_CB_CONTINUE;
		}
		/* AD does not provide syntaxes, matching rules and matching rule use */
		if ( at_schema_info( rs->sr_entry )
		     || oc_schema_info( rs->sr_entry )
		     || cr_schema_info( rs->sr_entry )
		     || ad_schema_at_info( rs->sr_entry )
		     || ad_schema_oc_info( rs->sr_entry ))
		{
			send_ldap_error( op, rs, LDAP_OTHER,
					 "Out of memory" );	
			return LDAP_OTHER;
		}
	}
	return SLAP_CB_CONTINUE;
}

static int
ad_schema_load_attrs_cb( Operation *op, SlapReply *rs )
{
	int rc = LDAP_SUCCESS;
	char err_text[200];

	if ( rs->sr_type == REP_SEARCH ) {
		rc = ad_schema_register_attribute(rs->sr_entry, err_text, 200, 0);
		
		if (rc != LDAP_SUCCESS) {
			return rc;
		}
	}
	return SLAP_CB_CONTINUE;
}

static int ad_schema_load_required_class_from_db(
	Operation *op,
	SlapReply *rs,
	struct berval *ldapDisplayName);

static int
ad_schema_load_check_required( Operation *op, SlapReply *rs )
{
	Attribute *attr;
	ObjectClass *oc;
	struct berval *ldapDisplayName;
	int i;

	attr = attr_find( rs->sr_entry->e_attrs, ad_subClassOf);
	if (attr != NULL) {
		ldapDisplayName = &attr->a_vals[0];
		oc = oc_bvfind(ldapDisplayName);
		if (oc == NULL) {
			ad_schema_load_required_class_from_db(op,rs,ldapDisplayName);
		}
	}
	attr = attr_find( rs->sr_entry->e_attrs, ad_systemAuxiliaryClass);
	if (attr && attr->a_numvals > 0) {
		for (i = 0; i < attr->a_numvals; i++) {
			ldapDisplayName = &attr->a_vals[i];
			oc = oc_bvfind(ldapDisplayName);
			if (oc == NULL) {
				ad_schema_load_required_class_from_db(op,rs,ldapDisplayName);
			}
		}
	}
	attr = attr_find( rs->sr_entry->e_attrs, ad_auxiliaryClass);
	if (attr && attr->a_numvals > 0) {
		for (i = 0; i < attr->a_numvals; i++) {
			ldapDisplayName = &attr->a_vals[i];
			oc = oc_bvfind(ldapDisplayName);
			if (oc == NULL) {
				ad_schema_load_required_class_from_db(op,rs,ldapDisplayName);
			}
		}
	}
	return 0;
}


static int
ad_schema_load_classes_cb( Operation *op, SlapReply *rs )
{
	int i, rc = LDAP_SUCCESS;
	char err_text[200];

	if ( rs->sr_type == REP_SEARCH ) {
		ad_schema_load_check_required( op, rs );
		rc = ad_schema_register_class(rs->sr_entry, err_text, 200);
		
		if (rc != LDAP_SUCCESS) {
			return rc;
		}
	}
	return SLAP_CB_CONTINUE;
}

static int
ad_schema_op_search( Operation *op, SlapReply *rs )
{
	slap_callback *sc = op->o_tmpcalloc( 1, sizeof( slap_callback ), op->o_tmpmemctx );
	sc->sc_response = ad_schema_info_cb;
	sc->sc_next = op->o_callback;
	op->o_callback = sc;
	return SLAP_CB_CONTINUE;
}

static int ad_schema_load_attr_from_db(
	BackendDB *be,
	ConfigReply *cr)
{
	slap_overinst *on = (slap_overinst *)be->bd_info;
	BackendDB db = *be;
	Connection conn = { 0 };
	OperationBuffer opbuf;
	Operation *op;
	void *thrctx = NULL;
	SlapReply new_rs = { 0 };
	slap_callback cb = { 0 };
	char *filter = "(objectClass=attributeSchema)";

	thrctx = ldap_pvt_thread_pool_context();
	connection_fake_init( &conn, &opbuf, thrctx );
	op = &opbuf.ob_op;
	op->o_bd = &db;
	op->o_dn = op->o_bd->be_rootdn;
	op->o_ndn = op->o_bd->be_rootndn;
	op->o_bd->bd_info = (BackendInfo *)on->on_info->oi_orig;
	op->ors_attrsonly = 0;
	op->ors_attrs = slap_anlist_no_attrs;
	op->ors_filterstr.bv_len = strlen(filter);
	op->ors_filterstr.bv_val = filter;
	op->ors_filter = str2filter_x( op, op->ors_filterstr.bv_val );
	op->ors_slimit =  SLAP_NO_LIMIT;
	op->ors_limit = NULL;
	op->ors_tlimit = SLAP_NO_LIMIT;
	cb.sc_private = NULL;
	cb.sc_response = ad_schema_load_attrs_cb;
	op->o_tag = LDAP_REQ_SEARCH;
	op->o_callback = &cb;
	op->ors_deref = LDAP_DEREF_NEVER;
	op->ors_scope = LDAP_SCOPE_SUBTREE;
	op->o_req_dn = op->o_bd->be_nsuffix[0];
	op->o_req_ndn = op->o_req_dn;

	(void)op->o_bd->be_search(op, &new_rs);
	if (new_rs.sr_err != LDAP_SUCCESS) {
		Debug( LDAP_DEBUG_ANY,
		       "ad_schema_load_attr_from_db: Unable to load schema from database\n", 0, 0, 0 );
	}
	return 0;

}


static int ad_schema_load_classes_from_db(
	BackendDB *be,
	ConfigReply *cr)
{
	slap_overinst *on = (slap_overinst *)be->bd_info;
	BackendDB db = *be;
	Connection conn = { 0 };
	OperationBuffer opbuf;
	Operation *op;
	void *thrctx = NULL;
	SlapReply new_rs = { 0 };
	slap_callback cb = { 0 };
	char *filter = "(objectClass=classSchema)";

	thrctx = ldap_pvt_thread_pool_context();
	connection_fake_init( &conn, &opbuf, thrctx );
	op = &opbuf.ob_op;
	op->o_bd = &db;
	op->o_dn = op->o_bd->be_rootdn;
	op->o_ndn = op->o_bd->be_rootndn;
	op->o_bd->bd_info = (BackendInfo *)on->on_info->oi_orig;
	op->ors_attrsonly = 0;
	op->ors_attrs = slap_anlist_no_attrs;
	op->ors_filterstr.bv_len = strlen(filter);
	op->ors_filterstr.bv_val = filter;
	op->ors_filter = str2filter_x( op, op->ors_filterstr.bv_val );
	op->ors_slimit =  SLAP_NO_LIMIT;
	op->ors_limit = NULL;
	op->ors_tlimit = SLAP_NO_LIMIT;
	cb.sc_private = NULL;
	cb.sc_response = ad_schema_load_classes_cb;
	op->o_tag = LDAP_REQ_SEARCH;
	op->o_callback = &cb;
	op->ors_deref = LDAP_DEREF_NEVER;
	op->ors_scope = LDAP_SCOPE_SUBTREE;
	op->o_req_dn = op->o_bd->be_nsuffix[0];
	op->o_req_ndn = op->o_req_dn;

	(void)op->o_bd->be_search(op, &new_rs);
	if (new_rs.sr_err != LDAP_SUCCESS) {
		Debug( LDAP_DEBUG_ANY,
		       "ad_schema_load_classes_from_db: Unable to load schema from database\n", 0, 0, 0 );
	}
	return 0;

}

static int ad_schema_load_required_class_from_db(
	Operation *op,
	SlapReply *rs,
	struct berval *ldapDisplayName)
{
	slap_overinst *on = (slap_overinst *)op->o_bd->bd_info;
	BackendDB db = *op->o_bd;
	Operation new_op = *op;
	SlapReply new_rs = { 0 };
	slap_callback cb = { 0 };
	char *filter = "(&(objectClass=classSchema)(ldapDisplayName=)";

	new_op.o_bd = &db;
	new_op.o_dn = op->o_bd->be_rootdn;
	new_op.o_ndn = op->o_bd->be_rootndn;
	new_op.o_bd->bd_info = (BackendInfo *)on->on_info->oi_orig;
	new_op.ors_attrsonly = 0;
	new_op.ors_attrs = slap_anlist_no_attrs;
	new_op.ors_filterstr.bv_len = STRLENOF( filter ) + ldapDisplayName->bv_len;
	new_op.ors_filterstr.bv_val = op->o_tmpalloc( new_op.ors_filterstr.bv_len+1, op->o_tmpmemctx );
	sprintf(new_op.ors_filterstr.bv_val, "(&(objectClass=classSchema)(ldapDisplayName=%s)", ldapDisplayName->bv_val);
	new_op.ors_filter = str2filter_x( op, new_op.ors_filterstr.bv_val );
	new_op.ors_slimit =  SLAP_NO_LIMIT;
	new_op.ors_limit = NULL;
	new_op.ors_tlimit = SLAP_NO_LIMIT;
	cb.sc_private = NULL;
	cb.sc_response = ad_schema_load_classes_cb;
	new_op.o_tag = LDAP_REQ_SEARCH;
	new_op.o_callback = &cb;
	new_op.ors_deref = LDAP_DEREF_NEVER;
	new_op.ors_scope = LDAP_SCOPE_SUBTREE;
	new_op.o_req_dn = op->o_bd->be_nsuffix[0];
	new_op.o_req_ndn = op->o_req_dn;

	(void)new_op.o_bd->be_search(&new_op, &new_rs);
	if (new_rs.sr_err != LDAP_SUCCESS) {
		Debug( LDAP_DEBUG_ANY,
		       "ad_schema_load_required_class_from_db: Unable to load schema from database\n", 0, 0, 0 );
	}
	op->o_tmpfree(new_op.ors_filterstr.bv_val, op->o_tmpmemctx);
	filter_free_x( op, new_op.ors_filter, 1 );
	return 0;

}
static int ad_schema_db_open(
	BackendDB *be,
	ConfigReply *cr)
{
	/* Todo execute this is separate thread */
	ad_schema_load_attr_from_db(be, cr);
	ad_schema_load_classes_from_db(be, cr);
	return 0;
}

int
ad_schema_init( void )
{
	int i, code;

	ad_schema.on_bi.bi_type = "ad_schema";
	ad_schema.on_bi.bi_op_add = ad_schema_add;
	ad_schema.on_bi.bi_db_open = ad_schema_db_open;
	ad_schema.on_bi.bi_op_search = ad_schema_op_search;
	for ( i=0; ad_syntaxes[i].oid; i++ ) {	
		code = register_syntax( &ad_syntaxes[ i ].syn );
		if ( code != 0 ) {
			Debug( LDAP_DEBUG_ANY,
				"ad_schema_init: register_syntax failed\n",
				0, 0, 0 );
			return code;
		}

		if ( ad_syntaxes[i].mrs != NULL ) {
			code = mr_make_syntax_compat_with_mrs(
				ad_syntaxes[i].oid, ad_syntaxes[i].mrs );
			if ( code < 0 ) {
				Debug( LDAP_DEBUG_ANY,
					"ad_schema_init: "
					"mr_make_syntax_compat_with_mrs "
					"failed\n",
					0, 0, 0 );
				return code;
			}
		}
	}


	for ( i = 0; as[i].desc; i++ ) {
		code = register_at( as[i].desc, as[i].adp, 0 );
		if ( code ) {
			Debug( LDAP_DEBUG_ANY,
				"ad_schema_init: register_at #%d failed\n", i, 0, 0 );
			return code;
		}
	}

	for ( i=0; schema_ocs[i].ot; i++ ) {
		code = register_oc( schema_ocs[i].ot, schema_ocs[i].oc, 0 );
		if ( code ) {
			Debug( LDAP_DEBUG_ANY,
			       "ad_schema_init: register_oc failed\n",
			       0, 0, 0 );
			return -1;
		}
	}

	return overlay_register( &ad_schema );
}

#if SLAPD_OVER_AD_SCHEMA == SLAPD_MOD_DYNAMIC
int
init_module( int argc, char *argv[] )
{
	return ad_schema_init();
}
#endif /* SLAPD_OVER_AD_SCHEMA == SLAPD_MOD_DYNAMIC */

#endif /* defined(SLAPD_OVER_AD_SCHEMA) */
