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
#ifndef AD_SCHEMA_H
#define AD_SCHEMA_H

/* System Flags */
#define AD_FLAGS_ATTR_NOT_REPLICATED         0x00000001
#define AD_FLAGS_ATTR_REQ_PARTIAL_SET_MEMBER 0x00000002
#define AD_FLAGS_ATTR_IS_CONSTRUCTED         0x00000004
#define AD_FLAGS_ATTR_IS_OPERATIONAL         0x00000008
#define AD_FLAGS_SCHEMA_BASE_OBJECT          0x00000010
#define AD_FLAGS_ATTR_IS_RDN                 0x00000020
#define AD_FLAGS_DISALLOW_MOVE_ON_DELETE     0x02000000
#define AD_FLAGS_DOMAIN_DISALLOW_MOVE        0x04000000
#define AD_FLAGS_DOMAIN_DISALLOW_RENAME      0x08000000
#define AD_FLAGS_CONFIG_ALLOW_LIMITED_MOVE   0x10000000
#define AD_FLAGS_CONFIG_ALLOW_MOVE           0x20000000
#define AD_FLAGS_CONFIG_ALLOW_RENAME         0x40000000
#define AD_FLAGS_DISALLOW_DELETE             0x80000000

/* schemaFlagsEx */
#define AD_FLAGS_ATTR_IS_CRITICAL            0x00000001

/* Search Flags */

#define AD_FLAGS_ATTINDEX                    0x00000001
#define AD_FLAGS_PDNT_ATTINDEX               0x00000002
#define AD_FLAGS_ANR                         0x00000004
#define AD_FLAGS_PRESERVE_ON_DELETE          0x00000008
#define AD_FLAGS_COPY                        0x00000010
#define AD_FLAGS_TUPLE_INDEX                 0x00000020
#define AD_FLAGS_SUBTREE_ATTINDEX            0x00000040
#define AD_FLAGS_CONFIDENTIAL                0x00000080
#define AD_FLAGS_NEVER_VALUEAUDIT            0x00000100
#define AD_FLAGS_RODC_FILTERED_ATTR          0x00000200
#define AD_FLAGS_EXTENDED_LINK_TRACKING      0x00000400
#define AD_FLAGS_BASE_ONLY                   0x00000800
#define AD_FLAGS_PARTITION_SECRET            0x00001000

struct ad_schema_attribute {
	struct berval attributeID;
	struct berval attributeSyntax;
	struct berval schemaIDGUID;
	struct berval oMObjectClass;
	struct berval attributeSecurityGUID;
	unsigned long systemFlags;
	unsigned long searchFlags;
	unsigned long schemaFlagsEx;
	int msDS_IntId;
	int linkID;
	int mAPIID; 
	int oMSyntax;
	int systemOnly;
	int rangeLower;
	int rangeUpper;
	int isMemberOfPartialAttributeSet;
};

struct ad_schema_class {
	struct berval governsID;
	struct berval schemaIDGUID;
	struct berval defaultSecurityDescriptor;
	int msDS_IntId;
	int defaultHidingValue;
	int showInAdvancedViewOnly;
	int objectClassCategory;
	int systemFlags;
	int systemOnly;
/* TODO implement these if necessary
   systemMustContain
   systemMayContain
   systemPossSuperiors
   systemAuxiliaryClass
   mustContain
   systemMayContain
   possSuperiors
   auxiliaryClass
*/
};

#endif /* AD_SCHEMA_H */
