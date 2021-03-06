# $OpenLDAP$
# This work is part of OpenLDAP Software <http://www.openldap.org/>.
#
# Copyright 1998-2018 The OpenLDAP Foundation.
# Copyright 2004 Howard Chu, Symas Corp. All Rights Reserved.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted only as authorized by the OpenLDAP
# Public License.
#
# A copy of this license is available in the file LICENSE in the
# top-level directory of the distribution or, alternatively, at
# <http://www.OpenLDAP.org/license.html>.

LDAP_SRC = ../../..
LDAP_BUILD = $(LDAP_SRC)
LDAP_INC = -I$(LDAP_BUILD)/include -I$(LDAP_SRC)/include -I$(LDAP_SRC)/servers/slapd -I/usr/local/samba/include
LDAP_LIB = $(LDAP_BUILD)/libraries/libldap_r/libldap_r.la \
	$(LDAP_BUILD)/libraries/liblber/liblber.la

LIBTOOL = $(LDAP_BUILD)/libtool
CC = gcc
OPT = -g -O2 -Wall -L/usr/local/samba/lib -L/usr/local/lib/ldb -Wl,-rpath=/usr/local/samba/lib \
	-lsamba-security -lndr -lldb -ltalloc

DEFS = -DSLAPD_OVER_RDNVAL=SLAPD_MOD_DYNAMIC \
	-DSLAPD_OVER_PGUID=SLAPD_MOD_DYNAMIC \
	-DSLAPD_OVER_VERNUM=SLAPD_MOD_DYNAMIC \
	-DSLAPD_OVER_AD_SCHEMA=SLAPD_MOD_DYNAMIC \
	-DSLAPD_OVER_SHOWDELETED=SLAPD_MOD_DYNAMIC \
	-DSLAPD_OVER_SECDESCRIPTOR=SLAPD_MOD_DYNAMIC \
	-DSLAPD_OVER_OPPREP=SLAPD_MOD_DYNAMIC \
	-DSLAPD_OVER_OBJECTGUID=SLAPD_MOD_DYNAMIC \
	-DSLAPD_OVER_SAMBA_ACL=SLAPD_MOD_DYNAMIC

INCS = $(LDAP_INC)
LIBS = $(LDAP_LIB)

PROGRAMS = pguid.la \
	rdnval.la \
	vernum.la \
	libsamba_utils.la \
	ad_schema.la \
	show_deleted.la \
	secdescriptor.la \
	opprep.la \
	objectguid.la \
	samba_acl.la

LTVER = 0:0:0

prefix=/usr/local
exec_prefix=$(prefix)
ldap_subdir=/openldap

libdir=$(exec_prefix)/lib
libexecdir=$(exec_prefix)/libexec
moduledir = $(libexecdir)$(ldap_subdir)

.SUFFIXES: .c .o .lo

.c.lo:
	$(LIBTOOL) --mode=compile $(CC) $(OPT) $(DEFS) $(INCS) -c $<

all: $(PROGRAMS)

libsamba_utils.la: samba_utils.lo
	$(LIBTOOL) --mode=link $(CC) $(OPT) -version-info $(LTVER) \
	-rpath $(moduledir) -shared -o $@ $? $(LIBS)

pguid.la: pguid.lo
	$(LIBTOOL) --mode=link $(CC) $(OPT) -version-info $(LTVER) \
	-rpath $(moduledir) -module -o $@ $? $(LIBS)

rdnval.la: rdnval.lo
	$(LIBTOOL) --mode=link $(CC) $(OPT) -version-info $(LTVER) \
	-rpath $(moduledir) -module -o $@ $? $(LIBS)

vernum.la: vernum.lo
	$(LIBTOOL) --mode=link $(CC) $(OPT) -version-info $(LTVER) \
	-rpath $(moduledir) -module -o $@ $? $(LIBS)

ad_schema.la: ad_schema.lo
	$(LIBTOOL) --mode=link $(CC) $(OPT) -version-info $(LTVER) \
	-rpath $(moduledir) -module -o $@ $? $(LIBS)

show_deleted.la: show_deleted.lo
	$(LIBTOOL) --mode=link $(CC) $(OPT) -version-info $(LTVER) \
	-rpath $(moduledir) -module -o $@ $? $(LIBS)

secdescriptor.la: secdescriptor.lo
	$(LIBTOOL) --mode=link $(CC) $(OPT) -version-info $(LTVER) \
	-rpath $(moduledir) -module -o $@ $? $(LIBS) ./.libs/libsamba_utils.la

opprep.la: opprep.lo
	$(LIBTOOL) --mode=link $(CC) $(OPT) -version-info $(LTVER) \
	-rpath $(moduledir) -module -o $@ $? $(LIBS) ./.libs/libsamba_utils.la

objectguid.la: objectguid.lo
	$(LIBTOOL) --mode=link $(CC) $(OPT) -version-info $(LTVER) \
	-rpath $(moduledir) -module -o $@ $? $(LIBS) ./.libs/libsamba_utils.la

samba_acl.la: samba_acl.lo
	$(LIBTOOL) --mode=link $(CC) $(OPT) -version-info $(LTVER) \
	-rpath $(moduledir) -module -o $@ $? $(LIBS) ./.libs/libsamba_utils.la

clean:
	rm -rf *.o *.lo *.la .libs

install: $(PROGRAMS)
	mkdir -p $(DESTDIR)$(moduledir)
	for p in $(PROGRAMS) ; do \
		$(LIBTOOL) --mode=install cp $$p $(DESTDIR)$(moduledir) ; \
	done

