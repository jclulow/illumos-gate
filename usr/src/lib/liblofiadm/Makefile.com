#
# This file and its contents are supplied under the terms of the
# Common Development and Distribution License ("CDDL"), version 1.0.
# You may only use this file in accordance with the terms of version
# 1.0 of the CDDL.
#
# A full copy of the text of the CDDL should have accompanied this
# source.  A copy of the CDDL is also available via the Internet at
# http://www.illumos.org/license/CDDL.
#

#
# Copyright 2021 Oxide Computer Company
#

LIBRARY =	liblofiadm.a
VERS =		.1

OBJECTS =	ilstr.o liblofiadm.o

include $(SRC)/lib/Makefile.lib
include $(SRC)/lib/Makefile.rootfs

CSTD =		$(CSTD_GNU99)

CPPFLAGS +=	-I$(SRC)/common/ilstr

LIBS =		$(DYNLIB)
LDLIBS +=	-lc

SRCDIR =	../common

.KEEP_STATE:

all: $(LIBS)

include $(SRC)/lib/Makefile.targ

pics/ilstr.o: $(SRC)/common/ilstr/ilstr.c
	$(COMPILE.c) -o $@ $^
	$(POST_PROCESS_O)
