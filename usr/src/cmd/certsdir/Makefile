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
# Copyright 2012 Joshua M. Clulow <josh@sysmgr.org>
#
PROG=		certsdir

OBJS=		certsdir.o utils.o scf.o
SRCS=	 	$(OBJS:%.o=%.c)

include ../Makefile.cmd

FILEMODE =	0555

MANIFEST =		certsdir.xml
ROOTMANIFESTDIR =	$(ROOTSVCSYSTEM)

LDLIBS +=	-lscf

.KEEP_STATE:

.PARALLEL: $(OBJS)

all:		$(PROG) 

$(PROG):	$(OBJS)
	$(LINK.c) $(OBJS) -o $@ $(LDLIBS)
	$(POST_PROCESS)

install: all .WAIT $(ROOTLIBPROG) $(ROOTMANIFEST)

lint: 	lint_SRCS

clean:
	$(RM) $(OBJS)

include ../Makefile.targ
