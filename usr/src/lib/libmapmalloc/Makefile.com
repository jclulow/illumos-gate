#
# CDDL HEADER START
#
# The contents of this file are subject to the terms of the
# Common Development and Distribution License (the "License").
# You may not use this file except in compliance with the License.
#
# You can obtain a copy of the license at usr/src/OPENSOLARIS.LICENSE
# or http://www.opensolaris.org/os/licensing.
# See the License for the specific language governing permissions
# and limitations under the License.
#
# When distributing Covered Code, include this CDDL HEADER in each
# file and include the License file at usr/src/OPENSOLARIS.LICENSE.
# If applicable, add the following below this CDDL HEADER, with the
# fields enclosed by brackets "[]" replaced with your own identifying
# information: Portions Copyright [yyyy] [name of copyright owner]
#
# CDDL HEADER END
#
# Copyright (c) 2014, Joyent, Inc.
#
# Copyright 2007 Sun Microsystems, Inc.  All rights reserved.
# Use is subject to license terms.
#

LIBRARY=	libmapmalloc.a
VERS=		.1

C_OBJECTS = \
	calloc.o \
	textmem.o \
	valloc.o

ASM_OBJECTS = \
	asm_subr.o

OBJECTS = $(C_OBJECTS) $(ASM_OBJECTS)

# include library definitions
include ../../Makefile.lib

SRCDIR =	../common

LIBS =		$(DYNLIB) $(LINTLIB)

LINTSRC=	$(LINTLIB:%.ln=%)

CFLAGS +=	$(CCVERBOSE)
CPPFLAGS +=	-I../common -I../../common/inc -D_REENTRANT
DYNFLAGS +=	$(ZINTERPOSE)
LDLIBS +=	-lc
ASFLAGS +=	-P -D_ASM

$(LINTLIB) lint :=	LINTFLAGS += -erroff=E_BAD_PTR_CAST_ALIGN
$(LINTLIB) lint :=	LINTFLAGS64 += -erroff=E_BAD_PTR_CAST_ALIGN

$(LINTLIB) lint :=	SRCS = $(C_OBJECTS:%.o=../common/%.c) \
			$(ASM_OBJECTS:%.o=$(ISASRCDIR)/%.s)

.KEEP_STATE:

lint: lintcheck

# include library targets
include ../../Makefile.targ

pics/%.o: ../common/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

pics/%.o: $(ISASRCDIR)/%.s
	$(COMPILE.s) -o $@ $<
	$(POST_PROCESS_O)

# install rule for lint library target
$(ROOTLINTDIR)/%:	../common/%
	$(INS.file)
