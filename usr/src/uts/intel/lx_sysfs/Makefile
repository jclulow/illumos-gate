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
# Copyright 2015 Joyent, Inc.
#

#
# uts/intel/lx_sysfs/Makefile
#
#	This makefile drives the production of the lx_sysfs file system
#	kernel module.
#
#	i86 architecture dependent
#

#
#	Path to the base of the uts directory tree (usually /usr/src/uts).
#
UTSBASE	= ../..

#
#	Path to where brand common sources live
#
LX_CMN		= $(SRC)/common/brand/lx

#
#	Define the module and object file sets.
#
MODULE		= lx_sysfs
OBJECTS		= $(LX_SYSFS_OBJS:%=$(OBJS_DIR)/%)
LINTS		= $(LX_SYSFS_OBJS:%.o=$(LINTS_DIR)/%.ln)
ROOTMODULE	= $(USR_FS_DIR)/$(MODULE)

INC_PATH	+= -I$(UTSBASE)/common/brand/lx 
INC_PATH	+= -I$(UTSBASE)/common/brand/lx/procfs
INC_PATH	+= -I$(LX_CMN)

#
#	Include common rules.
#
include $(UTSBASE)/intel/Makefile.intel

#
#	Define targets
#
ALL_TARGET	= $(BINARY)
LINT_TARGET	= $(MODULE).lint
INSTALL_TARGET	= $(BINARY) $(ROOTMODULE)

#
#	Overrides.
#
CFLAGS		+= $(CCVERBOSE)

#
#	Depends on procfs and lx_brand
#
LDFLAGS		+= -dy -Nfs/procfs -Nbrand/lx_brand

#
#	Default build targets.
#
.KEEP_STATE:

def:		$(DEF_DEPS)

all:		$(ALL_DEPS)

clean:		$(CLEAN_DEPS)

clobber:	$(CLOBBER_DEPS)

lint:		$(LINT_DEPS)

modlintlib:	$(MODLINTLIB_DEPS)

clean.lint:	$(CLEAN_LINT_DEPS)

install:	$(INSTALL_DEPS)

#
#	Include common targets.
#
include $(UTSBASE)/intel/Makefile.targ

#
#	Include brand-specific rules
#

include $(UTSBASE)/intel/lx_sysfs/Makefile.rules
