#
# Copyright 2012 Joshua M. Clulow <josh@sysmgr.org>
#

BINARIES= git-outgoing

CLEANFILES += $(BINARIES)

include ../Makefile.tools

.KEEP_STATE:

all:	$(BINARIES)

install: all .WAIT $(ROOTONBLDMACHBINARIES)

clean:
	$(RM) $(CLEANFILES)

include ../Makefile.targ
