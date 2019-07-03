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
# Copyright 2019 Joyent, Inc.
#

include $(SRC)/Makefile.master

ROOTOPTPKG =	$(ROOT)/opt/util-tests
TESTDIR =	$(ROOTOPTPKG)/tests/strings
ROOTBINDIR =	$(ROOTOPTPKG)/bin

TEST_PROGRAMS = \
		strings_test0 \
		strings_test1 \
		strings_test2 \
		strings_test3 \
		strings_test4 \
		strings_testpath

COMMON_OBJS = \
		force_umem_debug.o \
		strlist.o \
		strpath.o

include $(SRC)/cmd/Makefile.cmd
include $(SRC)/test/Makefile.com

OBJS =		$(TEST_PROGRAMS:%=%.o)
SRCS =		$(OBJS:%.o=%.c)

CMDS =		$(TEST_PROGRAMS:%=$(TESTDIR)/%)
$(CMDS) :=	FILEMODE = 0555

CFLAGS +=	-I$(SRC)/common/strings
LDLIBS +=	-lcustr
CSTD =		$(CSTD_GNU99)


all: $(TEST_PROGRAMS)

strings_%: strings_%.o $(COMMON_OBJS)
	$(LINK.c) $^ -o $@ $(LDLIBS)
	$(POST_PROCESS)

%.o: $(SRC)/common/strings/%.c
	$(COMPILE.c) -o $@ $<
	$(POST_PROCESS_O)

install: all $(CMDS)

clobber: clean
	-$(RM) $(TEST_PROGRAMS)

clean:
	-$(RM) $(OBJS) $(COMMON_OBJS)

$(CMDS): $(TESTDIR) $(TEST_PROGRAMS)

$(TESTDIR):
	$(INS.dir)

$(TESTDIR)/%: %
	$(INS.file)
