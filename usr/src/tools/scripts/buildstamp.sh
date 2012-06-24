#!/usr/bin/ksh -p
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

#
# Copyright 2012 Joshua M. Clulow <josh@sysmgr.org>
#

WHICH_SCM=which_scm
CW=cw
NAWK=nawk


echo "date: $(date)"
echo "uname: $(uname -a)"

$WHICH_SCM | read scm_type junk || exit 1
cmd=
if [[ $scm_type == "git" ]]; then
	cmd="git rev-parse --verify HEAD"
elif [[ $scm_type == "mercurial" ]]; then
	cmd="hg log -r tip --template {node}"
fi
if [[ -n $cmd ]]; then
	echo "scm: ${scm_type} $($cmd)"
fi

$CW -_versions 2>&1 | $NAWK '
  /^primary:/ { print; watch = 1; next; }
  watch == 1  { print("primaryversion: " $0); watch = 0; next; }
  /^shadow:/  { print; watch = 2; next; }
  watch == 2  { print("shadowversion: " $0); watch = 0; next; }
'

exit 0
