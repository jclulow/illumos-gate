#!/bin/bash

set -o errexit
set -o pipefail

UNIFDEF=${UNIFDEF:-/ws/unifdef/unifdef-2.12/unifdef}

if [[ -z "$CODEMGR_WS" ]]; then
	echo 'bldenv?' >&2
	exit 1
fi
cd "$SRC"

function whack {
	local args=''
	local pat=$1
	shift

	while :; do
		case "$1" in
		'')
			break;
			;;
		asm)
			shift
			args+=' -t'
			;;
		*)
			echo 'pardon?' >&2
			exit 1
			;;
		esac
	done

	#
	# Find all the C (or C-like) files that mention __xpv and clean out the
	# ifdefs:
	#
	(git grep -l -w __xpv "$pat" || true) | while read f; do
		if "$UNIFDEF" -B -m -U__xpv $args "$f"; then
			printf 'unmodified: %s\n' "$f"
		else
			rc=$?
			if (( rc == 1 )); then
				printf 'modified: %s\n' "$f"
			else
				printf 'error %d on %s\n' "$rc" "$f"
				exit 1
			fi
		fi
	done
}

whack 'uts/**/*.c'
whack 'uts/**/*.h'
whack 'uts/**/*.s' asm
