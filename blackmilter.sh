#!/bin/sh
#
# blackmilter.sh - startup script for blackmilter on FreeBSD
#
# This goes in /usr/local/etc/rc.d and gets run at boot-time.
#
# Variables available:
#   blackmilter_enable='YES/NO'
#   blackmilter_program='path'
#   blackmilter_socket='path'
#   blackmilter_flags='flags'

# PROVIDE: blackmilter
# REQUIRE: LOGIN FILESYSTEMS
# BEFORE: mail

. /etc/rc.subr

name='blackmilter'
rcvar='blackmilter_enable'

load_rc_config "$name"

# Defaults.
blackmilter_enable="${blackmilter_enable:-NO}"
blackmilter_program="${blackmilter_program:-/usr/local/sbin/blackmilter}"
blackmilter_socket="${blackmilter_socket:-/var/run/blackmilter.sock}"
blackmilter_flags="${blackmilter_flags:--autoupdate}"

# Add socket to any given argument.
blackmilter_flags="${blackmilter_flags} ${blackmilter_socket}"

command="$blackmilter_program"

run_rc_command "$1"
