#!/bin/bash

# `udhcpc` has the unfortunate habit of outputting messages to stdout.
# We have to redirect them to stderr, so that they aren't intermixed
# with parsable data from our script.
exec 5>&1 >&2

# The  `exec` here is important. Otherwise Network Secretary couldn't
# easily kill the `udhcpc` process.
exec udhcpc -s "$(dirname "$0")/udhcpc-script.sh" "$@"
