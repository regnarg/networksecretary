#!/bin/bash

# Traverse all variable names starting with lowercase
# (good heuristic for `udhcpc` variables).
#
# For the ``>&5`` trick, see ``udhcpc-wrapper.sh``.

export event="$1" # Also include the event type in the output
env |grep -E '^[a-z]' >&5
echo >&5
