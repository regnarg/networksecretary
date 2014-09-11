#!/bin/bash

# The ``grep .`` ensures that we return a nonzero exit when no network id
# is output.
udhcpc -i "$1" -fqn -s "$(dirname "$0")/netdet-dhcp-script.sh"  5>&1 >/dev/null |grep .

