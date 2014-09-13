#!/bin/bash

# The ``grep .`` ensures that we return a nonzero exit when no network id
# is output.

# HACK ALERT: The fake client ID is currently necessary. Without it, we get
# a random lease, then identify network and then try to reuse the last lease
# for that network, which ultimately fails because we already have a lease.
# Therefore we have to pretend that we are someone else.
#
# A clean solution will be to send only a DHCPDISCOVER during network detection,
# not a DHCPREQUEST (i.e., not to accept the offer). However, none of the common
# DHCP clients can do this nor did I find a usable DHCP library.
udhcpc -i "$1" -fqn -s "$(dirname "$0")/netdet-dhcp-script.sh"  -c 11:22:33:44:55:66 5>&1 >/dev/null |grep .

