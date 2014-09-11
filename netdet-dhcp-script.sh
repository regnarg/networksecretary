#!/bin/bash

[[ "$1" == bound ]]  || exit 0

get_mac() {
    arping -f -D -s 0.0.0.0 -I "$interface" "$1" | grep reply | grep -Eoi '[0-9a-f]{2}(:[0-9a-f]{2}){5}'
}

if [[ -n "$router" ]]; then
    gwmac="$(get_mac "$router")"
fi

if [[ -n "$gwmac" ]]; then
    macid="gw:$gwmac"
else
    dhcp_mac="$(get_mac "$serverid")"
    if [[ -n "$dhcp_mac" ]]; then
        macid="dhcp:$dhcp_mac"
    fi
fi

[[ -n "$macid" ]] || exit 1

netstr="$router:$subnet:$macid"
echo >&2 "network ident string: $netstr"
echo "$netstr" |md5sum |cut -c 1-6 >&5
