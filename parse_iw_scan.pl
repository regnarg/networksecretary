#!/usr/bin/perl -n

sub end_item {
    
}

if (/^BSS ([0-9a-f]{2}(?::[0-9a-f]{2}){5})/i) {
    if ($bssid) { end_item; }
    $bssid = $1;
}

if (/^\s*SSID:\s*(.*)$/) {
    $essid = $1;
}

END { end_item; }
