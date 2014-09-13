#!/usr/bin/perl -n

use JSON;
our %data;

sub end_item {
    if (!%data) { return };
    # XXX Can WPA and WEP be both allowed on one AP? I have not found any other criterion
    #     for WEP APs than that they have the Privacy capability and do not have WPA/RSN.
    if ($privacy_cap && !%auth) {
        $auth{wep} = 1;
    }
    if ($privacy_cap && !%enc) {
        $auth{wep} = 1;
    }
    my @auth = keys %auth;
    $data{auth} = \@auth;
    my @enc = keys %enc;
    $data{enc} = \@enc;
    my %tmp = %data;
    push @out, \%tmp if (%data);
}

if (/^BSS ([0-9a-f]{2}(?::[0-9a-f]{2}){5})/i) {
    end_item;
    $privacy_cap = 0;
    %data = ();
    %auth = ();
    %enc = ();
    $data{bssid} = $1;
}

if (/capability:.*\bprivacy\b/i) {
    $privacy_cap = 1;
}

if (/^\s*(RSN|WPA)\b/i) {
    $enc{lc $1} = 1;
}

if (/^\s*SSID:\s*(.*)$/i) {
    $data{essid} = $1;
}


if (/Authentication suites:\s*(.*)/) {
    my @suites = split / /, $1;
    for (@suites) {
        $auth{lc $_} = 1;
    }
}

END {
    end_item;
    print to_json(\@out, {pretty => 1}) . "\n";
}
