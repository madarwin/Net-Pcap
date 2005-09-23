#!/usr/bin/perl -T
use strict;
use Socket;
use Test::More;
my $total;  # number of packets to process
BEGIN {
    $total = 10;
    my $proto = getprotobyname('icmp');

    if(socket(S, PF_INET, SOCK_RAW, $proto)) {
        close(S);
        plan tests => 5
    } else {
        plan skip_all => "must be run as root"
    }
}
use Net::Pcap;

eval "use Test::Exception"; my $has_test_exception = !$@;

my($dev,$pcap,$dumper,$dump_file,$err) = ('','','','');

# Find a device and open it
$dev = Net::Pcap::lookupdev(\$err);
$pcap = Net::Pcap::open_live($dev, 1024, 1, 0, \$err);

# Testing error messages
SKIP: {
    skip "Test::Exception not available", 2 unless $has_test_exception;

    # breakloop() errors
    throws_ok(sub {
        Net::Pcap::breakloop()
    }, '/^Usage: Net::Pcap::breakloop\(p\)/', 
       "calling breakloop() with no argument");

    throws_ok(sub {
        Net::Pcap::breakloop(undef)
    }, '/^p is not of type pcap_tPtr/', 
       "calling breakloop() with incorrect argument type");
}

# Testing stats()
my $user_text = "Net::Pcap test suite";
my $count = 0;

sub process_packet {
    my($user_data, $header, $packet) = @_;
    my %stats = ();

    if(++$count == $total/2) {
        eval { Net::Pcap::breakloop($pcap) };
        is( $@, '', "breakloop()" );
    }
}

my $r = Net::Pcap::loop($pcap, $total, \&process_packet, $user_text);
ok( ($r == -2 or $r == $count), "checking loop() return value" );
is( $count, $total/2, "half the packets processed" );

# Note: I'm not sure why $count is always $total/2 even when $r == -2
# Maybe I just don't understand what the docmentation says. 
# Or maybe I shouldn't write tests at 02:10 %-)

Net::Pcap::close($pcap);
