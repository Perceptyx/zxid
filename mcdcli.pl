#!/usr/bin/perl
# 20160422 Sampo Kellomaki (sampo@zxid.org)
#
# memcached client and test program
#
# Out of various perl modules available for memcached, it appears that only
# libmemcached based one supports the memcached binary protocol we desire
# See also: https://cloud.github.com/downloads/dustin/memcached/protocol-binary.txt

use Time::HiRes qw(time);
use Cache::Memcached::libmemcached;
# sudo cpan Cache::Memcached::libmemcached

$usage = <<USAGE;
Usage: mcdcli.pl server:port op key value
E.g:   mcdcli.pl 127.0.0.1:4442 set foo bar
E.g2:  mcdcli.pl 127.0.0.1:4442 get foo
USAGE
    ;

($server, $op, $key, $val) = @ARGV;

$mcd = Cache::Memcached::libmemcached->new({servers=>[$server], binary_protocol=>1});

if ($op eq 'get') {
    $v = $mcd->get($key);
    print $v;
} elsif ($op eq 'set') {
    if ($mcd->set($key,$val)) {
	warn "ok";
    } else {
	warn "err";
    }
} elsif ($op eq 'setget') {
    if ($mcd->set($key,$val)) {
	warn "ok";
    } else {
	warn "err";
    }
    $v = $mcd->get($key);
    print $v;
} elsif ($op eq 'test1') {
    if ($mcd->set($key,$val)) {
	warn "ok";
    } else {
	warn "err";
    }
    $n = 1_000_000;
    $start = time;
    for ($i = 0; $i <= $n; ++$i) {
	$v = $mcd->get($key);
    }
    $elapsed = time - $start;
    print $v;
    warn "Time for $n gets: $elapesd -- ".$n/$elapsed." gets/sec";
} else {
    die "Unknown op($op)\n$usage";
}

__END__

gdb ./zxcached -dd 0x03 -nfd 8 -npdu 4 -p mcdb:127.0.0.1:4442

20160423 ca. 20k gets/sec on single key single connection single thread
