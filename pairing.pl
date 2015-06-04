#!/usr/bin/perl
# Copyright (c) 2015 Synergetics SA (sampo@synergetics.be), All Rights Reserved.
# This is confidential unpublished proprietary source code of the author.
# NO WARRANTY, not even implied warranties. Contains trade secrets.
# Distribution prohibited unless authorized in writing.
#
# 13.3.2010, created --Sampo
# 14.2.2014, perfected local login with IdP --Sampo
# 30.5.2015, adapted for use as pairing --Sampo
#
# Web GUI CGI for generating mobile pairing key.
#
# CGI / QUERY_STRING variables
#   c  $cmd    Command
#   d  $dir    Path to ZXID config directory, e.g: /var/zxid/ or /var/zxid/idp

#$cpath = '/d/ssoid/e2eta/ssoid.com/';
$cpath = '/d/ssoid/e2eta/';  # Rely on VURL and VPATH
$usage = <<USAGE;
Web GUI CGI for generating mobile pairing key
Usage: http://localhost:8081/idppairing.pl?QUERY_STRING
       ./idppairing.pl -a QUERY_STRING
         -a Ascii mode
USAGE
    ;
die $usage if $ARGV[0] =~ /^-[Hh?]/;

use Net::SAML;
use Data::Dumper;

close STDERR;
open STDERR, ">>/var/tmp/e2eta.stderr" or die "Cant open error log: $!";
select STDERR; $|=1; select STDOUT;

warn "$$: START env: " . Dumper(\%ENV);

$ENV{QUERY_STRING} ||= shift;
$qs = $ENV{QUERY_STRING};
cgidec($qs);

if ($ENV{CONTENT_LENGTH}) {
    sysread STDIN, $qs, $ENV{CONTENT_LENGTH};
    #warn "GOT($qs) $ENV{CONTENT_LENGTH}";
    cgidec($qs);
}

$qs = 'o=E' if !length($cgi{o}) && !length($qs);

$cf = Net::SAML::new_conf_to_cf("CPATH=$cpath&BARE_URL_ENTITYID=0&IDP_ENA=0");
$res = Net::SAML::simple_cf($cf, -1, $qs, undef, 0x3fff); # 0x1829
cgidec($res);
warn "res($res):".Dumper(\%cgi);

sub uridec {
    my ($val) = @_;
    $val =~ s/\+/ /g;
    $val =~ s/%([0-9A-Fa-f]{2})/chr(hex($1))/gsex;  # URI decode
    return $val;
}

sub urienc {
    my ($val) = @_;
    $val =~ s/([^A-Za-z0-9.,_-])/sprintf("%%%02x",ord($1))/gsex; # URI enc
    return $val;
}

sub cgidec {
    my ($d) = @_;
    for $nv (split '&', $d) {
	($n, $v) = split '=', $nv, 2;
	$cgi{$n} = uridec($v);
    }
}

sub readall {
    my ($f, $nofatal) = @_;
    my ($pkg, $srcfile, $line) = caller;
    undef $/;         # Read all in, without breaking on lines
    open F, "<$f" or do { if ($nofatal) { warn "$srcfile:$line: Cant read($f): $!"; return undef; } else { die "$srcfile:$line: Cant read($f): $!"; } };
    binmode F;
    my $x = <F>;
    close F;
    return $x;
}

sub show_templ {
    my ($templ, $hr) = @_;
    $templ = readall($templ);
    $templ =~ s/!!(\w+)/$$hr{$1}/gs;
    my $len = length $templ;
    syswrite STDOUT, "Content-Type: text/html\r\nContent-Length: $len$setcookie\r\n\r\n$templ";
    exit;
}

# Since we share the session with the real IdP, we can fish out the original IdP uid from there.
$sespath = "$cgi{'sespath'}/.ses";
$sesobj = readall($path);
$uid = (split /\|/, $sesobj)[4];  # Fifth pipey separated field is the IdP side uid

for ($iter = 50; $iter; --$iter) {  # Try again until successful
    open R, "</dev/urandom" or die "Cant open read /dev/urandom: $!";
    sysread R, $pw, 3;  # 3 bytes, each used for two digits for total 6 digit pairing code
    close R;
    $cgi{PCODE} = sprintf("%02d%02d%02d", ord(substr($pw,0,1))%100, ord(substr($pw,1,1))%100, ord(substr($pw,2,1))%100);

    ($pcode_path = $sespath) =~ s%/ses/[A-Za-z0-9_=-]+/.ses$%/pcode/$cgi{PCODE}%;
    next if -e $pcode_path;  # This PCODE has already been issued (and not consumed)
    open P, ">$pcode_path" or die "Cant open write $pcode_path: $!";
    printf P "%d %s", time()+180, $uid;
    close P;

    ## Store the pairing key under user's directory so that IdP authentication function can see it.
    #$path =~ s%/ses/[A-Za-z0-9_=-]+/.ses$%/uid/$uid/.pairing%;
    #warn "sesobj($sesobj) uid($uid) path($path)";
    #open P, ">$path" or die "Cant open write $path: $!";
    #printf P "%d %s", time()+180, $cgi{PAIRING};
    #close P;
}
show_templ("pairing.html", \%cgi);

__END__
