#!/usr/bin/perl
# Copyright (c) 2012-2015 Synergetics NV (sampo@synergetics.be), All Rights Reserved.
# Copyright (c) 2010 Sampo Kellomaki (sampo@iki.fi), All Rights Reserved.
# This is confidential unpublished proprietary source code of the author.
# NO WARRANTY, not even implied warranties. Contains trade secrets.
# Distribution prohibited unless authorized in writing.
# $Id$
#
# 8.3.2010, created --Sampo
# 5.2.2012, changed zxpasswd to use -n instead of -c --Sampo
# 9.2.2014, changed to use zxpasswd -new
# 3.6.2015, added appcode and SSO after provisioning support --Sampo
#
# See also: https://dev.synersec.eu:8443/protected/mediawiki/index.php/E2ETA_Identity_Provider_(IdP)#SSO_after_provisioning_hack
#
# Web GUI for creating new user, possibly in middle of login sequence.
# The AuthnRequest is preserved through new user creation by passing ar.

$from = 'sampo-synnewuser-noreply@zxid.org';
$admin_mail = 'sampo-synnewuser@zxid.org';
$dir = '/home/sampo/sidemo/zxid/idp.i-dent.eu/';
$appeid = 'https://sp.citizendata.eu:8445/protected/saml?o=B';
$appkey = 'foobar123ABC';  # appkey agreed between the IdP and the SP
$url_after_sso = '/provis-sso-ok.html'; # where user is redirected after provisioning and SSO
$idpeid = 'https://idp.i-dent.eu/synidp';
#$idpeid = 'https://ssoid.com/idp';

$usage = <<USAGE;
Web GUI for creating new user, possibly in middle of login sequence.
Usage: http://localhost:8081/synnewuser.pl?QUERY_STRING
       ./synnewuser.pl -a QUERY_STRING
         -a Ascii mode
         -t Test mode
USAGE
    ;
die $usage if $ARGV[0] =~ /^-[Hh?]/;
if ($ARGV[0] eq '-t') {
    warn "Sending...";
    send_detail("Test $$");
    exit;
}

use Data::Dumper;
use MIME::Base64;
sub decode_safe_base64 { my ($x) = @_; $x=~tr[-_][+/]; return decode_base64 $x; }
sub encode_safe_base64 { my ($x) = @_; $x = encode_base64 $x, ''; $x=~tr[+/][-_]; return $x; }
use Net::SAML;
use Digest::SHA;

close STDERR;
open STDERR, ">>/var/tmp/zxid.stderr" or die "Cant open error log: $!";
select STDERR; $|=1; select STDOUT;

($sec,$min,$hour,$mday,$mon,$year) = gmtime(time);
$ts = sprintf "%04d%02d%02d-%02d%02d%02d", $year+1900, $mon+1, $mday, $hour, $min, $sec;
#warn "$$: START env: " . Dumper(\%ENV);

$ENV{QUERY_STRING} ||= shift;
cgidec($ENV{QUERY_STRING});

if ($ENV{CONTENT_LENGTH}) {
    sysread STDIN, $data, $ENV{CONTENT_LENGTH};
    #warn "GOT($data) $ENV{CONTENT_LENGTH}";
    cgidec($data);
}
warn "$$: cgi: " . Dumper(\%cgi);

sub uridec {
    my ($val) = @_;
    $val =~ s/\+/ /g;
    $val =~ s/%([0-9a-f]{2})/chr(hex($1))/gsexi;  # URI decode
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
    my ($f) = @_;
    my ($pkg, $srcfile, $line) = caller;
    undef $/;         # Read all in, without breaking on lines
    open F, "<$f" or die "$srcfile:$line: Cant read($f): $!";
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
    syswrite STDOUT, "Content-Type: text/html\r\nContent-Length: $len\r\n\r\n$templ";
    exit;
}

sub redirect {
    my ($url) = @_;
    syswrite STDOUT, "Location: $url\r\n\r\n";
    exit;
}

sub send_mail {
    my ($to, $subj, $body) = @_;
    open S, "|/usr/sbin/sendmail -i -B 8BITMIME -t" or die "No sendmail in path: $! $?";
    $msg = <<MAIL;
From: $from
To: $to
Subject: $subj
MIME-Version: 1.0
Content-Type: text/plain; charset=ISO-8859-1
Content-Transfer-Encoding: 8bit

$body
MAIL
;
    warn "msr($msg)";
    print S $msg;
    close S;
}

sub send_detail {
    my ($subj) = @_;
    send_mail($admin_mail, $subj, <<BODY);
cn: $cgi{'au'}
uid: $cgi{'au'}
ip: $ENV{REMOTE_ADDR}
email: $cgi{'email'}

Comments or special requests:
$cgi{'comment'}
BODY
    ;
}

sub gen_username {
    my ($cn) = @_;
    my ($first) = split /\w+/, $cn;
    $first =~ tr[A-Za-z0-9_-][_]cs;
    for ($i = 1; $i < 1000; ++$i) {  # Keep trying but reasonably avoid infinite loop
	return "$first$i" unless -e "${dir}uid/$first$i";
    }
    # Short form username did not workout in forst 1000 tries. Probably a popular first
    # name. Lets take the full cn to help generate some uniqueness.
    $cn =~ tr[A-Za-z0-9_-][_]cs;
    for ($i = 1; $i < 1000000; ++$i) {  # Keep trying but reasonably avoid infinite loop
	return "$cn$i" unless -e "${dir}uid/$cn$i";
    }
    die "gen_username($cn) not successful in million tries";
}

sub gen_password {
    open R, "</dev/urandom" or die "Cant open read /dev/urandom: $!";
    sysread R, $pw, 9;
    close R;
    return encode_safe_base64($pw,'');
}

sub gen_app_code {
    my ($secs) = @_;
    return encode_safe_base64(SHA1("$secs$appkey"));
}

### Post processing

if (length $cgi{'continue'}) {
    if ($cgi{'idpurl'} && $cgi{'rfr'} && $cgi{'ar'}) {
	warn "Redirecting back to IdP";
	redirect("$cgi{'idpurl'}?o=$cgi{'rfr'}&ar=$cgi{'ar'}");
    } elsif ($cgi{'ssoena'}) {
	$cf = Net::SAML::new_conf_to_cf("NON_STANDARD_ENTITYID=$cgi{'appeid'}&AUTHN_REQ_SIGN=0");
	$cgi = Net::SAML::new_cgi($cf, "rs=$cgi{'rs'}&eid=$cgi{'eid'}");
	$an_req = Net::SAML::start_sso_url($cf, $cgi);
	warn "an_req($an_req)";
	redirect($an_req);
    } else {
	warn "Redirecting back to index page.";
	redirect("/");
    }
}

### MAIN

if (length $cgi{'ok'}) {
    if (length($appkey)
	&& (($cgi{'appcode'} ne gen_app_code())
	    || ($cgi{'appsecs'} > time()+4000)      # forward slop 1h in case of time zone screwup
	    || ($cgi{'appsecs'} < time()-8000))) {  # backward slop 2h to fill the form in
	die "Bad appcode($cgi{'appcode'}) appsecs($cgi{'appsecs'}) time=".time();
    }
    if (length $cgi{'cn'} < 3 || length $cgi{'cn'} > 80) {
	$cgi{'ERR'} = "Common name must be at least 3 characters long (and no longer than 80 chars).";
	render_form();
	exit;
    }
    if (!length $cgi{'au'}) {
	$cgi{'au'} = gen_username($cgi{'cn'});
    }
    if (!length $cgi{'ap'}) {
	$cgi{'ap'} = gen_password();
    }
    if (length $cgi{'au'} < 3 || length $cgi{'au'} > 40) {
	$cgi{'ERR'} = "Username must be at least 3 characters long (and no longer than 40 chars).";
    } elsif ($cgi{'au'} !~ /^[A-Za-z0-9_-]+$/s) {
	$cgi{'ERR'} = "Username can only contain characters [A-Za-z0-9_-]";
    } elsif (length $cgi{'ap'} < 5 || length $cgi{'ap'} > 80) {
	$cgi{'ERR'} = "Password must be at least 5 characters long (and no longer than 80 chars).";
    } elsif (-e "${dir}uid/$cgi{'au'}") {
	$cgi{'ERR'} = "Username already taken.";
    } else {
	warn "Creating new user($cgi{'au'})";
	open P, "|./zxpasswd -new $cgi{'au'} ${dir}uid" or die "Cant open pipe to zxpasswd: $! $?";
	print P $cgi{'ap'};
	close P;
	warn "Populating user($cgi{'au'})";
	if (-e "${dir}uid/$cgi{'au'}") {
	    open LOG, ">${dir}uid/$cgi{'au'}/.log" or die "Cant open write .log: $!";
	    print LOG "$ts Created $cgi{'au'} ip=$ENV{REMOTE_ADDR}\n" or die "Cant write .log: $!";
	    close LOG or die "Cant close write .log: $!";

	    open IP, ">${dir}uid/$cgi{'au'}/.regip" or die "Cant open write .regip: $!";
	    print IP $ENV{REMOTE_ADDR} or die "Cant write .regip: $!";
	    close IP or die "Cant close write .regip: $!";

	    if ($cgi{'humanintervention'} > 0) {
		open HUMAN, ">${dir}uid/$cgi{'au'}/.human" or die "Cant open write .human: $!";
		print HUMAN $cgi{'humanintervention'} or die "Cant write .human: $!";
		close HUMAN or die "Cant close write .human: $!";
	    }
	    #mkdir "${dir}uid/$cgi{'au'}/.bs" or warn "Cant mkdir .bs: $!"; zxpasswd creates .bs
	    open AT, ">${dir}uid/$cgi{'au'}/.bs/.at" or die "Cant write .bs/.at: $!";
	    open OPTAT, ">${dir}uid/$cgi{'au'}/.bs/.optat" or die "Cant write .bs/.optat: $!";
	    $essential_at_list = "cn email lang";
	    for $at (qw($essential_at_list)) {
		$val = $cgi{$at};
		$val =~ s/[\r\n]//g;
		next if !length $val;
		if ($cgi{"${at}share"}) {
		    print AT "$at: $val\n";
		} else {
		    print OPTAT "$at: $val\n";
		}
	    }
	    
	    close AT;
	    close OPTAT;
	    
	    send_detail("New User $cgi{'au'}");

            if ($cgi{'idpurl'} && $cgi{'rfr'} && $cgi{'ar'}) {
		warn "Created user($cgi{'au'})";
		$cgi{MSG} = "Success! Created user $cgi{'au'}. Click Continue to get back to IdP login.";
		show_templ("synnewuser-status.html", \%cgi);
	    } elsif ($cgi{'ssoena'}) {
		warn "Created user($cgi{'au'})";
		$cgi{MSG} = "Success! Created user <b>$cgi{'au'}</b>, password <b>$cgi{'pw'}</b>. Make note of these login credentials. Click Continue to get back to application.";
		show_templ("synnewuser-status.html", \%cgi);
            } else {
		warn "Created user($cgi{'au'})";
		$cgi{MSG} = "Success! Created user $cgi{'au'}. Click Continue to get back to top.";
		show_templ("synnewuser-status.html", \%cgi);
            }
	} else {
	    $cgi{'ERR'} = "User creation failed. System error (${dir}uid/$cgi{'au'}).";
	}
    }
}

render_form();

sub render_form {
    $cgi{'humaninterventionchecked'} = $cgi{'humanintervention'} eq '1' ? ' checked':'';
    $cgi{'ip'} = $ENV{REMOTE_ADDR};
    $cgi{'rs'} = $url_after_sso;
    $cgi{'eid'} = $idpeid;
    $cgi{'appeid'} = $appeid;
    $cgi{'appsecs'} = time();
    $cgi{'appcode'} = gen_app_code($cgi{'appsecs'});
    if (!length $cgi{'ap'}) {
	$cgi{'ap'} = gen_password();  # Just a suggestion
    }
    show_templ("synnewuser-main.html", \%cgi);
}

__END__
