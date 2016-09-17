#!/bin/perl
# 20091124, Sampo Kellomaki (sampo@iki.fi)
# 20150324, updated to latest release of ykpersonalize --Sampo
#
# Program Yubikeys
#
# Usage: ./ykissue.pl fixed    start    end
# Usage: ./ykissue.pl ukulelej 00059100 00059196
#
# N.B. The fixed part MUST be even number for characters, because in reality it is hex.
#
# See also: ~/me/ykissue  -- log file of yk issuance operations, instructions for compiling ykpersonalize
#
# ModHex: cbdefghijklnrtuv
# Hex:    0123456789abcdef


($fixed, $start, $end, $norom) = @ARGV;

open RND, "</dev/random" or die "Cant open /dev/random: $!";
warn "norom($norom)";

#        0  1   2    3     4    5   6    7     8      9
@un  = ('','i','ii','iii','iv','v','vi','vii','viii','ik');
@dec = ('','k','kk','kkk','kl','l','lk','lkk','lkkk','kc');
@cen = ('','c','cc','ccc','cr','r','rc','rcc','rccc','cn');

sub rom {  # roman numeral generation
    my ($x) = @_;
    my @c = reverse split '', $x;
    my ($r);
    #my $r = $un[$c[0]];
    my $r = $dec[$c[1]] . $un[$c[0]];
    #warn "x($x) rom($r) dec($dec[$c[1]]) un($un[$c[0]]) c1($c[1]) c0($c[0])";
    return $r;
}

for $i ($start..$end) {
    unless ($norom) {
	$rom = rom($i);
	$rom .= 'j' if length($rom) & 0x01;
    }
    $prefix = $fixed.$rom;
    warn "\n### ($i, $prefix) Remove previous yubikey, insert new yubikey and hit ENTER to program...\n";
    $_ = <STDIN>;
    sysread RND, $rnd, 16;
    $rnd =~ s/(.)/sprintf "%02x", ord($1)/ges;
    #$cmd = sprintf "/apps/bin/ykpersonalize -y -v -ofixed=$prefix -ouid=%012x -a$rnd >/tmp/ykdebug.out", $i;
    $cmd = sprintf "LD_LIBRARY_PATH=/apps/yk/1.16.4/lib /apps/yk/1.16.4/bin/ykpersonalize -1 -y -v -ofixed=$prefix -ouid=%012x -a$rnd >/tmp/ykdebug.out", $i;
    warn "system($cmd)\n";
    system($cmd);
    #       yk#       extuid    intuid   aes128key                  who
    printf "%08d %-16s %012x %32s\n", $i, $fixed.$rom, $i, $rnd;

    warn "\n### Press yubikey to verify...";
    $_ = <STDIN>;
    chomp;
    system("LD_LIBRARY_PATH=/apps/lib /apps/bin/ykdebug $rnd $_ >/tmp/ykdebug.out");
    open F, "</tmp/ykdebug.out" or warn "Trouble opening: $!";
    @f = <F>;
    close F;
    $f = join '', @f;
    print STDERR $f;
    $f=~/ignoring prefix: ([a-z]+)/;
    warn "###### Programming error: prefix($prefix) gotprefix($1)" if $1 ne $prefix;
    $f=~/crc check: ([a-z]+)/;
    warn "###### Programming error: bad CRC($1)" if $1 ne 'ok';
}

#EOF
