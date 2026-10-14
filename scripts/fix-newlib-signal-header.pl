#!/usr/bin/env perl
use strict;
use warnings;
use File::Temp qw(tempfile);
use File::Basename qw(dirname);

@ARGV == 1 or die "usage: fix-newlib-signal-header.pl <SDK sys/signal.h>\n";
my ($path) = @ARGV;
open my $input, '<', $path or die "cannot read $path: $!\n";
my $text = do { local $/; <$input> };
my $before = $text;
close $input or die "cannot close $path: $!\n";
my $original = '#if !defined(__CYGWIN__) && !defined(__rtems__)';
my $corrected = "$original && !defined(__mochios__)";
# The upstream macros use bit signo, while its checked sigset functions and
# mochiOS use bit signo-1. Select the real functions for this target only.
my $count = ($text =~ s/^\Q$original\E$/$corrected/mg);
if (!$count) {
    die "unsupported newlib signal header: macro guard missing in $path\n"
        unless $text =~ /^\Q$corrected\E$/m;
}
$count <= 1 or die "ambiguous newlib signal macro guards in $path\n";
unless ($text =~ /#include <sys\/_mochios_siginfo\.h>/) {
    my $legacy = qr/typedef struct \{\n  int\s+si_signo;[^}]+\} siginfo_t;/;
    my $replaced = ($text =~ s/($legacy)/#if defined(__mochios__)\n#include <sys\/_mochios_siginfo.h>\n#else\n$1\n#endif/s);
    $replaced == 1 or die "unsupported newlib siginfo declaration in $path\n";
}
unless ($text =~ /^#define SA_RESTART 0x10000000$/m) {
    $text .= "\n/* mochiOS userspace signal restart policy. */\n" .
        "#if defined(__mochios__) && !defined(SA_RESTART)\n" .
        "#define SA_RESTART 0x10000000\n#endif\n";
}
unless ($text =~ /^#define SA_NOCLDWAIT 0x2$/m) {
    $text .= "\n/* mochiOS userspace child-status retention policy. */\n" .
        "#if defined(__mochios__) && !defined(SA_NOCLDWAIT)\n" .
        "#define SA_NOCLDWAIT 0x2\n#endif\n";
}
exit 0 if $text eq $before;
my ($output, $temporary) = tempfile('.signal-header-XXXXXX', DIR => dirname($path), UNLINK => 1);
print {$output} $text or die "cannot write $temporary: $!\n";
close $output or die "cannot close $temporary: $!\n";
chmod 0644, $temporary or die "cannot set permissions on $temporary: $!\n";
rename $temporary, $path or die "cannot replace $path: $!\n";
