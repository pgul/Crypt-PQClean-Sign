package Crypt::PQClean::Sign;

use strict;
use warnings;

our $VERSION = '0.01';

use Exporter qw(import);
our @EXPORT_OK = qw(
    falcon512_keypair
    falcon512_sign
    falcon512_verify
);

require XSLoader;
XSLoader::load('Crypt::PQClean::Sign', $VERSION);

1;
__END__

=head1 NAME

Crypt::PQCrypt::Sign - Post-Quantum Cryptography with keypair

=head1 SYNOPSIS

  use Crypt::PQCrypt::Sign qw(falcon512_keypair falcon512_sign falcon512_verify);

  # generate keypair
  ($pk, $sk) = falcon512_keypair();

  # sign message
  my $signature = falcon512_sign($message, $sk);

  # check signature
  my $valid = falcon512_verify($signature, $message, $pk);

=head1 DESCRIPTION

  Provides an interface to the PQClean falcon-512 implementation.

=head1 FUNCTIONS

=over

=item B<falcon512_keypair>

=item B<falcon512_sign>

=item B<falcon512_verify>

=back

=cut
