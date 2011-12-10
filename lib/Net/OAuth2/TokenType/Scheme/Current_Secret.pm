use warnings;
use strict;

package Net::OAuth2::TokenType::Scheme::Current_Secret;

use Net::OAuth2::TokenType::Option::Defines;


# INTERFACE current_secret
# DEFINES
#   current_secret => [v_id, secret, expiration, @secret_payload]
#   current_secret_rekey_check => now -> ; (generate new secret if necessary)
# SUMMARY
#   maintain a current secret for use by format_bearer_signed
#
Define_Group current_secret => 'simple',
  qw(current_secret current_secret_rekey_check);

Default_Value current_secret_rekey_interval => 86400*7; # 7 days
Default_Value current_secret_payload => [];

# IMPLEMENTATION current_secret_simple FOR current_secret
#   (current_secret_)rekey_interval
#   (current_secret_)length
#   (current_secret_)payload
# SUMMARY
#   secret lifetime = 2*rekey_interval;
#   change the secret whenever we are within rekey_interval of expiration;
#   prior secrets remain available from the cache until they expire
# REQUIRES
#   v_id_next
#   vtable_insert
#   random
#
# rekey_interval should be set to be at least as long as the
# longest anticipated lifetime for tokens generated using this secret
# as needed, there will generally be 2 secret keys active,
# and, for every token issued from a given key, the secret for it
# will remain available for at least rekey_interval seconds after issuance, so as long as
# is longer the token lifetime, the token will never be prematurely
# expired.
# Note that for reliable repudiation of secrets, you need to be using
# a shared-cache vtable
sub pkg_current_secret_simple {
    my __PACKAGE__ $self = shift;
    my ( $random, $vtable_insert) = $self->uses_all(
       qw(random   vtable_insert));

    my (  $rekey_interval, $length, $payload) =
      $self->uses_params(current_secret => \@_,
        qw(rekey_interval   length   payload));

    my @stashed = (undef, undef, 0, @$payload);

    $self->uses(v_id_kind => 'counter'); # preferred but not required
    my $v_id_next = $self->uses('v_id_next');

    $self->install( current_secret => \@stashed );
    $self->install( current_secret_rekey_check => sub {
        my ($now) = @_;
        my (undef, undef, $expiration) = @stashed;
        if ($expiration < $now + $rekey_interval) {
            my ($v_id, $new_secret, $new_expiration) = 
              @stashed = ($v_id_next->(), 
                          $random->($length), 
                          $now + 2 * $rekey_interval, 
                          @$payload);
            $vtable_insert->($v_id,
                             $new_expiration, $now, $new_secret,
                             @$payload);
        }
    });
    return $self;
}


1;

__END__

=head1 NAME

Net::OAuth2::TokenType::Scheme::Current_Secret

=head1 SYNOPSIS

=head1 DESCRIPTION

This manages a shared "current secret" as needed for signed-Bearer token format.

=head1 AUTHOR

Roger Crew (crew@cs.stanford.edu)

=head1 COPYRIGHT

This module is Copyright (c) 2011, Roger Crew.
All rights reserved.

You may distribute under the terms of either the GNU General Public
License or the Artistic License, as specified in the Perl README file.
If you need more liberal licensing terms, please contact the
maintainer.

=head1 WARRANTY

This is free software. IT COMES WITHOUT WARRANTY OF ANY KIND.
