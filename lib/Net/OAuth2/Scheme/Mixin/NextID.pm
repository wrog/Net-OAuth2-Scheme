use warnings;
use strict;

package Net::OAuth2::Scheme::Mixin::NextID;
# ABSTRACT: the 'v_id_next', 'counter', and 'random' option groups

use Net::OAuth2::Scheme::Option::Defines;

# INTERFACE v_id_next
# DEFINES
#   v_id_next v_id_is_random

Define_Group v_id_next => 'default',
  qw(v_id_next v_id_is_random);

Default_Value v_id_random_length => 12;
Default_Value v_id_suffix => '';

# REQUIRES
#   v_id_kind
# (v_id_kind == 'random')
#   random
# (v_id_kind == 'counter')
#   counter
# OPTIONS
#   v_id_suffix
#   v_id_random_length   (v_id_kind == 'random')

sub pkg_v_id_next_default {
    my __PACKAGE__ $self = shift;
    my ($kind, $suffix) = 
      $self->uses_params(v_id => \@_, qw(kind suffix));
    ($kind, my @kvs) = @$kind if ref($kind) eq 'ARRAY';

    my $next_id;
    if ($kind eq 'random') {
        my $random = $self->uses('random');
        my $length = $self->uses_param(v_id_random => \@kvs, 'length');

        Carp::croak("v_id_length must be at least 8")
            unless $length >= 8;
        Carp::croak("v_id_length must be no more than 127")
            unless $length <= 127;
        $next_id = sub { pack 'Ca*a*', 128+$length, $random->($length), $suffix };
        $self->install('v_id_is_random', 1);
    }
    elsif ($kind eq 'counter') {
        my $counter = $self->uses('counter');
        $next_id = sub { pack 'a*a*', $counter->next(), $suffix };
        $self->install('v_id_is_random', 0);
    }
    else {
        Carp::croak("unknown v_id_kind: $kind");
    }
    $self->install( v_id_next => $next_id );
}


# INTERFACE counter
# SUMMARY
#   generate a sequence of bytes different from every previous sequence produced
#   and from every other possible sequence that can be produced from this same code
#   running in any other process or thread.
# DEFINES
#   counter  object with a 'next' method () -> string of bytes

Define_Group counter => 'default';

Default_Value counter_tag => '';

sub pkg_counter_default {
    my __PACKAGE__ $self = shift;    
    my $tag = $self->uses('counter_tag');
    $self->install('counter', Net::OAuth2::Server::Counter->new($tag));
}


# INTERFACE random
# SUMMARY
#   generate random bytes in a cryptographically secure mannter
# DEFINES
#   random  (n)-> string of n random octets

# default implementation
Define_Group  random => 'isaac';

# If you can find a better one, go for it.
sub pkg_random_isaac {
    my __PACKAGE__ $self = shift;
    my $rng = Net::OAuth2::Server::Random->new('Math::Random::ISAAC');
    $self->install( random => sub { $rng->bytes(@_) });
}

1;

=pod

=head1 SYNOPSIS

=head1 DESCRIPTION

This handles ID generation for use as VTable keys.

