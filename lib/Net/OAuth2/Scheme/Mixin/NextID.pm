use warnings;
use strict;

package Net::OAuth2::Scheme::Mixin::NextID;
# ABSTRACT: the 'v_id_next', 'counter', and 'random' option groups

use Net::OAuth2::Scheme::Option::Defines;
use Net::OAuth2::Scheme::Counter;

# INTERFACE v_id_next
# DEFINES
#   v_id_next v_id_is_random

Define_Group v_id_next => 'default',
  qw(v_id_next v_id_is_random v_id_get_suffix);

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
    $self->parameter_prefix(v_id_ => @_);
    my $kind = $self->uses('v_id_kind');
    ($kind, my @kvs) = @$kind if ref($kind) eq 'ARRAY';
    if ($kind eq 'random') {
        $self->parameter_prefix(v_id_random_ => @kvs);
        if ($self->is_resource) {
            $self->install(v_id_get_suffix => sub {
                my $value = shift;
                return (unpack 'w/aa*',$value)[1];
            });
        }
        if ($self->is_auth_server) {
            require Net::OAuth2::Scheme::Random;
            my $random = $self->uses('random');
            my $length = $self->uses('v_id_random_length');
            my $suffix = $self->uses('v_id_suffix');

            $self->croak("v_id_length must be at least 8")
              unless $length >= 8;
            $self->croak("v_id_length must be no more than 127")
              unless $length <= 127;
            $self->install(v_id_is_random => 1);
            $self->install(v_id_next => sub {
                return pack 'Ca*a*', 128+$length, $random->($length), $suffix;
            });
        }
    }
    elsif ($kind eq 'counter') {
        $self->parameter_prefix(v_id_counter_ => @kvs);
        $self->make_alias(v_id_counter_tag => 'counter_tag');
        if ($self->is_resource) {
            $self->install(v_id_get_suffix => $self->uses('counter_get_suffix'));
        }
        if ($self->is_auth_server) {
            my $counter = $self->uses('counter');
            my $suffix = $self->uses('v_id_suffix');
            $self->install(v_id_is_random => 0);
            $self->install(v_id_next => sub {
                return $counter->next() . $suffix;
            });
        }
    }
    else {
        $self->croak("unknown v_id_kind: $kind");
    }
}


# INTERFACE counter
# SUMMARY
#   generate a sequence of bytes different from every previous sequence produced
#   and from every other possible sequence that can be produced from this same code
#   running in any other process or thread.
# DEFINES
#   counter  object with a 'next' method () -> string of bytes

Define_Group counter_set => 'default', qw(counter counter_get_suffix);

Default_Value counter_tag => '';

sub pkg_counter_set_default {
    my __PACKAGE__ $self = shift;    
    if ($self->is_auth_server) {
        my $tag = $self->uses('counter_tag');
        $self->install('counter', Net::OAuth2::Scheme::Counter->new($tag));
    }
    if ($self->is_resource_server) {
        $self->install('counter_get_suffix', \&Net::OAuth2::Scheme::Counter::suffix);
    }
}


# INTERFACE random
# SUMMARY
#   generate random bytes in a cryptographically secure mannter
# DEFINES
#   random  (n)-> string of n random octets

# default implementation
Default_Value  random_class => 'Math::Random::MT::Auto';

Define_Group  random_set => 'default', qw(random);

# If you can find a better one, go for it.
sub pkg_random_set_default {
    my __PACKAGE__ $self = shift;
    my $rng = Net::OAuth2::Server::Random->new($self->uses('random_class'));
    $self->install( random => sub { $rng->bytes(@_) });
}

1;

=pod

=head1 SYNOPSIS

=head1 DESCRIPTION

This handles ID generation for use as VTable keys.

