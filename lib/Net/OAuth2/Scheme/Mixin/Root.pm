use warnings;
use strict;

package Net::OAuth2::TokenType::Scheme::Root;
# ABSTRACT: defines the root group setup

use Net::OAuth2::TokenType::Option::Defines;

Define_Group(root => 'setup');

my %defined_usage = map {$_,1} qw(
  access
  refresh
  authcode
);

my %defined_context = map {$_,1} qw(
  client
  auth_server
  resource_server
);

# sub is_client
# sub is_auth_server
# sub is_resource_server
{
    no strict 'refs';
    for my $whatever (keys %defined_context) {
        ${"is_${whatever}::"}{CODE} = sub {
            # assume not if we have not otherwise said so.
            return $_[0]->uses("is_$whatever", 0);
        };
    }
}

sub pkg_root_setup {
    my __PACKAGE__ $self = shift;

    my $usage = $self->uses(usage => 'access');
    die "unknown token kind: $usage"
      unless $defined_usage{$usage};

    my $context = $self->uses(context => ($usage ne 'access' ? () : ([])));
    for my $c (ref($context) ? @$context : ($context)) {
        die "unknown context: $c" unless $defined_context{$c};
        $self->ensure("is_$c", 1);
    }
    if ($usage ne 'access') {
        $self->ensure(format_no_params => 1);
        $self->ensure(is_client => 0, 'client implementations do not need refresh/authcode types'); 
        $self->ensure(is_auth_server => 1);
        $self->ensure(is_resource_server => 1);
    }
    $self->install(top => 'done');

    $self->export
      (
       ($self->is_client 
        ? ('token_accept',
           ($usage eq 'access' ? ('http_insert') :()),
          ) : ()),
       ($self->is_resource_server
        ? ('token_validate',
           ($usage eq 'access' ? ('http_extract') :()),
          ) : ()),
       ($self->is_auth_server
        ? ('token_create') : ()),
      );
    return $self;
}

1;

=pod

=head1 SYNOPSIS

=head1 DESCRIPTION

This defines implementation contexts.

