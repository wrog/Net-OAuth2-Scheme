use strict;
use warnings;

package Net::OAuth2::TokenType::Scheme::Format;

use Net::OAuth2::TokenType::Option::Defines;

Define_Group token_validate => 'default';

Define_Group format => undef,
  qw(token_create
     token_parse
     token_finish
     format_no_params
   );

# FUNCTION token_validate
#   token[, send_attributes] -> invalid?[, issued, expires_in, bindings...]
# SUMMARY
#   validate a token
#   token[,attributes] are from http_extract or a refresh request


# default implementation
# REQUIRES
#  token_parse vtable_lookup token_finish
sub pkg_token_validate_default {
    my __PACKAGE__ $self = shift;
    my (       $parse,     $finish,    $v_lookup) = $self->uses_all
      (qw(token_parse token_finish vtable_lookup));

    $self->install( token_validate => sub {

        my ($v_id, @payload) = $parse->(@_);
        my ($error, @validator) = $v_lookup->($v_id);

        return ($error, @validator) if $error;
        return ('not_found') unless @validator;

        return $finish->(\@validator, @payload);
    });
    return $self;
}


1;

__END__

=head1 NAME

Net::OAuth2::TokenType::Scheme::Format

=head1 SYNOPSIS

=head1 DESCRIPTION

This creates a framework for specifying token formats.

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
