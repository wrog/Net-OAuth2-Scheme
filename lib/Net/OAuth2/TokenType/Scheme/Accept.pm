use strict;
use warnings;

package Net::OAuth2::TokenType::Scheme::Accept;

use Net::OAuth2::TokenType::Option::Defines;

# FUNCTION token_accept
#   token[, issue_attributes] -> token[, send_attributes]
# SUMMARY
#   in the vast majority of cases
#   issue_attributes and send_attributes are the same
# IMPLEMENTATION token_accept_default
#   (accept_)token_type_re = ''
#   (accept_)remove = [qw(expires_in scope refresh_token)]
#   (accept_)keep = [...] or 'everything'
# REQUIRES
#   accept_needs
#   accept_hook

Define_Group token_accept => 'default';

Default_Value accept_remove => [qw(expires_in scope refresh_token)];
Default_Value accept_keep => 'everything';

sub pkg_token_accept_default {
    my __PACKAGE__ $self = shift;
    my ($remove, $keep, $needs, $hook) = $self->uses_params
      ('accept' => \@_, qw(remove keep needs hook));
    my $token_type = $self->uses('token_type');
    $self->install( token_accept => sub {
        my ($token, %params) = @_;
        return ('wrong_token_type',%params) 
          if (lc($params{token_type}) ne lc($token_type));
        $hook->(\%params);

        my @missing = ();
        my %save = map {
            my $v = $params{$_};
            push @missing,$_ if !defined($v) || !length($v);
            ($_,$v)
        } @$needs;
        return ("missing_$missing[0]") if @missing;

        if (ref $keep) {
            %params = map {$save{$_}? (): ($_,$params{$_})} @$keep;
        }
        else {
            delete @{params}{@$remove,@$needs};
        }
        return (undef, $token, %params, %save);
    });
    return $self;
}





1;

__END__

=head1 NAME

Net::OAuth2::TokenType::Scheme::Accept

=head1 SYNOPSIS

=head1 DESCRIPTION

This implements the default B<token_accept> client token method.

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
