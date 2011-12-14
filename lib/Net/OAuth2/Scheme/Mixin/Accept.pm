use strict;
use warnings;

package Net::OAuth2::Scheme::Mixin::Accept;
# ABSTRACT: defines 'token_accept'

use Net::OAuth2::Scheme::Option::Defines;

# FUNCTION token_accept
#   token[, issue_attributes] -> error, token[, save_attributes]
# SUMMARY
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
    $self->parameter_prefix(accept_ => @_);

    # these two cases are probably not necessary.  In fact, now that I
    # think about it 'token_accept' for refresh tokens and authcodes
    # should be completely inaccessible to clients, but maybe I'll
    # change my mind about this...

    if ($self->uses('usage') eq 'authcode') {
        # authcode is the token string ONLY
        $self->install( token_accept => sub { return $_[0]; } );
        return $self;
    }

    # ditto...
    if ($self->uses('usage') eq 'refresh') {
        # refresh is the token string ONLY
        $self->install( token_accept => sub {
            my ($token, %params) = @_;
            $token = $params{refresh_token} if  $params{refresh_token};
            return $token;
        });
        return $self;
    }

    # now for the real stuff
    my ($token_type, $remove, $keep, $needs, $hook) = $self->uses_all
      (qw(token_type accept_remove accept_keep accept_needs accept_hook));

    $self->install( token_accept => sub {
        my ($token, %params) = @_;
        return ('wrong_token_type')
          if (lc($params{token_type}) ne lc($token_type));
        my ($error) = $hook->(\%params);
        return ($error) if $error;

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

=pod

=head1 SYNOPSIS

=head1 DESCRIPTION

This implements the default B<token_accept> client token method.

