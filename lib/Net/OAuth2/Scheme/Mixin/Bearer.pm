use warnings;
use strict;

package Net::OAuth2::Scheme::Mixin::Bearer;
# ABSTRACT: implement bearer token schemes

use Net::OAuth2::Scheme::Option::Defines;


# Bearer tokens
#

# IMPLEMENTATION (transport_)bearer
#   (bearer_)scheme = 'Bearer';
#   (bearer_)scheme_re = '^Bearer$';
#   (bearer_)allow_body = 1;
#   (bearer_)allow_uri = 0;
#   (bearer_)param = 'oauth_token';
#   (bearer_)param_re = '^oauth_token$';
#   (bearer_)client_uses_param = 0;
# SUMMARY
#   Bearer token, handle-style


Default_Value bearer_scheme => 'Bearer';
Default_Value bearer_allow_body => 1;
Default_Value bearer_allow_uri => 0;
Default_Value bearer_param => 'oauth_token';
Default_Value bearer_client_uses_param => 0;

sub pkg_transport_bearer {
    my __PACKAGE__ $self = shift;
    $self->ensure(token_type => 'Bearer');
    my $scheme = $self->uses_param(transport_auth => \@_, 'scheme',
                                   $self->uses('bearer_scheme'));
    my $allow_body = $self->uses_param(bearer => \@_, 'allow_body');
    my $allow_uri = $self->uses_param(bearer => \@_, 'allow_uri');
    my $body_or_uri = 
      ($allow_body ? ($allow_uri ? 'dontcare' : 'body') : ($allow_uri ? 'query' : ''));
    my $param_name = $body_or_uri && $self->uses_param(bearer => \@_, 'param');

    if ($self->is_client) {
        $self->install( accept_needs => [] );
        $self->install( accept_hook => sub {} );
        if ($self->uses_param(bearer => \@_, 'client_uses_param')) {
            Carp::croak("bearer_client_no_header requires bearer_allow_(body|uri)")
                unless $body_or_uri;
            $self->http_parameter_inserter($body_or_uri, $param_name, sub { $_[0] });
        }
        else {
            $self->http_header_inserter(uses_params => \@_);
        }
    }

    if ($self->is_resource_server) {
        my $scheme_re = $self->uses_param(transport => \@_, scheme_re => qr(\A\Q$scheme\E\z)s);
        Carp::croak("bearer_scheme_re does not match bearer_scheme")
            if defined($scheme) && $scheme !~ $scheme_re;

        my $header_extractor = $self->http_header_extractor(uses_params => \@_);

        if ($body_or_uri) {
            my $param_re = $self->uses_param(bearer => \@_, param_re => qr(\A\Q$param_name\E\z)s);
            Carp::croak("bearer_param_re does not match bearer_param")
                if defined($param_name) && $param_name !~ $param_re;

            my $param_extractor = $self->http_parameter_extractor($body_or_uri, $param_re);
            $self->install( http_extract => sub {
                my ($plack_req) = @_;
                return ($header_extractor->($plack_req), $param_extractor->($plack_req));
            });
        }
        else {
            $self->install( http_extract => $header_extractor );
        }
    }
}

# IMPLEMENTATION (format_)bearer_handle
# SUMMARY
#   Bearer token, handle-style
# REQUIRES
#   v_id_next (v_id_is_random)
#   v_table_insert

sub pkg_format_bearer_handle {
    my __PACKAGE__ $self = shift;

    # yes, we can use this for authcodes and refresh tokens
    $self->install(format_no_params => 1);

    if ($self->is_auth_server) {
        # Enforce requirements on v_id_next.
        # Since, for this token format, v_ids are used directly,
        # they MUST NOT be predictable.
        $self->ensure(v_id_is_random => 1,
                      'bearer_handle tokens must use random identifiers');
        my ( $v_id_next, $vtable_insert, $token_type) = $self->uses_all
          (qw(v_id_next   vtable_insert   token_type));

        $self->install( token_create => sub {
            my ($now, $expires_in, @bindings) = @_;
            my $v_id = $v_id_next->();
            my $error = $vtable_insert->($v_id, $expires_in + $now, $now, @bindings);
            return ($error,
                    ($error ? () : 
                     (encode_base64url($v_id),
                      token_type => $token_type,
                     )));
        });
    }

    if ($self->is_resource_server) {
        # handle token has no @payload
        $self->install( token_parse => sub {
            return (decode_base64url($_[0]));
        });
        $self->install( token_finish => sub {
            my ($v) = @_;          # ($validator, @payload)
            return ('unrecognized')
              unless my ($expiration, $issuance, @bindings) = @$v;
            return (undef, $issuance, $expiration - $issuance, @bindings);
        });
    }
    return $self;
}


# IMPLEMENTATION format_bearer_signed FOR format
#   (bearer_signed_)hmac
#   (bearer_signed_)nonce_length  [=hmac length/2]
#   (bearer_signed_)fixed
# SUMMARY
#   Bearer token, signed-assertion-style
# REQUIRES
#   current_secret
#   random
#
# Access_token value contains a key identifying a shared secret
# (and possibly also the authserver and the resource), a set
# of values specifying expiration and scope, and a HMAC value to sign
# everything.  Only the shared secret needs to be separately
# communicated.

Default_Value bearer_signed_hmac => 'hmac_sha224';
Default_Value bearer_signed_fixed => [];

sub pkg_format_bearer_signed {
    my __PACKAGE__ $self = shift;
      
    # yes, we can use this for authcodes and refresh tokens
    $self->install(format_no_params => 1);

    if ($self->is_auth_server) {
        my $hmac = $self->uses_param(bearer_signed => \@_, 'hmac');
        my ($hlen,undef) = hmac_name_to_len_fn($hmac)
          or Carp::croak("unknown/unavailable hmac function: $hmac");
        my $nonce_len = $self->uses_param(bearer_signed => \@_, nonce_length => $hlen/2);

        $self->uses(current_secret_length => $hlen);
        $self->uses(current_secret_payload =>
                    $self->uses_param(bearer_signed => \@_, 'fixed'));

        my @secret = @{$self->uses('current_secret')};
        my $auto_rekey_check = $self->uses('current_secret_rekey_check');
        my $random = $self->uses('random');

        my $token_type = $self->uses('token_type');

        $self->install( token_create => sub {
            my ($now, $expires_in, @bindings) = @_;
            my ($error) = $auto_rekey_check->($now);
            return (rekey_failed => $error)
              if $error;

            my ($v_id, $v_secret, undef, @fixed) = @secret;
            for my $f (@fixed) {
                my $given = shift @bindings;
                return (fixed_parameter_mismatch => $f,$given)
                  if $f ne $given;
            }
            my $nonce = $random->($nonce_len);
            return (undef,
                    encode_base64url(pack 'w/aa*', $v_id,
                                     sign_binary($v_secret,
                                                 pack('w/aww(w/a)*', $nonce, $now, $expires_in, @bindings),
                                                 hmac => $hmac,
                                                 extra => $v_id)),
                    token_type => $token_type,
                   );
        });
    }
    if ($self->is_resource_server) {
        # On the resource side we cannot use 'current_secret'
        # since token may have been created with a previous secret,
        # so we just have to take whatever we get from the vtable
        $self->install( token_parse => sub {
            my ($token) = @_; # bearer token, no additional attributes
            my ($v_id, $bin) = unpack 'w/aa*', decode_base64url($token);
            return ($v_id, $v_id, $bin)
        });
        $self->install( token_finish => sub {
            my ($validator, $v_id, $bin) = @_;
            my (undef, undef, $v_secret, @fixed) = @$validator;
            my ($payload, $error) = unsign_binary($v_secret, $bin, $v_id);
            return ($error) if $error;
            my ($now, $expires_in, @bindings) = unpack 'w/xww(w/a)*', $payload;
            return (undef, $now, $expires_in, @fixed, @bindings);
        });
    }
    return $self;
}


1;

=pod

=head1 SYNOPSIS

=head1 DESCRIPTION

This implements two varieties of Bearer tokens.

