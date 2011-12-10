use warnings;
use strict;

package Net::OAuth2::TokenType::Scheme::HMac;

use Net::OAuth2::TokenType::Option::Defines;

# HMAC token

# IMPLEMENTATION (transport_)http_hmac
#   (http_hmac_)nonce_length = 8
#   (http_hmac_)ext_body  ($request, 'server'|'client') -> ext
# SUMMARY
#   http_hmac token
# REQUIRES
#   random

Default_Value http_hmac_scheme => 'MAC';
Default_Value http_hmac_nonce_length => 8;
Default_Value http_hmac_ext_body => sub {''};

sub pkg_transport_http_hmac {
    my __PACKAGE__ $self = shift;
    $self->ensure(token_type => 'mac');
    my $scheme = $self->uses_param(transport_auth => \@_, 'scheme',
                                   $self->uses('http_hmac_scheme'));

    my $http_hmac_ext_body = $self->uses_param(http_hmac => \@_, 'ext_body');
    if ($self->is_resource_server) {
        $self->install( http_extract =>
            $self->http_header_extractor
              (uses_params => \@_,
               parse_auth => sub {
                   my ($auth, $req) = @_;
                   return () unless $auth =~ m{\AMAC\s+}gs;
                   my $astring = $1;
                   my %attr = ();
                   while ($auth =~ m{\G([^=[:space:]]+)\s*=\s*"([^"]*)"\s+}gs) {
                       $attr{$1} = $2;
                   }
                   return () if grep {!defined} (my ($id, $nonce, $mac) = @attr{qw(id nonce mac)});
                   my $ext = defined($attr{ext}) ? $attr{ext} : '';
                   return ($id, $mac, $nonce, $req->method, $req->uri, $req->host, $req->port,
                           $ext, $http_hmac_ext_body->($req, 'server'));
               }));
    }
    if ($self->is_client) {
        my $random = $self->uses('random');
        my $nonce_length = $self->uses_param(http_hmac => \@_, 'nonce_length');

        $self->install( accept_needs => [qw(mac_key mac_algorithm _issued)] );
        $self->install( accept_hook => sub {
            my $params = shift;
            $params->{_issued} = time();
        });

        $self->http_header_inserter
          (uses_params => \@_,
           make_auth => sub {
               my ($http_req, $token, %o) = @_;

               my @missing;
               my ($key, $alg, $issued) = 
                 map {defined $o{$_} ? $o{$_} : do { push @missing, @_; undef }}
                   (qw(mac_key mac_algorithm _issued));
               return ("missing_$missing[0]", $http_req)
                 if @missing;

               my $nonce = (time() - $issued) . ':' . encode_plainstring($random->($nonce_length));

               my $uri = $http_req->uri;
               $uri = $uri->to_string if ref($uri);

               my ($host,$port) = split ':',($http_req->header('Host') || $http_req->host_port);
               $port ||= $uri->scheme eq 'https' ? 443 : 80;

               my $ext = $http_hmac_ext_body->($http_req, 'client');

               my $normalized = join "\n",
                 $nonce, $http_req->method, $http_req->uri->path_query, $host, $port, $ext, '';
               return
                 (undef,
                  join ",\n ", qq(id="$token"), qq(nonce="$nonce"),
                     qq(mac=").encode_base64($alg->($key,$normalized), '').qq("),
                       (length($ext) ? (qq(ext="$ext")) : ()));
           });
    }
    return $self;
}

# IMPLEMENTATION (format_)http_hmac
#   (http_hmac_)hmac
# SUMMARY
#   HMAC-HTTP tokens
# REQUIRES
#   v_id_next
#   v_table_insert
#   v_id_kind == something random

sub pkg_format_http_hmac {
    my __PACKAGE__ $self = shift;

    # CANNOT be used for authcodes and refresh tokens
    $self->install(format_no_params => 0);

    my $mac_alg_name = $self->uses_param(http_hmac => \@_, 'hmac');
    $mac_alg_name =~ y/_/-/;
    my ($mac_alg_keylen, $mac_alg) = hmac_name_to_len_fun($mac_alg_name);

    if ($self->is_auth_server) {
        my $random = $self->uses('random');  # for key generation
        $self->uses(v_id_kind => 'counter'); # preferred but not required
        my $v_id_next = $self->uses('v_id_next');
        my $vtable_insert = $self->uses('vtable_insert');
        my $token_type = $self->uses('token_type');
        $self->install( token_create => sub {
            my ($now, $expires_in, @bindings) = @_;
            my $v_id = $v_id_next->();
            my $key = $random->($mac_alg_keylen);
            my $error = $vtable_insert->($v_id, $now + $expires_in, $now, $key, @bindings);
            return ($error,
                    ($error ? () :
                     (encode_plainstring($v_id), 
                      token_type => $token_type,
                      mac_key => $key, 
                      mac_algorithm => $mac_alg_name)));
        });
    }

    if ($self->is_resource_server) {
        $self->install( token_parse => sub {
            my ($v_id, %param) = @_;
            return decode_plainstring($v_id), @param{qw(mac nonce _method _uri _host _port ext _ext_body)};
        });

        $self->install( token_finish => sub {
            my ($v, $mac, $nonce, $method, $uri, $host, $port, $ext, $ext_body) = @_; # ($validator, @payload)
            my ($expiration, $issuance, $key, @bindings) = @$v;
            return ('bad_hash')
              unless length($mac) == $mac_alg_keylen &&
                timing_indep_eq($mac, $mac_alg->(join "\n",$nonce,$method,$uri,$host,$port,$ext,''), $mac_alg_keylen) &&
                length ($ext) == length($ext_body) &&
                timing_indep_eq($ext, $ext_body);
            return (undef, $issuance, $expiration - $issuance, @bindings);
        });
    }
    return $self;
}

1;

__END__

=head1 NAME

Net::OAuth2::Token::Scheme::HMac

=head1 SYNOPSIS

=head1 DESCRIPTION

This implements HMac-HTTP tokens as described in
L<draft-ietf-oauth-v2-http-mac-00|http://tools.ietf.org/html/draft-ietf-oauth-v2-http-mac-00>
minus the bodyhash functionality (which was in the process of being
discarded last I looked at the mailing list)

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
