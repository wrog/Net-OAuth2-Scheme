use strict;
use warnings;

package Net::OAuth2::TokenType::Factory;
# ABSTRACT: a factory for token types

use parent 'Net::OAuth2::TokenType::Options::Builder';

use parent 'Net::OAuth2::TokenType::Scheme::Root';
use parent 'Net::OAuth2::TokenType::Scheme::Transport';
use parent 'Net::OAuth2::TokenType::Scheme::Format';
use parent 'Net::OAuth2::TokenType::Scheme::Accept';
use parent 'Net::OAuth2::TokenType::Scheme::VTable';
use parent 'Net::OAuth2::TokenType::Scheme::NextID';

#... and, we are done.  Bwahahahahahaha.
1;

=pod

=head1 SYNOPSIS

  # The recipes;
  # 
  # can be hardcoded, initialized from config files, etc...

  my %recipe_client = (
     context => 'client',
     transport => 'bearer'
     ... or ...
     transport => 'hmac_http',
  )

  my %recipe_common = (
     %recipe_client,
     format => 'bearer_handle', # or 'bearer_signed'
     ... or ...
     format => 'hmac_http',

     vtable => 'shared_cache', # default
     cache => $cache_object    # shared cache for authservers + resources
     ...or...
     vtable => 'authserv_push',
     ...or...
     vtable => 'resource_pull',
  );

  my %recipe_auth = (
     %recipe_common,
     context => 'authorization_server',

     # if authserv_push
     vtable_push => \&my_push_method,
  );

  my %recipe_resource = (
     %recipe_common,
     context => 'resource_server',

     # if authserv_push or resource_pull
     cache => $private_cache_object,  # only accessible to resource server

     # if resource_pull
     vtable_pull => \&my_pull_method,
     },
  );

  # for refresh tokens
  my %recipe_refresh = (
     usage => 'refresh',
     format => 'bearer_handle', # or 'bearer_signed'

     vtable => 'shared_cache',
     cache => $private_cache_object,  # only accessible to authserver(s)
  );

  sub TOKENTYPE_CLASS { 'Net::OAuth2::TokenType' }

  ######
  # client code

  my $access_token_type = TOKENTYPE_CLASS->new(%recipe_client);

  ######
  # authserver code

  my $access_token_type  = TOKENTYPE_CLASS->new(%recipe_auth);
  my $refresh_token_type = TOKENTYPE_CLASS->new(%recipe_refresh);
  my $authcode_type      = TOKENTYPE_CLASS->new(%recipe_authcode);

  ######
  # resource code

  my $token_type = TOKENTYPE_CLASS->new(%recipe_resource);


=head1 DESCRIPTION

A TypeFactory is an ephemeral object that takes a collection of option
settings representing a specific token scheme, i.e., a recipe that
specifies some or all of the following

=over

=item *

use (access vs. refresh vs. authorization code),

=item *

transport method and format

=item *

resource identifier or related family thereof,

=item *

client identifier or capability class,

=item *

resource/authorization server secret sharing paradigm
(i.e., type of "validator table" or "vtable"),

=back

and then generates a token type object for the particular purpose and
context for which it is needed, whether this be an access token for a
client, authorization server, or resource server, or a refresh token
or an authorization code.

The token type object (see L<Net::OAuth2::TokenType>) produced has
methods for creating, disecting, and transmitting individual tokens
that are specific to the specified scheme.

=head1 KINDS OF OPTIONS

There will generally be two kinds of option settings

=over

=item I<option_name> C<=E<gt>> I<value> 

which directly sets the value of the specified option,

=item I<group_name> C<=E<gt>> I<implementation> 

which indicates that if some option value belonging to
I<group_name> is actually needed and no value has yet
been set nor any default provided, then the given 
I<implementation> should be installed to set all of 
the option values belonging to I<group_name>.  

This will often have the effect of requiring other option values,
which then might cause other implementations to be installed.
Implementations may also designate "exports" that will then 
appear as additional methods on the token type object.

I<implementation> is usually a string indicating the name of the method to be 
called to instantiate the values of the options in I<group_name>
(C<pkg_>I<group_name>C<_>I<implementation>, e.g., 
C<< transport => bearer >> specifies that
the C<< pkg_transport_bearer() >> method from L<TokenType::Scheme::Bearer>
should be called if the C<transport> options are needed)

I<implementation> can also be an arrayref, in which case the first element
should be a string interpreted as above and the remaining elements are expected to
be alternating keywords and values, e.g., 

  transport => ['bearer',
                 param => 'oauth_second',
                 allow_uri => 1]

which causes additional options to be set prior to invoking the implementation.
Generally each keyword will be the name of an option with some prefix stripped.
E.g., the previous example is equivalent to

  transport => 'bearer',
  bearer_param => 'oauth_second',
  bearer_allow_uri => 1,

=back

Group settings and single-option settings can be given in any order;
nothing is executed until the context/usage is determined and a token type is to be produced.

Note however that the usual rules for initialing perl hashes still apply,
e.g., if you specify an option setting twice in the same call, 
only the second one matters


=head1 USAGE OPTIONS

There are two option settings that determine where and how the token type can used

=head2 usage

=over

=item C<access>

(Default.)  Indicates that this is a token used for access to resources.  

Note that in OAuth2, clients and resource servers do not, in fact,
need to see other kinds of token type objects.  (Yes, client
implementations do handle refresh tokens and authorization codes, but
there they are simply opaque strings and the transport is already
nailed down by the OAuth2 protocol itself, so there are no actual
methods that need to be made available.)

=item C<refresh>

This type is used for refresh tokens.

Provides at least B<token_create> and B<token_validate>.
(Since the OAuth 2.0 specification dictates how refresh tokens appear
in requests and responses, there is no need for separate B<http_insert> or
B<http_extract> methods here.)

In this case, I<both> the authorization server and resource server
contexts (below) are assumed since the authorization server is both a
producer and consumer of refresh tokens.  This means that any option
settings that would otherwise only be necessary for a resource server
implementation will be required here.

=item C<authcode>

This type is used for authorization codes.

This supplies the same methods and entails the same context assumptions 
as for refresh tokens (above).

(Yes, the OAuth 2.0 specification does not actually consider
authorization codes to be tokens, but from a functional point of view
they essentially are, i.e., most of the same methods are needed,
therefore this is as good a place as any to obtain implementations of
them.)

=back

=head2 context

For access token types, the context value can be one of the following strings:

=over

=item C<client>

This token type is for use in a client implementation.
Provides at least B<token_accept> and B<http_insert>.

=item C<resource_server>

This token type is for use in a resource server implementation.
Provides at least B<http_extract> and B<token_validate>.

=item C<authorization_server>

This token type is for use in an authorization server implementation.
Provides at least B<token_create>.

=back

One may also supply a listref, e.g.,

 context => ['authorization_server','resource_server']

for a combined implementation where authorization server and resource
server are in the same process.  In this case, the resulting token
type will have at least the methods B<token_create>, B<http_extract>,
B<token_validate> and possibly others.

=head1 OPTION GROUPS

You will need to provide settings for at least C<transport>, C<format>, and C<cache>.

=head2 transport

Provides B<http_extract> and B<http_insert>.  Choices are

=over

=item C<< bearer_header  [scheme => I<scheme>] >>

Bearer token string in an Authorization header.
C<scheme> and C<location> can also be specified separately as 
options C<bearer_param_name> and C<bearer_param_location>.

Refers to option C<bearer_header_scheme>

=item C<< bearer_param  [name => I<name>, location => 'body'|'query'|'dontcare'] >>

Bearer token string in a POST body or URI parameter.  
C<name> and C<location> can also be specified separately as 
options C<bearer_param_name> and C<bearer_param_location>.

=item C<hmac_http>

Implements the transport side of L<draft-ietf-oauth-v2-http-mac>,
a "proof-style" token in which the token string is a key identifier 
and additional parameters (C<nonce>, C<mac>) placed in an Authorization
header constituting proof that the client possesses the token secret
without having to actually send the secret.

=back

=head2 format

Provides C<token_create>, C<token_parse>, and C<token_finish>  Choices are

=over

=item C<bearer_handle>

Use a "handle-style" bearer token where the token string is a random
base64url string with no actual content.  Expiration information and
all binding values must live in the vtable and need to be communicated
individually to the resource server.

=item C<bearer_signed>

Use a "assertion-style" bearer token where the token string includes
all binding values, a nonce, and a hash value keyed on a shared secret
that effectively signs everything.  Only the shared secret needs to be
kept in the vtable and communicated separately to the resource server.

=item C<hmac_http>

Implements the formatting portion of L<draft-ietf-oauth-v2-http-mac>
(see description under C<transport_hmac_http>).  Expiration
information and all binding data live in the vtable, as for
handle-style bearer tokens.

=back

=head2 vtable

The validator table or "vtable" is the mechanism via which secrets are
communicated from the authorization server to the resource server.

Conceptually, it is a shared cache, for which two functions are
exposed to the formatting group: C<vtable_insert>, which the
authorization server uses to write new secrets and binding values to
the cache, and C<vtable_lookup>, which the resource server uses to
obtain these values as needed to validate a given token and return the
bindings and expiration data associated with it.

There are three implementation frameworks to choose from:

=over

=item C<shared_cache>

The cache is an actual (secure) shared cache, whether this be, say,

=over

=item *

a L<memcached> server (or a farm thereof) mutually accessible to 
authorization and resource servers, which can then live on entirely 
different hosts or even distinct network sites

=item * 

a file-based cache (e.g., L<Cache::File>), which requires
authorization and resource servers to either be on the same host 
or have access to the same file server

=item *

a shared-memory-segment cache (e.g., L<Cache::Memory>), which requires
authorization and resource servers to either be on the same host.

=item *

some kind of shared internal reference in the case where the
authorization and resource servers are in the same process.

=back

C<vtable_insert> and C<vtable_lookup> translate directly to
C<vtable_put> and C<vtable_get> (see C<vtable-cache> below) with no
additional machinery.  Secrets inserted by the authorization server
just become automatically available immediately on the resource
server, and we don't have to know exactly how the communication
happens because the cache implementer already took care of that for
us.

=item C<authserv_push>

There is a cache, but it is local/private to the resource server.

C<vtable_insert> by the authorization server is actually
C<vtable_push> which sends the new entry to the resource server by
some means.  A push-handler in the resource server receives the entry
and calls C<vtable_pushed> to insert it into the actual cache, and
either B<token_create> blocks until the push response is received or
(more likely) we just assume the resource server has enough of a head
start that the insertion will be completed by the time the client gets
around to actually using the token.

C<vtable_lookup> by the resource server is then just C<vtable_get>.

The function B<vtable_push> must be supplied in the authorization
server implementation.  It is expected to send its (opaque) argument
to the resource server and then returns the (null or error code)
response it received.

The function B<vtable_pushed> is exported by the token type to the
resource server implementation.  The push request handler is expected
to call it on the value sent by B<vtable_push> and send back whatever
return value (null or error code) it gets.

=item C<resource_pull>

There is a cache, but it is (again) local/private to the resource server.

C<vtable_insert> by the authorization server does C<vtable_enqueue>,
which just places the entry on an internal queue.

C<vtable_lookup> does the following

=over

=item *

the resource server first does a C<vtable_get> which may succeed or fail.  
Failure is immediately followed by

=item *

a call to C<vtable_pull> which is expected to send a query to the authorization
server.  

=item *

A pull handler on the authorization server then calls C<vtable_dump> 
to flush the contents of the internal queue and
incorporate this list value into a response back to the resource server.

=item *

C<vtable_pull> then receives that response, extracts the reply list value 
and returns it, at which point

=item *

C<vtable_load> can then load the new entries into the resource
server's cache and then 

=item *

C<vtable_get> can be retried.

=back

The function B<vtable_pull> must be supplied in the resource server
implementation and is expected to send an opaque query to the
authorization server and return whatever response it receives.

The function B<vtable_dump> is exported by the token type to the
authorization server implementation.  Its argument is expected to be
the query value received by the pull-handler, and its return value
is to be included in the response to the pull request.

=back

=head2 vtable_cache

The low-level cache interface; provides C<vtable_get> and C<vtable_put>.
The default implementation is 

=over

=item C<object>

which requires C<cache> to be set to some object that implements the 
L<Cache|Cache> interface, specifically C<get()> and the 3-argument C<set()>.

=back

I<< (...some day there may also be a straight hash-reference
implementation for those cases where response and authorization server
are the same process and somebody wants to be ultra-secure by not even
allowing the cache into shared memory... but I'm not going to worry
about this for now...) >>

=head2 vtable_pull_queue

Provides a queue for C<< vtable => resource_pull >>, in the form of the functions
C<vtable_enqueue>, C<vtable_dump>, C<vtable_query>, and C<vtable_load>.

This has a default implementation that you probably don't need to care about.

=head2 current_secret

Provides current secret management for C<< format => bearer_signed >>,
namely a list reference C<current_secret> and a function
C<current_secret_rekey_check>, which is run every time a new token is
created in order to regenerate the secret as needed.

This has a default implementation that refers to C<current_secret_rekey_interval> and C<current_secret_length>.

=head2 v_id_next

Generates new v_ids.  Provides the function C<v_id_next> and the flag C<v_id_is_random>, 
which causes C<format_bearer_handle> to die if it is not set.

This has a default implementation ...

=head2 random

A cryptographically secure random number generator.

This has a default implementation

=over

=item C<isaac>

which is the L<Math::Random::ISAAC(::XS)|Math::Random::ISAAC> random number generator.

=back

=head1 INDIVIDUAL OPTIONS

