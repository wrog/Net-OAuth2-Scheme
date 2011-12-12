use strict;
use warnings;

package Net::OAuth2::Scheme::Factory;
# ABSTRACT: the default factory for token schemes

use parent 'Net::OAuth2::Scheme::Option::Builder';

use parent 'Net::OAuth2::Scheme::Mixin::Root';
use parent 'Net::OAuth2::Scheme::Mixin::Transport';
use parent 'Net::OAuth2::Scheme::Mixin::Format';
use parent 'Net::OAuth2::Scheme::Mixin::Accept';
use parent 'Net::OAuth2::Scheme::Mixin::VTable';
use parent 'Net::OAuth2::Scheme::Mixin::NextID';

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

  # more stuff for authorization servers and resource servers
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

  # the completely specialized versions:
  my %recipe_auth = (
     %recipe_common,
     context => 'auth_server',

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

  ######
  # client code

  my $access_scheme = Net::OAuth2::Scheme->new(%recipe_client);

  ######
  # authserver code

  my $access_scheme   = Net::OAuth2::Scheme->new(%recipe_auth);
  my $refresh_scheme  = Net::OAuth2::Scheme->new(%recipe_refresh);
  my $authcode_scheme = Net::OAuth2::Scheme->new(%recipe_authcode);

  ######
  # resource code

  my $access_scheme = Net::OAuth2::Scheme->new(%recipe_resource);

=head1 DESCRIPTION

The token scheme factory object is created by
L<Net::OAuth2::Scheme>-E<gt>B<new>() to parse the option settings
given and produce the specialized methods that the resulting scheme
object will need.  It is an ephemeral object that self-destructs the
moment the scheme object is complete.

You should not need to create factory objects yourself, though it I<is>
intended for you to be able to create your own factory I<classes> with
their own option groups and implementation methods for, e.g., new
token formats, transport schemes, etc.  See
L<Net::OAuth2::Scheme::Option::Builder> and
L<Net::OAuth2::Scheme::Option::Defines> and the various mixins 
L<Net::OAuth2::Scheme::Mixin::*> to get a sense of how to do this
(... though also be aware that this part of the world may be in a bit
of flux for a while...)

=head1 KINDS OF OPTIONS

There will generally be two kinds of option settings

=over

=item I<option_name> C<=E<gt>> I<value> 

which directly sets the value of the specified option.  

=item I<group_name> C<=E<gt>> I<implementation> 

which has the effect of setting an entire group of options.
(Options that are members of a group can be set individually,
but in most cases you shouldn't, and if you do, you need to
be sure you set all of them).

I<implementation> is either a string naming the implementation choice
that this group represents or an arrayref whose first element is said
implementation choice and the remaining elements are alternating
keyword-value pairs, e.g.,

  transport => ['bearer',
                 param => 'oauth_second',
                 allow_uri => 1]

which specify the settings of related options that the implementation
directly depends on.  Generally each keyword here will be the name of
some option with some prefix stripped.  E.g., the previous example is
equivalent to specifying

  transport => 'bearer',
  bearer_param => 'oauth_second',
  bearer_allow_uri => 1,

=back

Group settings and single-option settings can be given in any order;
nothing is executed until the context/usage is determined and a scheme
object needs to be produced.

Note, however, that the usual rules for initializing perl hashes still
apply, e.g., if you specify an option setting twice in the same
parameter list, only the second one matters.

An option setting is regarded as I<constant>, i.e., once an option
value is actually set, it is an error to attempt to set it differently
value later (group implementations I<can> do this, which will then
abort your scheme creation).

You can use the C<defaults> option (or C<defaults_all> if you are
completely crazy) to change the defaults for certain options without
actually setting them (if say, one of the existing defaults turns out
to be stupid, or you are building a scheme template into which Other
People will be inserting Actual Settings later...).

=head1 OPTIONS

Generally you will have to set one of C<usage> or C<context>.

Specifying C<transport> is usually enough for client implementations.
Authorization and resource servers will also need at least C<format>
and C<vtable>.  

Certain option settings will entail the presence of others (e.g., all
current versions of C<vtable> require a setting for C<cache>) which
will be noted below.

=head2 usage

=over

=item C<access>

(Default.)  This scheme provides access token methods for use in a
client, authorization server, or resource server implementation.

Note that in OAuth2, clients and resource servers do not, in fact,
(currently) need to see other kinds of scheme objects.  While client
implementations do need to handle refresh tokens and authorization
codes, in that context they are simply opaque strings and questions of
transport that would normally be of interest are already completely
determined by the OAuth2 protocol itself, so there are no actual
methods that need to be made available there.

=item C<refresh>

This scheme provides refresh token methods 
for use in an authorization server implementation.

The methods B<token_create> and B<token_validate> are provided.

=item C<authcode>

This scheme provides authorization codes methods
for use in an authorization server implementation.

The methods B<token_create> and B<token_validate> are provided.

(authorization code schemes currently differ from refresh token
schemes only in choice of binding information, which is outside the
scope of these modules, so these schemes are functionally identical,
for now...)

=back

=head2 context

For access-token schemes, the implementation context needs to be specified.
This can be one or more of the following:

=over

=item C<client>

This scheme object is for use in a client implementation.
The methods B<token_accept> and B<http_insert> will be provided.

=item C<resource_server>

This scheme object is for use in a resource server implementation.
The methods B<http_extract> and B<token_validate> will be provided.

=item C<auth_server>

This scheme object is for use in an authorization server implementation.
The B<token_create> method will be provided.

=back

This option value can either be as single string or a listref in the case of 
combined implementations where the same process is serving multiple 
roles for whatever reason.

Note that while refresh token and authorization code schemes are only
needed within an authorization server implementation, since the same
server also has to be able to I<receive> these tokens/codes, the
resource-side methods need to be enabled.  Thus the scheme object is
produced (mostly) as if

 context => [qw(auth_server, resource_server)]

were specified, meaning that any option settings that would otherwise
only be necessary for a resource server implementation will be
required in these cases as well.

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
some or all of the binding values, a nonce, and a hash value keyed on
a shared secret that effectively signs everything.  Only the shared
secret and remaining binding values needs to be kept in the vtable and
communicated separately to the resource server.

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

The cache is an actual (secure) shared cache, accessible to both the
authorization server and the resource server, whether this be, say,

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
authorization and resource requests are handled by the same process.

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
B<vtable_push> which sends the new entry to the resource server by
some means.  A push-handler in the resource server receives the entry
and calls B<vtable_pushed> to insert it into the actual cache, and
either B<token_create> blocks until the push response is received or
(if you care about speed and can tolerate the occasional race condition
failure) we just assume the resource server has enough of a head start
that the insertion will be completed by the time the client gets
around to actually using the token.

C<vtable_lookup> by the resource server is then just C<vtable_get>.

The function B<vtable_push> must be supplied in the authorization
server implementation.  It is expected to send its (opaque) argument
to the resource server and then returns the (null or error code)
response it received.

The function B<vtable_pushed> is available on the scheme object to the
resource server implementation.  The push request handler is expected
to call it on the value sent by B<vtable_push>, sending back as a response
whatever return value (null or error code) it gets.

=item C<resource_pull>

There is a cache, but it is (again) local/private to the resource server.

C<vtable_insert> by the authorization server does C<vtable_enqueue>,
which just places the entry on an internal queue.

C<vtable_lookup>, when called by the resource server, does the following

=over

=item *

a call to C<vtable_get>, which may succeed or fail.  
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

The function B<vtable_dump> is available on the scheme object to the
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

