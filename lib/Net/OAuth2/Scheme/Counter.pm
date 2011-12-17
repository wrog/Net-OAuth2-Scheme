use warnings;
use strict;

package Net::OAuth2::Scheme::Counter;
# ABSTRACT: a host-wide counter
use Carp;
use Thread::IID 'interpreter_id';

my %current = ();
my %refs = ();  # how many objects have been created for a given tag
my $p_id = -1;
my $i_id;
my $start;

# This counter rolls over every 200 days
# (token lifetimes should not be ANYWHERE NEAR this long)
sub _mk_start {
    $start = pack "Cw2a3a*", 0x0, ($i_id = interpreter_id), ($p_id = $$), pack('V',time());
}

sub next {
    my $self = shift;
    my $tag = $$self;

    # check for fork()
    ref($self)->CLONE unless $$ == $p_id;

    my $s0 = ord(substr($current{$tag},0,1));
    my ($n,$s) = unpack 'wa*', (($s0 & 0x40) ? chr(0xc0)^$current{$tag} : $current{$tag});
    $s = pack 'wa*', $n+1, $s;
    $s0 = ord(substr($s,0,1));
    return $current{$tag} =
      ($s0 & 0xc0)==0x80 ? chr(0xc0)^$s : ($s0 & 0x40) ? chr(0x40).$s : $s;

    # # base-128 bytestring
    # # high-order byte has high-order bit set; all others are 0x00-0xfe
    # $current{$tag} =~ m{\A(\177*)(?:([\0-\176])([\0-\177]*[\200-\377])|([\200-\377]))(.*)}s;
    # return $current{$tag} = pack 'a*Ca*a*',
    #   "\0" x length($1),
    #   (defined($2)
    #    ? (ord($2)+1, $3)
    #    : (ord($4)==255 ? (0, "\200") : (ord($4)+1, ''))
    #   ),
    #   $5;
}

sub new {
    my $class = shift;
    my $tag = shift || '';

    # check for fork()
    $class->CLONE unless $$ == $p_id;

    $current{$tag} = $start
      unless ($current{$tag});

    ++$refs{$tag};
    return bless \( $tag ), $class;
}

sub DESTROY {
    my $self = shift;
    --$refs{$$self};
    # this routine only exists for the sake of being able to detect
    # unused tags upon interpreter clone or process fork.
    #
    # once a counter for a given tag is created, it's best to keep it
    # around; we risk repeats if we get rid of a tag and recreate it
    # within a second of its original creation in the same process/thread
}

sub CLONE {
    my $class = shift;
    return if $p_id == $$ && $i_id == interpreter_id;
    _mk_start();
    for my $tag (keys %refs) {
        if ($refs{$tag} <= 0) {
            # nobody is currently using it
            # therefore it has not been used yet in this thread
            # therefore we can safely ignore it
            delete $refs{$tag};
            delete $current{$tag};
        }
        else {
            $current{$tag} = $start;
        }
    }
}

1;
