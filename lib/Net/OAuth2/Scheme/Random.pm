use strict;
use warnings;

package Net::OAuth2::Server::Random;
use Carp;
use Thread::IID 'interpreter_id';

# fixup procedures for when rng_class->new
# does not quite do the right thing
my %fixup = ();

# we keep around one RNG per rng_class per thread
# keep re-using the same seed in forks and interpreter clones
my @seeds = _make_seed();
my %rng = ();
my %bytes = (); # leftover bytes from bytestring generation
my %refs = ();  # how many objects have been created for a given rng_class
my $p_id = -1;
my $i_id;

sub _reseed_for_new_thread {
    my $rng_class = shift;
    my $rng = $rng_class->new(@seeds, $p_id, $i_id, time);
    $rng = $fixup{$rng_class}->($rng)
      if $fixup{$rng_class};
    $rng{$rng_class} = $rng;
    $bytes{$rng_class} = '';
}    

our $RNG_Class = 'Math::Random::ISAAC';
$fixup{$RNG_Class} = \&_rng_fixup_ISAAC;

sub new {
    my $class = shift;
    my $rng_class = shift || $RNG_Class;
    $class->CLONE unless $$ == $p_id;
    unless ($rng{$rng_class}) {
        eval "require $rng_class";
        _reseed_for_new_thread($rng_class);
    }
    $refs{$rng_class}++;
    return bless \( $rng_class ), $class;
}

sub _rng {
    my $self = shift;

    # just in case CLONE is not called after a fork()
    # which is how things work in unix,
    # so we have to check for this here.
    ref($self)->CLONE unless $$ == $p_id;

    return $rng{$$self};
}

sub DESTROY {
    my $self = shift;
    --$refs{$$self};
    # this routine only exists for the sake of being able to detect
    # unused RNG classes upon interpreter clone or process fork.
    # 
    # once a RNG of a given class is created with a given seed,
    # we need to keep it around forever within any given process/thread
    # otherwise, we will get repeats
}

sub CLONE {
    my $class = shift;
    return if $p_id == $$ && $i_id == interpreter_id;
    $p_id = $$;
    $i_id = interpreter_id;
    for my $rng_class (keys %rng) {
        if ($refs{$rng_class} <= 0) {
            # nobody is currently using it
            # therefore it has not been used yet in this thread
            # therefore we can safely get rid of it
            delete $rng{$rng_class};
            delete $bytes{$rng_class};
            delete $refs{$rng_class};
        }
        else {
            _reseed_for_new_thread($rng_class);
        }
    }
}

sub irand {
    my $self = shift;
    $self->_rng->irand();
}

sub bytes {
    my ($self, $nbytes) = @_;
    Carp::croak('non-negative integer expected') 
        if $nbytes < 0;

    my $rng = $self->_rng;

    my @ints = ();
    push @ints, $rng->irand for (1..$nbytes>>2);

    unless (my $nrem = $nbytes&3) {
        return pack 'L*', @ints;
    }
    else {
        my ($rest);
        my $extras = $bytes{$$self};
        if ($nrem == length($extras)) {
            ($rest,$bytes{$$self}) = ($extras,'');
        }
        else {
            ($rest,$bytes{$$self}) = unpack 'C/aa*', 
              ($nrem > length($extras) 
               ? pack 'Ca*L', $nrem, $extras, $rng->irand
               : pack 'Ca*',  $nrem, $extras);
        }
        return pack 'a*L*', $rest, @ints;
    }
}

sub _make_seed {
    # stolen from Math::Random::Secure
    my $source;
    if ($^O =~ /Win32/i) {
        # On Windows, there is apparently only one choice
        require Crypt::Random::Source::Strong::Win32;
        $source = Crypt::Random::Source::Strong::Win32->new();
    }
    else {
         require Crypt::Random::Source::Factory;
         my $factory = Crypt::Random::Source::Factory->new();
         $source = $factory->get;

         # Never allow rand() to be used as a source, it cannot possibly be
         # cryptographically strong with 15 or 32 bits for its seed.
         $source = $factory->get_strong
           if ($source->isa('Crypt::Random::Source::Weak::rand'));
    }
    return unpack('L*', $source->get(64));
}

### ISAAC-specific stuff

sub _rng_fixup_ISAAC {
    my $rng = shift;
    # It's faster to skip the frontend interface of Math::Random::ISAAC
    # and just use the backend directly. However, in case the internal
    # code of Math::Random::ISAAC changes at some point, we do make sure
    # that the {backend} element actually exists first.
    $rng = $rng->{backend} if $rng->{backend};
    return $rng;
}

