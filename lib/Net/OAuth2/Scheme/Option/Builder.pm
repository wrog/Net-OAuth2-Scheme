use strict;
use warnings;

package Net::OAuth2::Scheme::Option::Builder;
# ABSTRACT: poor man's mixin/role closure builder

use Net::OAuth2::Scheme::Option::Defines qw(All_Classes);


# use machinery from Net::OAuth2::TokenType::Scheme::Defines
# to gather all default values and group definitions
sub _all_defaults {
    my $class = shift;
    no strict 'refs';
    map {%{"${_}::Default"}} All_Classes($class);
}

sub _all_groups {
    my $class = shift;
    no strict 'refs';
    map {%{"${_}::Group"}} All_Classes($class);
}

use fields qw(value defaults pkg used export);
sub new {
    my $class = shift;
    my %opts = @_;
    $class = ref($class) if ref($class);
    my __PACKAGE__ $self = fields::new($class);
    my %group = $class->_all_groups;

    for my $i (values %group) {
        if (defined $i->{default}) {
            $self->{pkg}->{$_} = $i->{default}
              for @{$i->{keys}};
        }
    }
    for my $o (keys %opts) {
        if (my $i = $group{$o}) {
            $self->{pkg}->{$_} = "pkg_${i}_$opts{$o}"
              for @{$i->{keys}};
        }
        else {
            $self->{value}->{$o} = $opts{$o};
        }
    }

    $self->{defaults} = 
      $self->{value}->{defaults_all}
        ||
      { _all_defaults(ref($self)),
        %{$self->{value}->{defaults} || {}},
      };
}

sub installed {
    my __PACKAGE__ $self = shift;
    my ($key, $default) = @_;
    return $self->{value}->{$key};
}

# uses(key => [,default_value])
# if option 'key' is not defined,
# either use default_value, install package for it, or die
sub uses {
    my __PACKAGE__ $self = shift;
    my ($key, $default) = @_;
    unless (exists($self->{value}->{$key})) {
        if (defined $default) {
            $self->install($key, $default);
        }
        elsif (defined($default = $self->{defaults}->{$key})) {
            $self->install($key, $default);
        }
        elsif (my ($pkg,@kvs) = ($self->{pkg}->{$key})) {
            ($pkg,@kvs) = @$pkg if ref($pkg);
            $self->$pkg(@kvs);
            Carp::croak("package failed to define value:  $pkg -> $key")
                unless defined $self->{value}->{$key};
        }
    }
    my $value = $self->{value}->{$key};
    Carp::croak("undefined:  $key")
      unless defined($value);
    $self->{used}->{$key}++;
    return $value;
}

# ensure(key => $value, $msg)
# == uses(key => $value) and die with $msg if value is not $value
sub ensure {
    my __PACKAGE__ $self = shift;
    my ($key, $value, $msg) = @_;
    $self->uses($key, $value) eq $value
      or Carp::croak($msg || "$key expected to be '$value'");
    return $self;
}

# uses_all(qw(key1 key2 ...))
# == (uses('key1'), uses('key2'),...)
sub uses_all {
    my __PACKAGE__ $self = shift;
    return map {$self->uses($_)} @_;
}

# like uses() but checks a supplied prefix-stripped list of key-value pairs first
# uses_param(prefix => $kvs, key => $default)
# == uses('prefix_key', {@$kvs}->{key} // $default)
sub uses_param {
    my __PACKAGE__ $self = shift;
    my ($prefix, $kvs, $name, $default) = @_;
    my $value = {@$kvs}->{$name};
    $value = $default unless defined $value;
    return $self->uses("${prefix}_$name", $value);
}

# like uses_all() but checks a supplied prefix-stripped list of key-value pairs first
# uses_params(prefix => $kvs, qw(key1 key2 ...))
# == (uses_param(prefix => $kvs, 'key1'), uses_param(prefix => $kvs, 'key2'), ...)
sub uses_params {
    my __PACKAGE__ $self = shift;
    my ($prefix, $kvs, @names) = @_;
    return map { $self->uses_param($prefix, $kvs, $_) } @names;
}

# install(key => $value) sets option 'key' to $value
sub install {
    my __PACKAGE__ $self = shift;
    my ($key, $value) = @_;

    Carp::croak("tried to install undef?:  $key")
        unless defined $value;
    Carp::croak("multiple definitions?:  $key")
        if defined $self->{value}->{$key};
    Carp::croak("redefinition after use?:  $key")
        if $self->{used}->{$key};

    $self->{value}->{$key} = $value;
}

# export(keys...) == uses(keys ...)
# marking all keys as being exported.
sub export {
    my __PACKAGE__ $self = shift;
    $self->uses_all(@_);
    $self->{export}->{$_}++ for (@_);
}

sub all_exports {
    my __PACKAGE__ $self = shift;
    return keys %{$self->{export}};
}


    #   new( defaults => { additional defaults... } ...)
    #     if you want to keep all of the various default values set
    #     and only make minor changes
    #   new( defaults_all => { defaults ...}
    #     if you want to entirely replace all default values;
    #     in which case this function never gets called
    #     since defaults_all is already set;
    #     Kids, don't try this at home...

1;

=pod

=head1 SYNOPSIS

  use parent Net::OAuth2::TokenType::Option::Builder;

  Define_Group gearshift => tenspeed,
    qw(gearshift_doshift gearshift_coast);

  sub pkg_gearshift_tenspeed {
    my $self = shift;
    my $count = $self->uses(gearcount);
    $self->install(gearshift_doshift => sub {
       ...
    }
    $self->install(gearshift_coast => sub {
       ...
    }
  }  

  sub pkg_gearshift_sturmey_archer {
    ...
  }



=head1 DESCRIPTION

 buh.

=head1 METHODS

=over

=item B<install> (C<< name => $value >>)

Installs a value for option C<name>.

=item B<uses> (C<name>I<[, >C<$default>I<]>)

Gets the value for option C<name>.

If no value has yet been intalled,
installs a default value if one has been specified either 
here (C<$default>) or elsewhere 
(e.g., using the C<defaults> group or B<Define_value>)

Otherwise, C<name> must be part of some group,
so we see which implementation for that group 
has been chosen and invoke it to set C<name> 
(and whatever else) so that we can get a value.

=item B<export> C<'name'>

Does B<uses>(C<'name'>) then adds C<'name'> 
to the list of exported options.

=item B<ensure> (C<< name => $value >>)

Does B<uses>(C<< name => $value >>)
then dies if option C<name> does not, in fact, have the value C<$value>.

=item B<uses_all> (C<<qw( name1 name2 ... )>>)

Equivalent to B<uses>(C<name1>), B<uses>(C<name2>), etc..., 
returning the list of corresponding values.

=item B<uses_param>

=item B<uses_params>

=back



