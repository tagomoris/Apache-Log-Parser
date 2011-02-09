# -*- coding: utf-8 -*-

package Apache::Log::Parser;

use strict;
use warnings;
use Carp;
use List::Util qw( reduce );

our @FAST_COMMON_FIELDS = qw( rhost logname user datetime date time timezone request method path proto status bytes );
our @FAST_COMBINED_FIELDS = (@FAST_COMMON_FIELDS, 'refer', 'agent');

our $COMMON = [" ", [qw(rhost logname user datetime request status bytes)], undef];
our $COMBINED = [" ", [qw(rhost logname user datetime request status bytes refer agent)], sub{my $x=shift; defined($x->{agent}) and defined($x->{refer})}];
our $VHOST_COMMON = [" ", [qw( vhost rhost logname user datetime request status bytes )], undef];

our $STRICT_DEFAULT_FORMATS = [$COMBINED, $COMMON, $VHOST_COMMON];

our @REQUIRED_FIELDS = qw( rhost logname user datetime request status bytes );
our @FIELDS_ALWAYS_RETURNED = qw( host logname user datetime date time timezone request method path proto status bytes );

sub new {
    my $class = shift;
    my $self = bless {}, $class;

    my %args = @_;
    croak "only one option from 'strict' or 'fast' required." unless ($args{strict} xor $args{fast});

    if ($args{strict}) {
        my @formats = (ref($args{strict}) ? @{$args{strict}} : ());
        if (scalar(@formats) > 0) {
            for (my $i = 0; $i < scalar(@formats); $i++) {
                if ($formats[$i] eq 'common') {
                    $formats[$i] = $COMMON;
                }
                elsif ($formats[$i] eq 'combined') {
                    $formats[$i] = $COMBINED;
                }
                elsif ($formats[$i] eq 'vhost_common') {
                    $formats[$i] = $VHOST_COMMON;
                }
                else {
                    unless (length($formats[$i]->[0]) > 0 and
                                scalar(reduce{$a += scalar(grep{$_ eq $b}@REQUIRED_FIELDS)} 0, @{$formats[$i]->[1]}) == scalar(@REQUIRED_FIELDS)) {
                        croak "specified fields not enough";
                    }
                }
            }
            $self->{try_maps} = \@formats;
        }
        else {
            $self->{try_maps} = $STRICT_DEFAULT_FORMATS;
        }
        $self->{strict} = 1;
    }
    else {
        $self->{strict} = 0;
        if (ref($args{fast}) and scalar(@{$args{fast}}) > 0) {
            my @args = @{$args{fast}};
            my @fields = ();
            foreach my $arg (@args) {
                if ($arg eq 'common') {
                    push @fields, [scalar(@FAST_COMMON_FIELDS), \@FAST_COMMON_FIELDS];
                }
                elsif ($arg eq 'combined') {
                    push @fields, [scalar(@FAST_COMBINED_FIELDS), \@FAST_COMBINED_FIELDS];
                }
                elsif (ref($arg)) {
                    my @matchers = @{$arg};
                    push @fields, [scalar(@FAST_COMMON_FIELDS) + scalar(@matchers), [@FAST_COMMON_FIELDS, @matchers]]
                }
                else {
                    croak "unknow definition for fast parse";
                }
            }
            $self->{field_lists} = \@fields;
        }
        else {
            $self->{field_lists} = [
                [scalar(@FAST_COMBINED_FIELDS), \@FAST_COMBINED_FIELDS],
                [scalar(@FAST_COMMON_FIELDS), \@FAST_COMMON_FIELDS]
            ];
        }
        my $part = q{\s*"?([^"]*)?"?} ;
        my $common = q{([^\s]*)\s+([^\s]*)\s+([^\s]*)\s+\[(([^: ]+):([^ ]+) ([-+0-9]+))\]\s+"((\w+) ([^\s]*) ([^\s]*))"\s+([^\s]*)\s+([^\s]*)};
        my $common_parts = 13;
        my $max_match_parts = reduce {$a > $b ? $a : $b} 0, map {$_->[0]} @{$self->{field_lists}};
        my $regex = $common . ($part x ($max_match_parts - $common_parts));
        $self->{fastpattern} = qr/\A$regex/;
    }
    return $self;
}

sub parse_fast {
    my ($self, $line) = @_;
    chomp $line;
    my @values = ($line =~ $self->{fastpattern});
    my $matches = scalar(grep {$_} @values);
    foreach my $ref (@{$self->{field_lists}}) {
        next if $ref->[0] > $matches;
        my $pairs = {};
        for (my $i = 0; $i < $ref->[0]; $i++) {
            $pairs->{$ref->[1]->[$i]} = $values[$i];
        }
        return $pairs;
    }
    return undef;
}

sub dequote {
    my $str = shift;
    return $str unless substr($str, 0, 1) eq '"';
    my $body = substr($str, 1, length($str) - 2);
    $body =~ s/\\"/"/g;
    $body;
}

sub has_unquoted_tail_doublequote {
    my $part = shift;
    return 0 if substr($part, -1, 1) ne '"';
    return 1 if substr($part, -2, 1) ne '\\';

    my $reversed_body = substr(reverse($part), 1);
    my $backslash_count = 0;
    foreach my $c (split(//, $reversed_body)) { $c eq '\\' and $backslash_count += 1 or last; }
    not ($backslash_count % 2);
}

sub separate_log_items {
    my ($sep, $buf) = @_;
    my $continuing = 0;
    my $flag_in_quoted = 1;
    my $flag_in_bracket = 2;
    my @items = ();
    my @item_parts_in_quote = ();
    my @item_parts_in_brackets = ();

    foreach my $part (split($sep, $buf)) {
        unless ($continuing) {
            if (substr($part, 0, 1) eq '"') {
                if (has_unquoted_tail_doublequote($part)) {
                    push @items, dequote($part);
                }
                else {
                    $continuing = $flag_in_quoted;
                    push @item_parts_in_quote, $part;
                }
            } elsif (substr($part, 0, 1) eq '[') {
                if (substr($part, -1, 1) eq ']') {
                    push @items, substr($part, 1, length($part) - 2);
                }
                else {
                    $continuing = $flag_in_bracket;
                    push @item_parts_in_brackets, $part;
                }
            } else {
                push @items, $part;
            }
            next
        }

        if ($continuing == $flag_in_quoted) {
            push @item_parts_in_quote, $part;
            next unless has_unquoted_tail_doublequote($part);

            push @items, dequote(join(' ', @item_parts_in_quote));
            @item_parts_in_quote = ();
            $continuing = 0;
        }
        elsif ($continuing == $flag_in_bracket) {
            push @item_parts_in_brackets, $part;
            next if substr($part, -1 , 1) ne ']';

            my $s = join(' ', @item_parts_in_brackets);
            push @items, substr($s, 1, length($s) - 2);
            @item_parts_in_brackets = ();
            $continuing = 0;
        } else {
            croak "invalid status about continuing: '$continuing'.";
        }
    }
    return @items;
}

sub set_strict_mode {
    my $self = shift;
    $self->{strict} = shift || 0;
}

sub parse_strict {
    my ($self, $line) = @_;
    chomp $line;
    foreach my $rule (@{$self->{try_maps}}) {
        my @values = separate_log_items($rule->[0], $line);
        next if scalar(@values) < 2;

        my $pairs = {};
        my $fnum = 0;
        foreach my $f (@{$rule->[1]}) {
            $pairs->{$f} = $values[$fnum];
            $fnum += 1;
        }
        next unless reduce { $a and defined($pairs->{$b}) } 1, qw( bytes status request datetime user logname rhost );

        ($pairs->{date}, $pairs->{time}, $pairs->{timezone}) = $pairs->{datetime} =~ m!([^: ]+):([^ ]+)\s([-+0-9]+)!;
        ($pairs->{method}, $pairs->{path}, $pairs->{proto}) = split(/ /, $pairs->{request}, 3);
        next unless reduce { $a and defined($pairs->{$b}) } 1, qw( proto path method timezone time date );

        next if defined($rule->[2]) and not $rule->[2]->($pairs);

        return $pairs;
    }
    carp "unknown format: $line";
    return undef;
}

sub parse {
    my ($self, $line) = @_;
    if ($self->{strict}) {
        return $self->parse_strict($line);
    }
    $self->parse_fast($line);
}

1;
