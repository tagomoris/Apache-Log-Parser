#!/usr/local/bin/perl
use strict;
use warnings;
use Benchmark qw/timethese cmpthese/;

use Ax::ApacheLogParser;
use ApacheLog::Parser qw/parse_line_to_hash/;

my $logline = q{localhost.local - - [04/Oct/2007:12:34:56 +0900] "GET /apache_pb.gif HTTP/1.1" 200 2326 "http://www.dan.co.jp/" "Mozilla/5.0 (Macintosh; U; Intel Mac OS X; en-US; rv:1.8.1.7) Gecko/20070914 Firefox/2.0.0.7" "localhost" "127.0.0.1201102081601001" "000-mobilehost.any" 1280};

my (@logline) =
    ( $logline =~
          m!^(.*) (.*) (.*) (\[.*\]) (\".*\") (.*) (.*) (\".*\") (\".*\") (\".*\") (\".*\") (\".*\") (.*)! );

my $combined = join " ", ($1, $2, $3, $4, $5, $6, $7, $8, $9);

my $tsv = join "\t", @logline;

my @customized_fields = qw( rhost logname user datetime request status bytes refer agent vhost usertrack mobileid request_duration );
my $parser_strict = Ax::ApacheLogParser->new( strict => [
    ["\t", \@customized_fields, sub{my $x=shift;defined($x->{vhost}) and defined($x->{usertrack}) and defined($x->{mobileid})}],
    [" ", \@customized_fields, sub{my $x=shift;defined($x->{vhost}) and defined($x->{usertrack}) and defined($x->{mobileid})}],
    'combined',
    'common',
    'vhost_common'
]);
my $parser_fast = Ax::ApacheLogParser->new( fast => [[qw(refer agent vhost usertrack mobileid request_duration)], 'combined', 'common']);
my $parser_combined = Ax::ApacheLogParser->new( fast => 1 );
cmpthese(
    timethese(
        0,
        {
            rx_optim => sub {
                my (@l) =
                    ( $logline =~
                          m!^([^\s]*) ([^\s]*) ([^\s]*) \[([^: ]+):([^ ]+) ([-+0-9]+)\]\s+"(\w+) ([^\s]*) ([^\s]*)"\s+([^\s]*)\s+([^\s]*)\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"\s+"([^"]*)"\s+(\d+)!
                      );
            },
            rx_half_optim => sub {
                my (@l) =
                    ( $logline =~
                          m!^([^\s]*) ([^\s]*) ([^\s]*) \[([^: ]+):([^ ]+) ([-+0-9]+)\]\s+"(\w+) ([^\s]*) ([^\s]*)"\s+([^\s]*)\s+([^\s]*)(\s+"([^"]*)")?(\s+"([^"]*)")?(\s+"([^"]*)")?(\s+"([^"]*)")?(\s+"([^"]*)")?(\s+(\d+))?!
                      );
            },
            # tsv_split => sub { my (@l) = split /\t/, $tsv },
            # tsv_split_parse => sub { my (@l) = split /\t/, $tsv ;
            #                         foreach my $l (@l) {
            #                              if (substr($l, 0, 1) eq '"') {
            #                                  substr($l, 1, length($l) - 2);
            #                              }
            #                          }
            #                          my (@dates) = ($l[4] =~ m!([^: ]+):([^ ]+)\s([-+0-9]+)!);
            #                          my (@reqs) = split(/ /, $l[5], 3);
            #                      },
            # parser_strict_space => sub { my $log = $parser_strict->parse($logline); },
            # parser_strict_tsv => sub { my $log = $parser_strict->parse($tsv); },
            parser_fast_space => sub { my $log = $parser_fast->parse($logline); },
            # parser_fast_tsv => sub { my $log = $parser_fast->parse($tsv); },
            parser_fast_combined => sub { my $log = $parser_combined->parse($combined); },
            apachelog_parser => sub { my %hash = parse_line_to_hash($combined); },
        }
    )
);
