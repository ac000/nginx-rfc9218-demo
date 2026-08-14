#!/usr/bin/env perl

# RFC9218 Priority Test Server
#
# Simple HTTP server that runs priority tests (nghttp for HTTP/2,
# j3ster for HTTP/3) and returns results.
#
# Run this alongside nginx on a different port (e.g., 8081).
#
# Usage:
#     perl test-server.pl
#
# Then fetch results from:
#     http://localhost:8081/run-test     (HTTP/2 via nghttp)
#     http://localhost:8081/run-test-h3  (HTTP/3 via j3ster)
#
# Requirements:
#     - JSON module (apt install libjson-perl, or cpan JSON)
#     - nghttp                  (for /run-test)
#     - ./j3ster/j3ster binary  (for /run-test-h3)

use strict;
use warnings;
use IO::Socket::INET;
use JSON;

my $PORT = 8081;
my $URL_BASE    = "https://localhost:8443";  # HTTP/2 only origin (nghttp)
my $URL_BASE_H3 = "https://localhost:8444";  # HTTP/3 origin      (j3ster)

sub parse_nghttp_output {
    my ($output) = @_;
    my @results;

    # Match lines like:
    #   3     +12.76s        +25us   12.76s  200  50M /data.bin?id=high1
    for my $line (split /\n/, $output) {
        if ($line =~ /^\s*(\d+)\s+\+?([\d.]+)s\s+\+?\d+.s\s+([\d.]+)s\s+(\d+)\s+\S+\s+\/data\.bin\?id=(\w+)/) {
            my ($stream_id, $response_end, $process_time, $status, $req_id) = ($1, $2, $3, $4, $5);

            my ($priority, $urgency);
            if ($req_id =~ /high/) {
                $priority = 'high';
                $urgency = 1;
            } elsif ($req_id =~ /medium/) {
                $priority = 'medium';
                $urgency = 3;
            } else {
                $priority = 'low';
                $urgency = 6;
            }

            push @results, {
                stream_id => int($stream_id),
                id        => $req_id,
                time      => $process_time + 0,
                priority  => $priority,
                urgency   => $urgency,
            };
        }
    }

    # Sort by completion time
    @results = sort { $a->{time} <=> $b->{time} } @results;

    # Add completion order
    my $order = 1;
    for my $r (@results) {
        $r->{order} = $order++;
    }

    return \@results;
}

sub run_nghttp_test {
    my @cmd = (
        'nghttp', '-ns',
        '--extpri=u=6',
        '--extpri=u=1',
        '--extpri=u=3',
        '--extpri=u=6',
        '--extpri=u=1',
        '--extpri=u=3',
        "$URL_BASE/data.bin?id=low1",
        "$URL_BASE/data.bin?id=high1",
        "$URL_BASE/data.bin?id=medium1",
        "$URL_BASE/data.bin?id=low2",
        "$URL_BASE/data.bin?id=high2",
        "$URL_BASE/data.bin?id=medium2",
    );

    my $output = `@cmd 2>&1`;
    my $exitcode = $? >> 8;

    my $parsed = parse_nghttp_output($output);

    return {
        success    => $exitcode == 0 ? JSON::true : JSON::false,
        results    => $parsed,
        raw_output => $output,
        returncode => $exitcode,
    };
}

# HTTP/3 test via j3ster.  Mirrors the nghttp scenario: six concurrent
# requests, two each at u=1 (high), u=3 (medium), u=6 (low).  j3ster
# already emits per-stream JSON (finish_ms, finish_order, priority,
# path, status).  We map its output to the same shape as the nghttp
# path so the front-end can reuse its rendering.
sub run_j3ster_test {
    my $j3ster = "./j3ster/j3ster";

    unless (-x $j3ster) {
        return {
            success    => JSON::false,
            results    => [],
            raw_output => "j3ster binary not found at $j3ster - run 'make' in ./j3ster/",
            returncode => 127,
        };
    }

    my @cmd = (
        $j3ster, '-j',
        '-r', 'u=6:/data.bin?id=low1',
        '-r', 'u=1:/data.bin?id=high1',
        '-r', 'u=3:/data.bin?id=medium1',
        '-r', 'u=6:/data.bin?id=low2',
        '-r', 'u=1:/data.bin?id=high2',
        '-r', 'u=3:/data.bin?id=medium2',
        '127.0.0.1', '8444',
    );

    # capture stdout only; keep stderr in the raw output for diagnostics
    my $output = `@cmd 2>&1`;
    my $exitcode = $? >> 8;

    my @results;
    my $j3;
    if ($output =~ /(\{.*\})/s) {
        eval { $j3 = decode_json($1); };
    }

    if ($j3 && ref($j3->{streams}) eq 'ARRAY') {
        for my $s (@{$j3->{streams}}) {
            my $path = $s->{path} // '';
            my ($req_id) = $path =~ /\bid=([A-Za-z0-9_]+)/;
            $req_id //= "stream$s->{stream_id}";

            my ($priority, $urgency);
            if ($req_id =~ /high/) {
                $priority = 'high';  $urgency = 1;
            } elsif ($req_id =~ /medium/) {
                $priority = 'medium'; $urgency = 3;
            } else {
                $priority = 'low';   $urgency = 6;
            }

            push @results, {
                stream_id => int($s->{stream_id} // 0),
                id        => $req_id,
                time      => ($s->{finish_ms} // 0) / 1000.0,
                priority  => $priority,
                urgency   => $urgency,
                order     => int($s->{finish_order} // 0),
            };
        }

        # ensure ordered by completion time (matches nghttp path)
        @results = sort { $a->{time} <=> $b->{time} } @results;
        my $o = 1;
        $_->{order} = $o++ for @results;
    }

    return {
        success    => ($exitcode == 0 && @results) ? JSON::true : JSON::false,
        results    => \@results,
        raw_output => $output,
        returncode => $exitcode,
    };
}

sub handle_request {
    my ($client) = @_;

    # Read request
    my $request = '';
    while (my $line = <$client>) {
        $request .= $line;
        last if $line =~ /^\r?\n$/;
    }

    # Parse request line
    my ($method, $path) = $request =~ /^(\w+)\s+(\S+)/;
    $path //= '/';

    print "[test-server] $method $path\n";

    my ($status, $body);

    if ($path eq '/run-test') {
        my $result = run_nghttp_test();
        $status = "200 OK";
        $body = encode_json($result);
    } elsif ($path eq '/run-test-h3') {
        my $result = run_j3ster_test();
        $status = "200 OK";
        $body = encode_json($result);
    } else {
        $status = "404 Not Found";
        $body = '{"error": "Not found"}';
    }

    my $response = "HTTP/1.1 $status\r\n";
    $response .= "Content-Type: application/json\r\n";
    $response .= "Access-Control-Allow-Origin: *\r\n";
    $response .= "Content-Length: " . length($body) . "\r\n";
    $response .= "Connection: close\r\n";
    $response .= "\r\n";
    $response .= $body;

    print $client $response;
}

# Main
my $server = IO::Socket::INET->new(
    LocalPort => $PORT,
    Type      => SOCK_STREAM,
    Reuse     => 1,
    Listen    => 10,
) or die "Cannot create server: $!\n";

print "Starting test server on port $PORT\n";
print "HTTP/2 (nghttp):    http://localhost:$PORT/run-test\n";
print "HTTP/3 (j3ster):    http://localhost:$PORT/run-test-h3\n";

while (my $client = $server->accept()) {
    handle_request($client);
    close($client);
}

close($server);
