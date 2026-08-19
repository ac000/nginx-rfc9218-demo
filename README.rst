==========================
RFC9218 HTTP/2 & HTTP/3 Priority Demo
==========================

This demo visualizes RFC9218 Extensible Prioritization in action, over
both HTTP/2 and HTTP/3.

Prerequisites
=============

This demo requires nginx with RFC9218 support. As of writing, this is not
yet in mainline nginx. You'll need to apply the RFC9218 patchset.

**Get the patches from the pull request:**

<https://github.com/nginx/nginx/pull/1657> HTTP/3 + HTTP/2 or
<https://github.com/nginx/nginx/pull/1520> HTTP/2

**Apply with curl + git-am:**::

    cd /path/to/nginx
    curl -L https://github.com/nginx/nginx/pull/1520.patch | git am

**Or use the GitHub CLI:**::

    cd /path/to/nginx
    gh pr checkout 1520

Build nginx with the patches applied, then use this demo to verify the
implementation works correctly.

Three Test Modes
================

The demo provides three ways to test RFC9218 priority:

1. **Browser Demo** - Visual progress bars showing resources loading in
   real-time. The page reports the negotiated protocol per request via
   the ``PerformanceResourceTiming.nextHopProtocol`` API. To force a
   specific protocol, use the "switch origin" links in the top banner:

   - ``https://localhost:8443/`` - HTTP/2 only (no QUIC listen, no
     ``Alt-Svc``). Reliable for repeated HTTP/2 measurements.
   - ``https://localhost:8444/`` - HTTP/3 preferred (advertises
     ``Alt-Svc: h3=":8444"``). Chrome uses HTTP/2 on the first load and
     switches to HTTP/3 on subsequent loads once ``Alt-Svc`` is cached.

   Note: Chrome does client-side priority scheduling, which can mask some
   server-side effects.

2. **nghttp Test (HTTP/2)** - Uses the ``nghttp`` command-line tool
   against ``:8443`` (HTTP/2 only) to send 6 concurrent requests with
   explicit RFC9218 priorities on a single HTTP/2 connection.

3. **j3ster Test (HTTP/3)** - Uses the bundled ``j3ster`` HTTP/3 client
   (see ``j3ster/``) against ``:8444`` to send the same 6-request
   priority scenario over a single QUIC connection. This exercises the
   HTTP/3 priority path directly, independent of the browser.

Browser Compatibility
=====================

**Use Chrome/Chromium** for the browser demo. Firefox currently sends
``Priority: u=0`` for all requests regardless of the fetch API ``priority``
option, so priority effects won't be visible.

Chrome/Chromium properly maps fetch priority to RFC9218 urgency values:

- ``priority: 'high'`` → lower urgency value (higher priority)
- ``priority: 'low'`` → higher urgency value (lower priority)

Enabling HTTP/3 with a self-signed certificate
==============================================

Chrome will not use HTTP/3 (QUIC) to an origin whose TLS certificate is
not fully trusted, even after clicking through the HTTP/2 "Not private"
warning. The older ``--ignore-certificate-errors`` flag is no longer
sufficient (recent Chromium versions display an "unsupported flag"
banner and reject QUIC handshakes with ``ERR_QUIC_PROTOCOL_ERROR``).

The demo ships a helper script that:

1. Computes the SubjectPublicKeyInfo SHA-256 hash of your demo cert.
2. Locates ``chromium`` / ``chromium-browser`` / ``google-chrome`` in
   ``PATH``.
3. Launches it in a throw-away profile
   (``--user-data-dir=/tmp/chrome-quic-demo``) with:

   - ``--origin-to-force-quic-on=localhost:8444`` to skip Alt-Svc
     racing and connect directly over QUIC.
   - ``--ignore-certificate-errors-spki-list=<HASH>`` which is the
     supported way to accept a specific self-signed cert (including on
     QUIC).

Run it as::

    ./chrome-quic-launch.sh                            # defaults
    ./chrome-quic-launch.sh /path/to/cert.pem          # custom cert
    ./chrome-quic-launch.sh /path/to/cert.pem https://localhost:8444/

.. note::

   Chromium will display a yellow bar reading
   *"--ignore-certificate-errors-spki-list is an unsupported flag"*.
   That warning is cosmetic - the flag IS honoured and QUIC connects
   fine.  You can ignore/dismiss the bar.

The per-request badge on each resource row and the "Last run
protocol(s)" summary in the top banner will confirm ``h3`` was used.

Quick Setup
===========

1. **Generate SSL certificates** (required for HTTP/2)::

       openssl req -x509 -newkey rsa:2048 -keyout key.pem -out cert.pem \
           -days 365 -nodes -subj '/CN=localhost'

2. **Generate test data file** (50MB)::

       dd if=/dev/urandom of=data.bin bs=1M count=50

3. **Use the example nginx.conf** (update paths as needed)::

       nginx -c /path/to/nginx.conf.example

4. **Add network bandwidth limiting** (required to see priority effects)::

       # Limit loopback to 50mbit/s (run as root)
       sudo tc qdisc add dev lo root handle 1: htb default 12
       sudo tc class add dev lo parent 1: classid 1:12 htb rate 50mbit

       # To remove limit after demo:
       sudo tc qdisc del dev lo root

5. **Start the test server** (for the nghttp and j3ster test buttons)::

       perl test-server.pl

6. **Build j3ster** (for the HTTP/3 test button)::

       cd j3ster && make

   Requires libngtcp2, libngtcp2_crypto_ossl, libnghttp3 and
   OpenSSL 3.5+ (native QUIC TLS API).

7. Visit https://localhost:8443/ **in Chrome/Chromium**

Why Network Limiting is Needed
==============================

RFC9218 priority scheduling determines which stream's DATA frames get sent
first when there's **connection-level congestion**. On a fast localhost
without bandwidth limiting, all streams complete too quickly to see the
priority effect.

How It Works
============

The demo requests 6 resources simultaneously, each with a different
RFC9218 priority level:

- **u=1** (High) - Should complete first
- **u=3** (Medium) - Default priority
- **u=6** (Low) - Should complete last

With RFC9218 enabled, nginx schedules higher-urgency DATA frames before
lower-urgency ones, so high-priority resources complete faster despite
being requested at the same time.

Expected Results
================

With RFC9218 working correctly, high-urgency streams complete before
low-urgency ones:

1. u=1 (high) resources complete before u=6 (low) resources
2. u=3 (medium) resources complete before u=6 (low) resources
3. u=6 (low) resources complete last

.. note::

   There may be some variability in the exact completion order due to:

   1. **Incremental flag**: Chrome sends the ``i`` (incremental) flag on all
      requests, which tells the server that interleaving streams at the same
      urgency level is acceptable.

   2. **Data already in flight**: Once nginx writes DATA frames to the
      kernel's TCP buffer, it loses control over them. Data already in the
      kernel buffer will be sent even if a higher-priority stream becomes
      ready.

   3. **Timing**: The exact moment each stream's response data becomes ready
      affects when its frames enter the priority queue.

   You may see ordering like: high1 → medium1 → high2 → medium2 → low1 → low2

The key indicator is that **all low-priority resources finish last**.

Files
=====

- ``index.html`` - Demo visualization page
- ``data.bin`` - Test data file (generate with ``dd if=/dev/urandom of=data.bin bs=1M count=50``)
- ``nginx.conf.example`` - Example nginx configuration (HTTP/2 + HTTP/3)
- ``test-server.pl`` - Perl backend for the nghttp and j3ster test buttons
- ``test-priority.sh`` - Standalone shell script for nghttp testing
- ``chrome-quic-launch.sh`` - Launch Chromium in a throw-away profile that trusts the demo cert on QUIC
- ``j3ster/`` - Minimal HTTP/3 client for RFC 9218 priority testing
- ``README.rst`` - This file
