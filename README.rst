==========================
RFC9218 HTTP/2 Priority Demo
==========================

This demo visualizes RFC9218 Extensible Prioritization in action.

Prerequisites
=============

This demo requires nginx with RFC9218 support. As of writing, this is not
yet in mainline nginx. You'll need to apply the RFC9218 patchset.

**Get the patches from the pull request:**

https://github.com/nginx/nginx/pull/1520

**Apply with curl + git-am:**::

    cd /path/to/nginx
    curl -L https://github.com/nginx/nginx/pull/1520.patch | git am

**Or use the GitHub CLI:**::

    cd /path/to/nginx
    gh pr checkout 1520

Build nginx with the patches applied, then use this demo to verify the
implementation works correctly.

Two Test Modes
==============

The demo provides two ways to test RFC9218 priority:

1. **Browser Demo** - Visual progress bars showing resources loading in
   real-time. Note: Chrome does client-side priority scheduling, which can
   mask some server-side effects.

2. **nghttp Test** - Uses the ``nghttp`` command-line tool to send requests
   with explicit RFC9218 priorities on a single HTTP/2 connection. This
   provides the clearest demonstration of server-side priority scheduling.

Browser Compatibility
=====================

**Use Chrome/Chromium** for the browser demo. Firefox currently sends
``Priority: u=0`` for all requests regardless of the fetch API ``priority``
option, so priority effects won't be visible.

Chrome/Chromium properly maps fetch priority to RFC9218 urgency values:

- ``priority: 'high'`` → lower urgency value (higher priority)
- ``priority: 'low'`` → higher urgency value (lower priority)

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

5. **Start the test server** (for nghttp test button)::

       perl test-server.pl

6. Visit https://localhost:8443/ **in Chrome/Chromium**

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
- ``nginx.conf.example`` - Example nginx configuration
- ``test-server.pl`` - Perl backend for running nghttp tests from browser
- ``test-priority.sh`` - Standalone shell script for nghttp testing
- ``README.rst`` - This file
