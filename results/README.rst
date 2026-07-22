Overview
========

These are screenshots of runs of the demo. All were done with Chromium.

There are two tests each done with and without the RFC9218 patches.

Within each set of two there is one each for the direct browser test and
the nghttp backend test, this really shows the prioritisation in effect
as Chromium also does it's own priority scheduling.

So there is

chromium-nginx-without-rfc9218-browser.png
------------------------------------------

Chromium doing the direct browser test against nginx *without* the
RFC9218 patches.

chromium-nginx-without-rfc9218-nghttp.png
-----------------------------------------

Chromium doing the nghttp test against nginx *without* the RFC9218
patches.

v3-2-chromium-nginx-with-rfc9218-browser.png
--------------------------------------------

Chromium doing the direct browser test against nginx *with* the RFC9218
patches.

v3-2-chromium-nginx-with-rfc9218-nghttp.png
-------------------------------------------

Chromium doing the nghttp test against nginx *with* the RFC9218 patches.
