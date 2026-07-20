#!/bin/bash
#
# RFC9218 Priority Comparison Test
#
# This script demonstrates the difference between nginx with and without
# RFC9218 priority scheduling. Run against both vanilla nginx and RFC9218
# nginx to compare results.
#
# Prerequisites:
#   - nghttp (from nghttp2 package)
#   - tc bandwidth limiting (see below)
#   - nginx running on https://localhost:8443 serving a large file at /data.bin
#
# Setup bandwidth limiting (as root):
#   sudo tc qdisc add dev lo root handle 1: htb default 12
#   sudo tc class add dev lo parent 1: classid 1:12 htb rate 50mbit
#
# Remove bandwidth limiting:
#   sudo tc qdisc del dev lo root

URL_BASE="https://localhost:8443"

echo "========================================"
echo "RFC9218 Priority Test with nghttp"
echo "========================================"
echo ""
echo "Sending 6 requests with different priorities:"
echo "  Request 1: u=6 (LOW)    - should finish LAST with RFC9218"
echo "  Request 2: u=1 (HIGH)   - should finish FIRST with RFC9218"
echo "  Request 3: u=3 (MEDIUM)"
echo "  Request 4: u=6 (LOW)    - should finish LAST with RFC9218"
echo "  Request 5: u=1 (HIGH)   - should finish FIRST with RFC9218"
echo "  Request 6: u=3 (MEDIUM)"
echo ""
echo "All requests sent simultaneously on one HTTP/2 connection."
echo "With RFC9218: HIGH priority completes before LOW"
echo "Without RFC9218: Requests complete in stream ID order"
echo ""
echo "========================================"
echo ""

# Send 6 requests with different priorities
# --extpri sets RFC9218 priority for each URI in order
# -s shows statistics including timing
# -n discards output (we only care about timing)
nghttp -ns \
    --extpri="u=6" \
    --extpri="u=1" \
    --extpri="u=3" \
    --extpri="u=6" \
    --extpri="u=1" \
    --extpri="u=3" \
    "${URL_BASE}/data.bin?id=low1" \
    "${URL_BASE}/data.bin?id=high1" \
    "${URL_BASE}/data.bin?id=medium1" \
    "${URL_BASE}/data.bin?id=low2" \
    "${URL_BASE}/data.bin?id=high2" \
    "${URL_BASE}/data.bin?id=medium2"

echo ""
echo "========================================"
echo "Look at 'time for response' column above."
echo ""
echo "With RFC9218 nginx:"
echo "  - high1/high2 (u=1) should have lowest response times"
echo "  - low1/low2 (u=6) should have highest response times"
echo ""
echo "Without RFC9218 nginx:"
echo "  - Response times follow request order (low1 first, medium2 last)"
echo "========================================"
