#!/usr/bin/env bash

set -euo pipefail

PROXY_HOST="127.0.0.1"
PROXY_PORT="7777"

MPV_OPTIONS=(
    --cache=no
    --profile=low-latency
)

STREAM_URI="udp://${PROXY_HOST}:${PROXY_PORT}"

echo "Connecting to ${STREAM_URI} …"
exec mpv "${MPV_OPTIONS[@]}" "${STREAM_URI}" 2>/dev/null
