#!/usr/bin/env bash

set -euo pipefail

PROXY_HOST="127.0.0.1"
PROXY_PORT="7777"

VLC_OPTIONS=(
    --network-caching=0
    --clock-jitter=0
    --clock-synchro=0
    --live-caching=0
)

STREAM_URI="udp://@${PROXY_HOST}:${PROXY_PORT}"

echo "Connecting VLC to ${STREAM_URI} …"
exec vlc "${VLC_OPTIONS[@]}" "${STREAM_URI}"
