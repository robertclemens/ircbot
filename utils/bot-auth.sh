#!/bin/bash
if [ -z "$1" ]; then echo "Usage: $0 \"<password>\""; exit 1; fi
TIME_MINUTE=$(($(date +%s) / 60))
HASH=$(echo -n "${1}:${TIME_MINUTE}" | sha256sum | head -c 64)
echo "Your one-time hash for the next 60 seconds is:"
echo "$HASH"
