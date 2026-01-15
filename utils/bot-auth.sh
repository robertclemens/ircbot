#!/bin/bash
if [ -z "$1" ]; then echo "Usage: $0 \"<password>\""; exit 1; fi
NONCE=$RANDOM
TIME_MINUTE=$(($(date +%s) / 60))
HASH=$(echo -n "${1}:${TIME_MINUTE}:${NONCE}" | sha256sum | head -c 64)
echo "Your one-time hash for the next 60 seconds is:"
echo "$NONCE:$HASH"
