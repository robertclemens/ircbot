#!/usr/bin/env bash
#
# bot-auth.sh — build a v1c (~A1c) AES-256-CBC + HMAC-SHA256 admin command
#               payload for ircbot. Uses ONLY openssl(1) and standard
#               coreutils. No Python, no Perl modules, no helper binary.
#
# Wire format produced:
#   ~A1c <base64( salt(16) || iv(16) || ciphertext || hmac(32) )>
#
# Key derivation:
#   keys = PBKDF2-HMAC-SHA256(password, salt, 100000, 64)
#   enc_key = keys[0..31]   mac_key = keys[32..63]
#
# Plaintext under the AES-CBC:
#   <unix_ts>:<nonce>:<command line>
#
# Auth:
#   hmac = HMAC-SHA256(mac_key, salt || iv || ciphertext)
#   (encrypt-then-MAC — bot verifies HMAC BEFORE attempting to decrypt)
#
# Usage:
#   BOT_AUTH_PASSWORD='hunter2' bot-auth.sh "die"
#   bot-auth.sh "+admin alice s3cret alice!*@trusted.example"   # prompts
#
# Requirements: openssl 1.1.1+ (any modern Linux/macOS, Git-for-Windows,
#               MSYS2, WSL). All other tools (xxd, base64, date) are in
#               the standard coreutils set that ships with bash.

set -euo pipefail

usage() {
    cat >&2 <<EOF
Usage: $0 "<command line, with args>"
Reads admin password from \$BOT_AUTH_PASSWORD or interactively.
Prints "~A1c <base64-blob>" to stdout — send to bot via:
    /quote PRIVMSG <bot_nick> :~A1c <base64-blob>
EOF
    exit 1
}

[ "$#" -eq 1 ] || usage
cmd_line="$1"

if [ -n "${BOT_AUTH_PASSWORD:-}" ]; then
    password="$BOT_AUTH_PASSWORD"
elif [ -t 0 ]; then
    read -r -s -p "Bot admin password: " password
    echo >&2
else
    read -r password
fi
[ -n "$password" ] || { echo "Error: empty password" >&2; exit 2; }

iterations=100000

# 16 bytes salt, 16 bytes IV (CBC standard), 8-byte nonce -> decimal
salt_hex=$(openssl rand -hex 16)
iv_hex=$(openssl rand -hex 16)
# 64-bit nonce, masked to int63 so the bot's strtoull -> int64 stays positive.
nonce_hex=$(openssl rand -hex 8)
nonce_dec=$(printf '%llu' "$((16#${nonce_hex} & 0x7FFFFFFFFFFFFFFF))")
ts=$(date -u +%s)

# Derive 64 bytes via PBKDF2-HMAC-SHA256, output as hex.
# OpenSSL 3.x has `openssl kdf PBKDF2`; OpenSSL 1.1.x can use the same
# primitive through `openssl enc -pbkdf2 -P` (it prints the derived
# key+IV; we want the full 64 bytes).
keys_hex=$(openssl kdf -keylen 64 \
                       -kdfopt digest:SHA256 \
                       -kdfopt pass:"$password" \
                       -kdfopt hexsalt:"$salt_hex" \
                       -kdfopt iter:"$iterations" \
                       -binary PBKDF2 2>/dev/null \
          | xxd -p -c 256 | tr -d '\n')
if [ -z "$keys_hex" ] || [ "${#keys_hex}" -ne 128 ]; then
    cat >&2 <<EOF
Error: 'openssl kdf -binary PBKDF2' did not produce 64 bytes.
       Your openssl: $(openssl version)
       This requires OpenSSL 3.0+. On older systems use the bot-auth helper
       binary (build from utils/bot-auth.c) or install Git for Windows /
       MSYS2 / a newer openssl package.
EOF
    exit 4
fi
enc_key="${keys_hex:0:64}"
mac_key="${keys_hex:64:64}"
unset keys_hex

# Encrypt plaintext with AES-256-CBC.  openssl enc adds PKCS#7 padding by
# default; with -K (hex key) and -iv (hex iv) it does NOT add the "Salted__"
# header that openssl normally puts on password-derived encryption.
ct_hex=$(printf '%s:%s:%s' "$ts" "$nonce_dec" "$cmd_line" \
    | openssl enc -aes-256-cbc -K "$enc_key" -iv "$iv_hex" \
    | xxd -p -c 4096 | tr -d '\n')
[ -n "$ct_hex" ] || { echo "Error: AES-CBC encrypt failed" >&2; exit 6; }

# HMAC-SHA256 over salt || iv || ciphertext, key = mac_key
hmac_hex=$(printf '%s%s%s' "$salt_hex" "$iv_hex" "$ct_hex" \
    | xxd -r -p \
    | openssl dgst -sha256 -mac HMAC -macopt "hexkey:$mac_key" \
    | awk '{print $NF}')
[ "${#hmac_hex}" -eq 64 ] || { echo "Error: HMAC produced ${#hmac_hex} hex chars" >&2; exit 7; }

# Assemble blob and base64 wrap.
b64=$({
    printf '%s' "$salt_hex"
    printf '%s' "$iv_hex"
    printf '%s' "$ct_hex"
    printf '%s' "$hmac_hex"
} | xxd -r -p | base64 -w0)

printf '~A1c %s\n' "$b64"
