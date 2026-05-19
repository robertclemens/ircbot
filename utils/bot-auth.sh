#!/usr/bin/env bash
#
# bot-auth.sh — build a v1 (~A1) AES-256-GCM admin command payload for ircbot.
#
# Usage:
#   bot-auth.sh "<command line, including args>"
#   echo "<password>" | bot-auth.sh -                     # password from stdin
#
# Prints a line of the form:
#   ~A1 <base64-blob>
#
# Send it to the bot via IRC as:
#   /quote PRIVMSG <bot_nick> :~A1 <base64-blob>
#
# Wire format (binary blob, base64-encoded above):
#   salt(16) || iv(12) || ciphertext(N) || tag(16)
#
# Key derivation:
#   key = PBKDF2-HMAC-SHA256(admin_password, salt, 100000, 32)
#
# Plaintext under the cipher:
#   <unix_ts>:<nonce>:<command> [args...]
#
# Requirements:
#   - openssl (1.1.1+) with -aes-256-gcm support
#   - GNU coreutils (od, base64, head)

set -euo pipefail

usage() {
    cat <<EOF
Usage: $0 "<command line, with args>"

Reads the admin/oper password from \$BOT_AUTH_PASSWORD or, if unset, prompts
on the controlling tty with echo disabled.

Examples:
    BOT_AUTH_PASSWORD='hunter2' $0 "die"
    $0 "+admin alice s3cret alice!*@trusted.example"
EOF
    exit 1
}

[ "$#" -eq 1 ] || usage
cmd_line="$1"

# Read password
if [ -n "${BOT_AUTH_PASSWORD:-}" ]; then
    password="$BOT_AUTH_PASSWORD"
elif [ -t 0 ]; then
    read -r -s -p "Bot admin password: " password
    echo >&2
else
    read -r password
fi
if [ -z "$password" ]; then
    echo "Error: empty password" >&2
    exit 2
fi

iterations=100000

# 16 bytes salt, 12 bytes IV (GCM standard), 8 bytes nonce (uint64 decimal)
salt_hex=$(openssl rand -hex 16)
iv_hex=$(openssl rand -hex 12)
nonce_hex=$(openssl rand -hex 8)

# Derive 32-byte key via PBKDF2-HMAC-SHA256, hex-encoded
key_hex=$(printf '%s' "$password" | \
    openssl kdf -keylen 32 -kdfopt digest:SHA256 \
                -kdfopt pass:"$password" \
                -kdfopt hexsalt:"$salt_hex" \
                -kdfopt iter:"$iterations" \
                -binary PBKDF2 2>/dev/null | xxd -p -c 64 | tr -d '\n')

# Older OpenSSL (1.1.1) lacks `openssl kdf`. Fall back to `openssl enc -pbkdf2`
# which uses the same primitive internally.
if [ -z "$key_hex" ]; then
    key_hex=$(printf '%s' "$password" | \
        openssl enc -aes-256-gcm -pbkdf2 -iter "$iterations" \
                    -S "$salt_hex" -md sha256 -P 2>/dev/null \
        | sed -n 's/^key=//p' | tr -d '\n')
fi
if [ -z "$key_hex" ] || [ "${#key_hex}" -ne 64 ]; then
    echo "Error: PBKDF2 key derivation failed (need openssl >=1.1.1 with PBKDF2)." >&2
    exit 3
fi

# Decimal nonce (drop the high bit so it fits in a positive int64 — matches
# the bot's strtoull parsing; signed math anywhere downstream stays safe).
nonce_dec=$(printf '%llu' "$((16#${nonce_hex} & 0x7FFFFFFFFFFFFFFF))")
ts=$(date -u +%s)
plaintext=$(printf '%s:%s:%s' "$ts" "$nonce_dec" "$cmd_line")

# Encrypt. openssl enc emits ciphertext; we then need to extract the tag.
# openssl enc with -aes-256-gcm does NOT output the tag separately in older
# versions, so use openssl's evp via a small helper. We use openssl's pipeline:
#   echo -n PLAINTEXT | openssl enc -aes-256-gcm -K <hex> -iv <hex> -nopad
# but that omits the tag. Use openssl 3.x's `-aead` option or compute via
# a Python/Perl one-liner. To keep this script dependency-light, use python3
# if available, otherwise fall back to perl.

encrypt_and_tag() {
    if command -v python3 >/dev/null 2>&1; then
        BOT_AUTH_PT="$plaintext" BOT_AUTH_KEY="$key_hex" BOT_AUTH_IV="$iv_hex" \
            python3 - <<'PY'
import binascii, os, sys
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
key = binascii.unhexlify(os.environ['BOT_AUTH_KEY'])
iv  = binascii.unhexlify(os.environ['BOT_AUTH_IV'])
pt  = os.environ['BOT_AUTH_PT'].encode('utf-8')
ct_and_tag = AESGCM(key).encrypt(iv, pt, None)
# ct_and_tag = ciphertext || tag(16)
sys.stdout.write(binascii.hexlify(ct_and_tag).decode('ascii'))
PY
    elif command -v perl >/dev/null 2>&1 && perl -MCrypt::AuthEnc::GCM -e1 2>/dev/null; then
        BOT_AUTH_PT="$plaintext" BOT_AUTH_KEY="$key_hex" BOT_AUTH_IV="$iv_hex" \
            perl <<'PL'
use strict;
use warnings;
use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate);
my $key = pack('H*', $ENV{BOT_AUTH_KEY});
my $iv  = pack('H*', $ENV{BOT_AUTH_IV});
my $pt  = $ENV{BOT_AUTH_PT};
my ($ct, $tag) = gcm_encrypt_authenticate('AES', $key, $iv, '', $pt);
print unpack('H*', $ct . $tag);
PL
    else
        echo "Error: need either python3 with 'cryptography' or perl with CryptX." >&2
        exit 4
    fi
}

ct_tag_hex=$(encrypt_and_tag)
if [ -z "$ct_tag_hex" ]; then
    echo "Error: GCM encryption failed." >&2
    exit 5
fi

# Assemble blob = salt || iv || ciphertext || tag and base64-encode
b64=$({
    printf '%s' "$salt_hex"
    printf '%s' "$iv_hex"
    printf '%s' "$ct_tag_hex"
} | xxd -r -p | base64 -w0)

printf '~A1 %s\n' "$b64"
