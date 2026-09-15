"""ircbot_weechat_auth.py — v2 (~A2/~A2A/~A2K) key-based admin-command client
for ircbot, WeeChat edition.  There are no passwords: each admin/oper has an
Ed25519+X25519 keypair (ircbot/utils/keygen), and the bot only ever learns
the *public* half.

Protocol (must match commands.c / crypto.c exactly — see
irchub/docs/passwordless.md #4): on the first command to a bot this script
signs a "~A2A <sig> <ts>:<nonce>" request with your Ed25519 key; the bot
replies with a NOTICE "~A2K <b64>" carrying its own public key, sealed
(X25519 ECDH + HKDF-SHA256 + AES-256-GCM) to your X25519 key and bound to
that request's ts:nonce.  Once that lockbox is opened and cached, every admin
command travels as a fresh "~A2 <b64>" PRIVMSG: a per-command X25519
ephemeral key is mixed with your static key so the bot can both decrypt and
authenticate the sender.  ~A2K notices are protocol traffic and are always
hidden from the chat window.

Dependency:  pip install cryptography      (or: apt install python3-cryptography)
All crypto runs in-process: your private key material never reaches a
command line, an environment variable, or a temp file, and this script never
shells out to openssl(1) or any other external program.

Install:
    cp ircbot_weechat_auth.py ~/.weechat/python/     (or ~/.local/share/weechat/python/)
    /python load ircbot_weechat_auth.py

Setup:
    1. Make a keypair with ircbot/utils/keygen (or irchub/bin/keygen); give
       the bot admin the .public.b64 contents, keep the .private.b64 to
       yourself and `chmod 600` it -- this script warns (but still runs) if
       it is not.
    2. /set plugins.var.python.ircbot_weechat_auth.keyfile /home/you/NAME.private.b64
    3. Optionally pin bots to their key:
       /set plugins.var.python.ircbot_weechat_auth.pinfile /home/you/.ircbot_bot_pins
       (chmod 600 on first write; leaving this empty, the default, disables pinning)
    4. From a buffer on the bot's network: /botcmd <bot_nick> <command> [args...]

Usage:
    /botcmd   <bot_nick> <command> [args...]   - auto-authenticates, then sends
    /botauth  <bot_nick>                       - drop the cached key, re-auth now
    /botforget <bot_nick>                      - drop the cached key (and pin)

Compare a bot's key fingerprint (printed here on every successful auth)
against that bot's own 'status' output or hub_admin's bot list before
trusting it for the first time.
"""

import base64
import hashlib
import os
import time
from collections import namedtuple

import weechat
# Imported defensively so a missing dependency shows one actionable line in the
# client instead of an ImportError traceback at load time.
try:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives.asymmetric.x25519 import (
        X25519PrivateKey, X25519PublicKey)
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
    CRYPTO_OK = True
except ImportError:
    CRYPTO_OK = False

CRYPTO_HINT = ("bot_auth: the 'cryptography' module is not installed — this "
               "script cannot do the Curve25519/AES-GCM handshake without it. "
               "Install one of:  sudo apt install python3-cryptography  |  "
               "pip install cryptography")

SCRIPT_NAME = "ircbot_weechat_auth"
SCRIPT_AUTHOR = "rclemens"
SCRIPT_VERSION = "6.0.0"
SCRIPT_LICENSE = "Public Domain"
SCRIPT_DESC = "Sends ~A2 admin commands to ircbot (Curve25519 + AES-256-GCM, passwordless)"

AUTH_TIMEOUT = 60     # seconds a pending ~A2A stays valid
MAX_QUEUE = 5         # queued commands per bot while authenticating

ClientKey = namedtuple("ClientKey",
                        ["ed_priv", "x_priv", "ed_pub", "x_pub", "pub64", "warning"])

# =============================================================================
# Pure protocol functions — no `weechat` calls anywhere below this line down
# to the "Pin-file helpers" section. Callable standalone by a test harness
# that has stubbed `weechat` into sys.modules before import.
#
# Note on memory hygiene: Python `bytes` are immutable, so shared secrets,
# derived keys, and decrypted plaintext returned by the `cryptography`
# library cannot be reliably zeroed in-process the way the Perl/C
# implementations do (a `bytearray` copy could be wiped, but the original
# immutable object handed back by the library would still linger until the
# garbage collector reclaims it).  This is a known limitation of doing crypto
# in pure Python; keep the process lifetime short and the keyfile chmod 600.
# =============================================================================

_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_LOWER = "abcdefghijklmnopqrstuvwxyz"
_LC_TABLE = str.maketrans(_UPPER, _LOWER)


def _lc(s):
    """ASCII-only lowercase: A-Z -> a-z, every other character unchanged."""
    return s.translate(_LC_TABLE)


def load_key(path):
    """Load the combined Ed25519+X25519 private key from `path` (first line,
    standard base64 with padding, decoding to exactly 64 bytes: ed_priv(32)
    || x_priv(32)).  Returns a ClientKey.  Raises ValueError/OSError on any
    failure.  `.warning` is a mode-permission message, or None.
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw_line = fh.readline()
    raw_b64 = raw_line.strip()
    if not raw_b64:
        raise ValueError("keyfile '%s' is empty" % path)
    try:
        raw = base64.b64decode(raw_b64, validate=True)
    except Exception as exc:
        raise ValueError("keyfile '%s': invalid base64 (%s)" % (path, exc)) from exc
    if len(raw) != 64:
        raise ValueError("keyfile '%s': decoded key must be 64 bytes, got %d"
                          % (path, len(raw)))

    ed_priv, x_priv = raw[:32], raw[32:64]
    ed_pub = Ed25519PrivateKey.from_private_bytes(ed_priv).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    x_pub = X25519PrivateKey.from_private_bytes(x_priv).public_key().public_bytes(
        Encoding.Raw, PublicFormat.Raw)
    pub64 = base64.b64encode(ed_pub + x_pub).decode("ascii")

    warning = None
    try:
        st = os.stat(path)
        if st.st_mode & 0o077:
            warning = ("keyfile '%s' is mode %04o — chmod 600 it"
                       % (path, st.st_mode & 0o7777))
    except OSError:
        pass

    return ClientKey(ed_priv=ed_priv, x_priv=x_priv, ed_pub=ed_pub, x_pub=x_pub,
                     pub64=pub64, warning=warning)


def fingerprint(pub64):
    """"ab12:cd34:ef56:7890" — first 8 bytes of SHA-256(pub64), where pub64 is
    the raw 64-byte combined public key (ed_pub(32) || x_pub(32))."""
    h = hashlib.sha256(pub64).digest()[:8]
    hexstr = h.hex()
    return ":".join(hexstr[i:i + 4] for i in range(0, 16, 4))


def build_auth(key, botnick, mynick):
    """Build one ~A2A auth request.  Returns (line, tsn)."""
    nonce = os.urandom(8).hex()   # 16 lowercase hex chars
    tsn = "%d:%s" % (int(time.time()), nonce)
    msg = (b"ircbot-A2A-v1\0" + _lc(botnick).encode("utf-8") + b"\0" +
           _lc(mynick).encode("utf-8") + b"\0" + tsn.encode("ascii"))
    sig = Ed25519PrivateKey.from_private_bytes(key.ed_priv).sign(msg)
    line = "~A2A " + base64.b64encode(sig).decode("ascii") + " " + tsn
    return line, tsn


def open_lockbox(key, botnick, mynick, tsn, b64):
    """Open a ~A2K lockbox.  `tsn` must be the ts:nonce of the pending request
    this reply answers.  Returns the bot's raw 64-byte combined public key on
    success, or None on any failure (malformed frame, bad point, wrong tag).
    """
    try:
        frame = base64.b64decode(b64, validate=True)
    except Exception:
        return None
    if len(frame) != 124:
        return None
    eph, iv, ct, tag = frame[0:32], frame[32:44], frame[44:108], frame[108:124]

    try:
        ss = X25519PrivateKey.from_private_bytes(key.x_priv).exchange(
            X25519PublicKey.from_public_bytes(eph))
    except Exception:
        return None
    if ss == b"\x00" * 32:   # reject a low-order point
        return None

    info = b"ircbot-A2K-v1" + key.x_pub
    km = HKDF(algorithm=hashes.SHA256(), length=32, salt=eph, info=info).derive(ss)

    aad = (b"ircbot-A2K-v1\0" + _lc(botnick).encode("utf-8") + b"\0" +
           _lc(mynick).encode("utf-8") + b"\0" + tsn.encode("ascii"))
    try:
        pt = AESGCM(km).decrypt(iv, ct + tag, aad)
    except Exception:
        return None
    if len(pt) != 64:
        return None
    return pt


def build_command(key, bot_pub64, botnick, mynick, command):
    """Build one ~A2 sealed command.  `bot_pub64` is the bot's raw 64-byte
    combined public key (as returned by open_lockbox).  Returns the line to
    send.  Raises ValueError if the command must be refused (control byte,
    or the finished line would exceed the 400-char budget)."""
    if any(b < 0x20 or b == 0x7F for b in command.encode("utf-8")):
        raise ValueError("command contains a control character")

    nonce = os.urandom(8).hex()
    pt = ("%d:%s:%s" % (int(time.time()), nonce, command)).encode("utf-8")

    bot_x_pub = bot_pub64[32:64]
    eph_priv = X25519PrivateKey.generate()
    eph_pub = eph_priv.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)

    dh1 = eph_priv.exchange(X25519PublicKey.from_public_bytes(bot_x_pub))
    dh2 = X25519PrivateKey.from_private_bytes(key.x_priv).exchange(
        X25519PublicKey.from_public_bytes(bot_x_pub))
    if dh1 == b"\x00" * 32 or dh2 == b"\x00" * 32:
        raise ValueError("key exchange produced a degenerate shared secret")

    info = b"ircbot-A2-v1" + key.x_pub + bot_x_pub
    km = HKDF(algorithm=hashes.SHA256(), length=32, salt=eph_pub, info=info).derive(dh1 + dh2)

    iv = os.urandom(12)
    aad = (b"ircbot-A2-v1\0" + _lc(botnick).encode("utf-8") + b"\0" +
           _lc(mynick).encode("utf-8"))
    ct_tag = AESGCM(km).encrypt(iv, pt, aad)

    frame = eph_pub + iv + ct_tag
    line = "~A2 " + base64.b64encode(frame).decode("ascii")
    if len(line) > 400:
        raise ValueError("command is too long (%d > 400 chars on the wire)" % len(line))
    return line


# =============================================================================
# Pin-file helpers.  Plain file I/O, no `weechat` calls.
# =============================================================================

def pin_lookup(pinfile, bot_lc):
    try:
        with open(pinfile, "r", encoding="utf-8") as fh:
            for line in fh:
                parts = line.strip().split(" ", 1)
                if len(parts) == 2 and parts[0] == bot_lc:
                    return parts[1]
    except OSError:
        pass
    return None


def pin_add(pinfile, bot_lc, pub_b64):
    is_new = not os.path.exists(pinfile)
    fd = os.open(pinfile, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    with os.fdopen(fd, "a", encoding="utf-8") as fh:
        fh.write("%s %s\n" % (bot_lc, pub_b64))
    if is_new:
        try:
            os.chmod(pinfile, 0o600)
        except OSError:
            pass


def pin_remove(pinfile, bot_lc):
    try:
        with open(pinfile, "r", encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return
    kept = [ln for ln in lines if ln.strip().split(" ", 1)[:1] != [bot_lc]]
    if len(kept) != len(lines):
        with open(pinfile, "w", encoding="utf-8") as fh:
            fh.writelines(kept)


# =============================================================================
# WeeChat glue.  Everything below touches `weechat`.  WeeChat callbacks are
# registered (and invoked) by function *name*, not by reference.
# =============================================================================

_KEY_CACHE = {}   # (server, bot_lc) -> bot_pub64 (raw 64 bytes)
_PENDING = {}     # same key         -> (tsn, send_time)
_QUEUE = {}       # same key         -> [command_line, ...]


def _load_key_pref():
    path = weechat.config_get_plugin("keyfile")
    if not path:
        return None, ("no keyfile set — /set plugins.var.python.%s.keyfile <path>"
                      % SCRIPT_NAME)
    try:
        return load_key(path), None
    except Exception as exc:                      # noqa: BLE001 - report to user
        return None, "keyfile error: %s" % exc


def _expire_pending(ck):
    pend = _PENDING.get(ck)
    if not pend or time.time() - pend[1] <= AUTH_TIMEOUT:
        return
    del _PENDING[ck]
    q = _QUEUE.pop(ck, None)
    if q:
        weechat.prnt("", "bot_auth: auth with %s timed out; dropped %d queued command(s)."
                     % (ck[1], len(q)))


def _send_line(buffer, server, bot_nick, line):
    weechat.command(buffer or "", "/quote -server %s PRIVMSG %s :%s" % (server, bot_nick, line))


def _send_auth(buffer, server, mynick, bot_nick, key):
    try:
        line, tsn = build_auth(key, bot_nick, mynick)
    except Exception as exc:                      # noqa: BLE001 - report to user
        weechat.prnt("", "bot_auth: failed to build auth request: %s" % exc)
        return
    _PENDING[(server, _lc(bot_nick))] = (tsn, time.time())
    _send_line(buffer, server, bot_nick, line)
    weechat.prnt("", "bot_auth: authenticating with %s..." % bot_nick)


def _send_command(buffer, server, mynick, key, bot_nick, bot_pub64, command_line):
    try:
        line = build_command(key, bot_pub64, bot_nick, mynick, command_line)
    except ValueError as exc:
        weechat.prnt("", "bot_auth: %s" % exc)
        return
    _send_line(buffer, server, bot_nick, line)


def _handle_botcmd(buffer, server, mynick, bot_nick, command_line):
    key, err = _load_key_pref()
    if err:
        weechat.prnt("", "bot_auth: %s" % err)
        return
    if key.warning:
        weechat.prnt("", "bot_auth: %s" % key.warning)

    ck = (server, _lc(bot_nick))
    _expire_pending(ck)

    bot_pub64 = _KEY_CACHE.get(ck)
    if bot_pub64:
        _send_command(buffer, server, mynick, key, bot_nick, bot_pub64, command_line)
        return

    q = _QUEUE.setdefault(ck, [])
    if len(q) >= MAX_QUEUE:
        weechat.prnt("", "bot_auth: queue for %s is full (max %d); dropping oldest."
                     % (bot_nick, MAX_QUEUE))
        q.pop(0)
    q.append(command_line)

    if ck in _PENDING:
        weechat.prnt("", "bot_auth: already authenticating with %s; command queued." % bot_nick)
        return
    _send_auth(buffer, server, mynick, bot_nick, key)


def cb_botcmd(data, buffer, args):
    if not CRYPTO_OK:
        weechat.prnt("", CRYPTO_HINT)
        return weechat.WEECHAT_RC_OK

    parts = args.split(None, 1)
    if len(parts) < 2:
        weechat.prnt("", "Usage: /botcmd <bot_nick> <command> [args...]")
        return weechat.WEECHAT_RC_OK

    server = weechat.buffer_get_string(buffer, "localvar_server")
    if not server:
        weechat.prnt("", "bot_auth: run /botcmd from a buffer on the bot's network.")
        return weechat.WEECHAT_RC_OK

    mynick = weechat.info_get("irc_nick", server) or ""
    _handle_botcmd(buffer, server, mynick, parts[0], parts[1])
    return weechat.WEECHAT_RC_OK


def cb_botauth(data, buffer, args):
    if not CRYPTO_OK:
        weechat.prnt("", CRYPTO_HINT)
        return weechat.WEECHAT_RC_OK

    bot_nick = args.strip()
    if not bot_nick:
        weechat.prnt("", "Usage: /botauth <bot_nick>")
        return weechat.WEECHAT_RC_OK

    server = weechat.buffer_get_string(buffer, "localvar_server")
    if not server:
        weechat.prnt("", "bot_auth: run /botauth from a buffer on the bot's network.")
        return weechat.WEECHAT_RC_OK

    key, err = _load_key_pref()
    if err:
        weechat.prnt("", "bot_auth: %s" % err)
        return weechat.WEECHAT_RC_OK

    mynick = weechat.info_get("irc_nick", server) or ""
    _KEY_CACHE.pop((server, _lc(bot_nick)), None)
    _send_auth(buffer, server, mynick, bot_nick, key)
    return weechat.WEECHAT_RC_OK


def cb_botforget(data, buffer, args):
    bot_nick = args.strip()
    if not bot_nick:
        weechat.prnt("", "Usage: /botforget <bot_nick>")
        return weechat.WEECHAT_RC_OK

    server = weechat.buffer_get_string(buffer, "localvar_server") or ""
    ck = (server, _lc(bot_nick))
    had = _KEY_CACHE.pop(ck, None) is not None
    _PENDING.pop(ck, None)
    _QUEUE.pop(ck, None)

    pinfile = weechat.config_get_plugin("pinfile")
    if pinfile:
        pin_remove(pinfile, _lc(bot_nick))

    weechat.prnt("", "bot_auth: forgot %s%s." % (bot_nick, "" if had else " (was not cached)"))
    return weechat.WEECHAT_RC_OK


def _parse_notice_line(line):
    """Parse a raw irc_in2_notice line into (nick, text), or None.  Handles
    an optional leading IRCv3 "@tags " prefix.  Not a `weechat` call."""
    s = line
    if s.startswith("@"):
        sp = s.find(" ")
        if sp == -1:
            return None
        s = s[sp + 1:]
    if not s.startswith(":"):
        return None
    sp = s.find(" ")
    if sp == -1:
        return None
    prefix = s[1:sp]
    rest = s[sp + 1:]
    parts = rest.split(" ", 2)
    if len(parts) < 3 or parts[0].upper() != "NOTICE":
        return None
    text = parts[2]
    if text.startswith(":"):
        text = text[1:]
    nick = prefix.split("!", 1)[0]
    return nick, text


def cb_notice(data, modifier, modifier_data, string):
    parsed = _parse_notice_line(string)
    if not parsed:
        return string
    nick, text = parsed
    if not text.startswith("~A2K "):
        return string

    # Protocol traffic: always hidden, whether or not we can process it.
    if not CRYPTO_OK:
        return ""

    server = modifier_data
    mynick = weechat.info_get("irc_nick", server) or ""
    ck = (server, _lc(nick))
    _expire_pending(ck)

    pend = _PENDING.pop(ck, None)
    if not pend:
        return ""   # no matching request: drop silently
    tsn, _sent = pend

    key, err = _load_key_pref()
    if err:
        weechat.prnt("", "bot_auth: %s" % err)
        return ""

    b64 = text[5:]
    bot_pub64 = open_lockbox(key, nick, mynick, tsn, b64)
    if bot_pub64 is None:
        weechat.prnt("", "bot_auth: ~A2K from %s failed to decrypt/verify; ignored." % nick)
        return ""

    pinfile = weechat.config_get_plugin("pinfile")
    if pinfile:
        bot_lc = _lc(nick)
        existing = pin_lookup(pinfile, bot_lc)
        got_b64 = base64.b64encode(bot_pub64).decode("ascii")
        if existing is None:
            pin_add(pinfile, bot_lc, got_b64)
        elif existing != got_b64:
            try:
                existing_raw = base64.b64decode(existing)
            except Exception:
                existing_raw = None
            weechat.prnt(
                "", "bot_auth: WARNING pinned-key mismatch for %s! pinned %s got %s "
                    "-- possible man-in-the-middle, or the bot was rekeyed. "
                    "Run /botforget %s to accept the new key."
                    % (nick, fingerprint(existing_raw) if existing_raw else "?",
                       fingerprint(bot_pub64), nick))
            return ""   # do NOT cache on a pin mismatch

    _KEY_CACHE[ck] = bot_pub64
    weechat.prnt("", "bot_auth: authenticated with %s — key %s" % (nick, fingerprint(bot_pub64)))

    q = _QUEUE.pop(ck, [])
    for cmd in q:
        _send_command("", server, mynick, key, nick, bot_pub64, cmd)
    return ""


def cb_timer(data, remaining_calls):
    for ck in list(_PENDING.keys()):
        _expire_pending(ck)
    return weechat.WEECHAT_RC_OK


if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE,
                    SCRIPT_DESC, "", ""):
    if not weechat.config_is_set_plugin("keyfile"):
        weechat.config_set_plugin("keyfile", "")
    if not weechat.config_is_set_plugin("pinfile"):
        weechat.config_set_plugin("pinfile", "")

    weechat.hook_command(
        "botcmd",
        "Send an encrypted (~A2) admin command to an ircbot (passwordless, key-based)",
        "<bot_nick> <command> [args...]",
        "  bot_nick: the bot's current nick on this network\n"
        "   command: the admin command, e.g. 'die' or '+admin ...'\n\n"
        "Set your key first:\n"
        "  /set plugins.var.python.%s.keyfile /path/to/NAME.private.b64  (chmod 600)\n"
        "  /set plugins.var.python.%s.pinfile /path/to/pinfile           (optional)"
        % (SCRIPT_NAME, SCRIPT_NAME),
        "", "cb_botcmd", "")
    weechat.hook_command(
        "botauth",
        "Drop the cached key for a bot and send a fresh ~A2A auth request",
        "<bot_nick>", "", "", "cb_botauth", "")
    weechat.hook_command(
        "botforget",
        "Drop the cached key (and pin) for a bot",
        "<bot_nick>", "", "", "cb_botforget", "")

    weechat.hook_modifier("irc_in2_notice", "cb_notice", "")
    weechat.hook_timer(5000, 0, 0, "cb_timer", "")

    if not CRYPTO_OK:
        weechat.prnt("", CRYPTO_HINT)
        weechat.prnt("", "/botcmd stays registered but will refuse to send "
                         "until then.")
    else:
        weechat.prnt("", "Set /set plugins.var.python.%s.keyfile <path> to your "
                         ".private.b64, then /botcmd <bot> <command>." % SCRIPT_NAME)
