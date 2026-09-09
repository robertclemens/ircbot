"""ircbot_weechat_auth.py — v1 (~A1) admin-command client for ircbot, WeeChat edition.

Wire format (must match commands.c exactly):
    PRIVMSG <bot> :~A1 <base64( salt[16] || iv[12] || ciphertext || tag[16] )>
    plaintext = "<unix_ts>:<nonce>:<command> [args...]"
    key       = PBKDF2-HMAC-SHA256(password, salt, 100000, 32)
    cipher    = AES-256-GCM, no AAD
Bot-side constraints: |now - ts| <= 30s, nonce unseen for 60s, and the sender's
hostmask must match an active admin/oper record.

Dependency:  pip install cryptography      (or: apt install python3-cryptography)

The crypto runs in-process: the password and derived key never reach a command
line, an environment variable, or a temp file.  Do not "simplify" this by
shelling out to `openssl enc -K <hex>` — argv is world-readable via ps(1).

Install:
    cp ircbot_weechat_auth.py ~/.weechat/python/     (or ~/.local/share/weechat/python/)
    /python load ircbot_weechat_auth.py

Setup (either one):
    /set plugins.var.python.ircbot_weechat_auth.passfile /home/you/.ircbot_admin_pass   (chmod 600)
    /set plugins.var.python.ircbot_weechat_auth.password <your_admin_password>

Usage (from a buffer on the bot's network):
    /botcmd <bot_nick> <command> [args...]
"""

import base64
import os
import stat
import time

import weechat
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

SCRIPT_NAME = "ircbot_weechat_auth"
SCRIPT_AUTHOR = "rclemens"
SCRIPT_VERSION = "5.0.0"
SCRIPT_LICENSE = "Public Domain"
SCRIPT_DESC = "Sends ~A1 admin commands to ircbot (AES-256-GCM)"

PBKDF2_ITERATIONS = 100000
SALT_SIZE = 16
GCM_IV_LEN = 12
IRC_LINE_LIMIT = 512


def build_v1_payload(password, command_line):
    """Return the base64 ~A1 blob for one admin command."""
    salt = os.urandom(SALT_SIZE)
    iv = os.urandom(GCM_IV_LEN)

    key = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt,
                     iterations=PBKDF2_ITERATIONS).derive(
                         password.encode("utf-8"))

    # Positive decimal integer parsed bot-side with strtoull(); 62 bits keeps
    # it well inside an unsigned 64-bit value.
    nonce = int.from_bytes(os.urandom(8), "big") >> 2

    plaintext = "%d:%d:%s" % (int(time.time()), nonce, command_line)
    # AESGCM.encrypt returns ciphertext || tag, which is the layout the bot
    # expects after salt || iv.
    ct_and_tag = AESGCM(key).encrypt(iv, plaintext.encode("utf-8"), None)
    return base64.b64encode(salt + iv + ct_and_tag).decode("ascii")


def load_password():
    """(password, None) or (None, error).  Passfile wins over the stored option."""
    path = weechat.config_get_plugin("passfile")
    if path:
        try:
            st = os.stat(path)
        except OSError as exc:
            return None, "passfile '%s' is unreadable (%s)" % (path, exc)
        if not stat.S_ISREG(st.st_mode):
            return None, "passfile '%s' must be a regular file" % path
        if st.st_uid != os.getuid():
            return None, "passfile '%s' must be owned by you" % path
        if st.st_mode & 0o077:
            return None, ("passfile '%s' is mode %04o — chmod 600 it"
                          % (path, st.st_mode & 0o7777))
        try:
            with open(path, "r", encoding="utf-8") as handle:
                pw = handle.readline().rstrip("\r\n")
        except OSError as exc:
            return None, "cannot read passfile: %s" % exc
        if not pw:
            return None, "passfile '%s' is empty" % path
        return pw, None

    pw = weechat.config_get_plugin("password")
    if not pw:
        return None, ("no password set — /set plugins.var.python.ircbot_weechat_auth.passfile "
                      "<file> (preferred) or ...ircbot_weechat_auth.password <pass>")
    return pw, None


def botcmd_cb(data, buffer, args):
    parts = args.split(None, 1)
    if len(parts) < 2:
        weechat.prnt("", "Usage: /botcmd <bot_nick> <command> [args...]")
        return weechat.WEECHAT_RC_OK

    server = weechat.buffer_get_string(buffer, "localvar_server")
    if not server:
        weechat.prnt("", "bot_auth: run /botcmd from a buffer on the bot's network.")
        return weechat.WEECHAT_RC_OK

    bot_nick, command_line = parts[0], parts[1]

    password, err = load_password()
    if err:
        weechat.prnt("", "bot_auth: %s" % err)
        return weechat.WEECHAT_RC_OK

    try:
        b64 = build_v1_payload(password, command_line)
    except Exception as exc:                      # noqa: BLE001 - report to user
        weechat.prnt("", "bot_auth: failed to build payload: %s" % exc)
        return weechat.WEECHAT_RC_OK

    # The server re-broadcasts our PRIVMSG prefixed with ":nick!user@host " and
    # the 512-byte limit counts that prefix plus CR-LF.  A blob clipped by the
    # server reaches the bot as a GCM tag failure — indistinguishable from a
    # wrong password — so refuse locally instead.
    line = "PRIVMSG %s :~A1 %s" % (bot_nick, b64)
    nick = weechat.buffer_get_string(buffer, "localvar_nick") or ""
    host = weechat.info_get("irc_server_isupport_value", "%s,HOSTLEN" % server)
    prefix = len(":%s!~user@" % nick) + (int(host) if host.isdigit() else 63) + 1
    if prefix + len(line) + 2 > IRC_LINE_LIMIT:
        weechat.prnt("", "bot_auth: '%s' is too long — the ~A1 blob would be "
                         "truncated on the wire (%d > %d bytes). Shorten the command."
                     % (command_line, prefix + len(line) + 2, IRC_LINE_LIMIT))
        return weechat.WEECHAT_RC_OK

    weechat.command(buffer, "/quote %s" % line)
    weechat.prnt("", "bot_auth: sent (~A1) '%s' to %s." % (command_line, bot_nick))
    return weechat.WEECHAT_RC_OK


if weechat.register(SCRIPT_NAME, SCRIPT_AUTHOR, SCRIPT_VERSION, SCRIPT_LICENSE,
                    SCRIPT_DESC, "", ""):
    weechat.hook_command(
        "botcmd",
        "Send an encrypted (~A1) admin command to an ircbot",
        "<bot_nick> <command> [args...]",
        "  bot_nick: the bot's current nick on this network\n"
        "   command: the admin command, e.g. 'die' or '+admin ...'\n\n"
        "Set the password first:\n"
        "  /set plugins.var.python.ircbot_weechat_auth.passfile /path/to/file  (chmod 600)\n"
        "  /set plugins.var.python.ircbot_weechat_auth.password <pass>",
        "", "botcmd_cb", "")
