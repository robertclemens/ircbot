/* run_bot.sh */

run_bot.sh is the preferred way to start your bot. Put this file in your bot directory and chmod 700 run_bot.sh and reference
this file when installing a crontab.



// Admin command transports

The bot accepts TWO equivalent encrypted wire formats for admin commands:

  ~A1   AES-256-GCM (single tag)
  ~A1c  AES-256-CBC + HMAC-SHA256 (encrypt-then-MAC)

Both derive their keys with PBKDF2-HMAC-SHA256(password, salt, 100000, ...).
Both protect the same plaintext envelope "<unix_ts>:<nonce>:<command...>".
Both are accepted equally — pick whichever your client can produce.

Use ~A1c when you want NO compiled helpers and NO CPAN modules: openssl(1)
alone can produce it.  Use ~A1 when you do have the compiled bot-auth helper
(or Python/CryptX) and want the slightly cleaner AEAD wire format.



/* bot-auth.sh  (~A1c, pure openssl CLI)  ***LEAKS YOUR PASSWORD*** */

SECURITY WARNING: this script passes the admin password to openssl as
`-kdfopt pass:"$password"` and the derived key as `enc -K <hex>`, both on the
command line, where any local user can read them from ps(1) for the lifetime
of the call.  Prefer a client script above.  See "WHY NOT openssl(1)".

Builds a ~A1c payload using ONLY openssl(1) and standard coreutils.  No
Python, no Perl modules, no compiled helpers.

    BOT_AUTH_PASSWORD='hunter2' ./bot-auth.sh "die"
    ./bot-auth.sh "+admin alice s3cret alice!*@trusted.example"   # prompts

Requires: openssl 3.0+ (for `openssl kdf -binary PBKDF2`).



/* bot-auth.cmd  (~A1c, Windows batch + openssl + PowerShell)  ***LEAKS*** */

SECURITY WARNING: passes the password and derived key on the command line
(readable via Win32_Process.CommandLine) and writes the derived keys and the
plaintext to temp files.  Needs reworking before it should be relied on.

Windows-native batch counterpart to bot-auth.sh.  Uses openssl.exe (ships
with Git for Windows or any OpenSSL 3.x install) and PowerShell (built into
Windows 10+).  No compiled helper, no Python, no Perl.

    set BOT_AUTH_PASSWORD=hunter2
    bot-auth.cmd "die"

Sends the output to the bot:
    /quote PRIVMSG <bot> :~A1c <base64>



/* ircbot_irssi_auth.pl  (~A1, Irssi, requires CryptX) */

Irssi script.  All crypto runs in-process via CryptX — PBKDF2 through
Crypt::KeyDerivation and AES-256-GCM through Crypt::AuthEnc::GCM.

    cpan CryptX            (or: apt install libcryptx-perl)
    /set bot_auth_passfile /home/you/.ircbot_admin_pass    # preferred, chmod 600
    /set bot_auth_password your_admin_password             # or store in irssi config
    /botcmd <bot_nick> <command> [args]

NOTE: Crypt::PBKDF2 is a separate distribution and is NOT part of CryptX.
This script deliberately uses CryptX's own Crypt::KeyDerivation::pbkdf2 so
CryptX is the only dependency.

WHY NOT openssl(1): `openssl enc` accepts a raw key only as `-K <hex>` on the
command line, and `openssl kdf` takes the password only as `-kdfopt pass:...`.
argv is world-readable via ps(1), so the CLI cannot be used for this protocol
without leaking either the derived key or the admin password to every local
user.  Do not "simplify" any of these scripts back onto the openssl CLI.


/* ircbot_hexchat_auth.py  (~A1, HexChat, requires python3-cryptography) */

HexChat Python script.  In-process PBKDF2 + AES-256-GCM.

    pip install cryptography       (or: apt install python3-cryptography)
    cp ircbot_hexchat_auth.py ~/.config/hexchat/addons/
    /BOTCMD passfile /home/you/.ircbot_admin_pass          # preferred, chmod 600
    /BOTCMD password your_admin_password                   # or store in prefs
    /BOTCMD <bot_nick> <command> [args]


/* ircbot_weechat_auth.py  (~A1, WeeChat, requires python3-cryptography) */

WeeChat Python script.  In-process PBKDF2 + AES-256-GCM.

    cp ircbot_weechat_auth.py ~/.weechat/python/   (or ~/.local/share/weechat/python/)
    /python load ircbot_weechat_auth.py
    /set plugins.var.python.ircbot_weechat_auth.passfile /home/you/.ircbot_admin_pass
    /botcmd <bot_nick> <command> [args]

Run /botcmd from a buffer on the bot's network — the script sends on that
buffer's server.


/* repartee — NOT CURRENTLY POSSIBLE */

Repartee (https://repart.ee/) scripts run in a sandboxed Lua 5.4 environment
with `os`, `io`, `loadfile`, `dofile` and `package` removed.  That leaves no
way to build a ~A1/~A1c frame:

  - no `package`/`require`  -> no crypto binding (luaossl, lua-openssl)
  - no `os`                 -> no clock for the <unix_ts> envelope field
  - no `io`                 -> no /dev/urandom

`math.random` is not a CSPRNG; deriving a salt, GCM IV or nonce from it would
silently destroy the security of every command sent.  A script here needs one
of: a crypto helper exposed on repartee's own `api` table, a whitelisted
`require`, or an api call that returns cryptographically secure random bytes
plus wall-clock time.  Until then, generate the blob with another client's
script (or a shell) and send it with repartee's raw-line command.



/* bot-auth.mrc  (~A1c, mIRC) */

mIRC wrapper.  Delegates the openssl + PowerShell orchestration to
bot-auth.cmd.  No compiled helper, no Python, no Perl.

    /set %bot_auth_password your_admin_password
    /set %bot_auth_helper   C:\path\to\utils\bot-auth.cmd
    /set %bot_auth_openssl  C:\Program Files\Git\usr\bin\openssl.exe   ; optional
    /botcmd <bot> <command> [args]



/* bot-auth.c  (~A1, compiled helper, optional) */

A small native helper that produces the ~A1 (AES-256-GCM) format.  Build
with:

    gcc -O2 -Wall -o bot-auth bot-auth.c -lcrypto

On Windows, in MSYS2 MinGW 64-bit shell:
    pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-openssl
    gcc -O2 -Wall -o bot-auth.exe bot-auth.c -lcrypto -static

Reads BOT_AUTH_PASSWORD from env (or stdin in "-" mode) and prints
"~A1 <base64>" to stdout.  Useful if you want a single tool with no
runtime dependencies on openssl.exe / PowerShell.



/* encrypt_config.c :: Compile instructions: gcc encrypt_config.c -o config_tool -lssl -lcrypto */

config_tool.c is a tool for generating a config file to use with the bot. This is normally not necessary but can provide
a good way to generate all of the channels, usermasks, passwords, etc without having to send the commands to the bot which
is useful for loading up many bots.



/* decrypt_config.c :: Compile instructions: gcc decrypt_config.c -o decyrpt_tool -lssl -lcrypto */

decrypt_tool.c is a debugging tool to look at the contents of your config file. This is normally not necessary but helps
debug issues with the bot.



/* legacy_encrypt_config.c :: Compile instructions: gcc legacy_encrypt_config.c -o decyrpt_tool -lssl -lcrypto */

legacy_encrypt_config.c is the old config encryption tool for versions < v1.1.2. It uses AES-256-CBC and that
cipher was changed to AES-256-GCM in v1.1.2. Config files are not compatible using the different ciphers so you
may use this tool on previous versions only.



/* legacy_decrypt_config.c :: Compile instructions: gcc legacy_decrypt_config.c -o decyrpt_tool -lssl -lcrypto */

legacy_decrypt_config.c is the old config decryption tool for versions < v1.1.2. It uses AES-256-CBC and that cipher
was changed to AES-256-GCM in v1.1.2. You may use this tool to decrypt a AES-256-CBC config and use the AES-256-GCM
config tool (encrypt_config.c) to migrate to the new cipher.



/* test_auth.c :: Compile instructions: gcc test_auth.c -o test_auth -lssl -lcrypto */

test_auth.c is a debug only tool that has been used to debug bot authorization commands during building of the bot code.
