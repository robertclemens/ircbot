/* run_bot.sh */

run_bot.sh is the preferred way to start your bot. Put this file in your bot directory and chmod 700 run_bot.sh and reference
this file when installing a crontab.



/* bot-auth.sh */

bot-auth.sh builds a v1 (~A1) AES-256-GCM admin command payload and prints it
to stdout in the form:

    ~A1 <base64-blob>

Where <base64-blob> = base64( salt(16) || iv(12) || ciphertext || tag(16) ),
the cipher is AES-256-GCM, and the key is PBKDF2-HMAC-SHA256(password, salt,
100000, 32).  The plaintext under the tag is "<unix_ts>:<nonce>:<command...>".

The bot rejects payloads older than 30 seconds, replays of any nonce in the
in-memory ring (4096 entries), or any mask that does not currently match an
active admin/oper record.

Usage:
    BOT_AUTH_PASSWORD='hunter2' ./bot-auth.sh "die"
    ./bot-auth.sh "+admin alice s3cret alice!*@trusted.example"     # prompts

The output line can be sent to the bot via:
    /quote PRIVMSG <bot_nick> :~A1 <base64>

Requires: openssl 1.1.1+, plus either python3 with the 'cryptography' module
or perl with CryptX (for AES-GCM, which openssl(1) does not expose cleanly).



/* bot_auth.pl */

bot_auth.pl is an irssi script that wraps the same v1 (~A1) format above.
Drop it into ~/.irssi/scripts/autorun/ and run:

    /set bot_auth_password your_admin_password
    /botcmd <bot_nick> <command> [args]

Requires CryptX from CPAN:  cpan CryptX



/* bot-auth.mrc */

bot-auth.mrc is the mIRC counterpart.  mIRC's native crypto does not support
AES-GCM, so this script shells out to bot-auth.sh via /run and forwards the
helper's "~A1 ..." line via /quote.

Setup variables before use:
    /set %bot_auth_helper   c:\ircbot\bot-auth.sh
    /set %bot_auth_password your_admin_password



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
