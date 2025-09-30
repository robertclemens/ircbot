/* run_bot.sh */

run_bot.sh is the preferred way to start your bot. Put this file in your bot directory and chmod 700 run_bot.sh and reference
this file when installing a crontab.



/* bot-auth.sh */

bot-auth.sh is a cli tool to generate hashes of admin or op passwords to send to the bot.



/* bot_auth.pl */

bot_auth.pl is an irssi script that you may load into irssi to generate on-the-fly commands to the bot with a hash.
Put this file in ~/.irssi/scripts/autorun/ to load the script upon startup.



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
