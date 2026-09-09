use strict;
use warnings;
use Irssi;
use Irssi::Irc;
use Crypt::KeyDerivation  qw(pbkdf2);          # CryptX
use Crypt::AuthEnc::GCM   qw(gcm_encrypt_authenticate); # CryptX
use Crypt::PRNG           qw(random_bytes);    # CryptX
use MIME::Base64          qw(encode_base64);   # core
use Config;

# ircbot_irssi_auth.pl — v1 (~A1) admin-command client for ircbot, Irssi edition.
#
# Wire format (must match commands.c exactly):
#   PRIVMSG <bot> :~A1 <base64( salt[16] || iv[12] || ciphertext || tag[16] )>
#   plaintext = "<unix_ts>:<nonce>:<command> [args...]"
#   key       = PBKDF2-HMAC-SHA256(password, salt, 100000, 32)
#   cipher    = AES-256-GCM, no AAD
# Bot-side constraints: |now - ts| <= 30s, nonce unseen for 60s, and the
# sender's hostmask must match an active admin/oper record.
#
# Dependency: CryptX only.
#   cpan CryptX          (or: apt install libcryptx-perl)
# Crypt::PBKDF2 is NOT part of CryptX and is deliberately not used — CryptX's
# own Crypt::KeyDerivation::pbkdf2 is the same libtomcrypt primitive.
#
# The crypto runs in-process: the password and derived key never appear in a
# command line, an environment variable, or a temp file.  Do not reintroduce
# `openssl enc -K <hex>` here — argv is world-readable via ps(1).
#
# Setup (either one):
#   /set bot_auth_passfile /home/you/.ircbot_admin_pass    (preferred, chmod 600)
#   /set bot_auth_password your_admin_password             (stored in irssi config)
#
# Usage:
#   /botcmd <bot_nick> <command> [args...]

our $VERSION = '5.0.0';
our %IRSSI = (
    authors     => 'rclemens',
    contact     => '',
    name        => 'Bot Authenticator (v1 / AES-256-GCM)',
    description => 'Sends ~A1 admin commands to ircbot. In-process crypto via CryptX.',
    license     => 'Public Domain',
);

# Build one ~A1 base64 blob.  Returns the base64 string.
sub build_v1_payload {
    my ($password, $command_line) = @_;

    my $salt = random_bytes(16);
    my $iv   = random_bytes(12);

    # PBKDF2-HMAC-SHA256, 100000 iterations, 32-byte key.
    my $key = pbkdf2($password, $salt, 100000, 'SHA256', 32);

    # Nonce: a positive decimal integer the bot parses with strtoull().  Use 62
    # bits so it is exact on both 64-bit and 32-bit perl builds and can never
    # render in scientific notation.
    # Mask the top two bits of the first byte rather than AND-ing with a
    # 64-bit literal, which warns "Hexadecimal number > 0xffffffff
    # non-portable" under `use warnings` on 32-bit perl.
    my $nonce;
    if ($Config{ivsize} >= 8) {
        my $nb = random_bytes(8);
        substr($nb, 0, 1) = chr(ord(substr($nb, 0, 1)) & 0x3F);
        $nonce = unpack('Q>', $nb);
    } else {
        # 32-bit perl: 48 bits of randomness, still far beyond the bot's
        # 4096-entry / 60-second replay ring.
        my @b = unpack('C6', random_bytes(6));
        $nonce = 0;
        $nonce = $nonce * 256 + $_ for @b;
    }

    my $plaintext = sprintf('%d:%s:%s', time(), $nonce, $command_line);
    my ($ct, $tag) = gcm_encrypt_authenticate('AES', $key, $iv, '', $plaintext);

    # Best-effort scrub of the derived key and plaintext.  Perl may retain
    # copies (COW, realloc); this is hygiene, not a guarantee.
    substr($key,       0, length($key),       "\0" x length($key));
    substr($plaintext, 0, length($plaintext), "\0" x length($plaintext));

    return encode_base64($salt . $iv . $ct . $tag, '');
}

# Read the admin password from the passfile if set, else the irssi setting.
# The passfile must be a regular file, owned by us, with no group/other bits.
sub load_password {
    my $file = Irssi::settings_get_str('bot_auth_passfile');
    if (defined $file && length $file) {
        my @st = stat($file);
        return (undef, "passfile '$file' is unreadable")           if !@st;
        return (undef, "passfile '$file' must be a regular file")  if !-f _;
        return (undef, "passfile '$file' must be owned by you")    if $st[4] != $<;
        return (undef, sprintf("passfile '%s' is mode %04o — chmod 600 it",
                               $file, $st[2] & 07777))             if $st[2] & 077;
        open(my $fh, '<', $file) or return (undef, "cannot open passfile: $!");
        my $pw = <$fh>;
        close($fh);
        return (undef, "passfile '$file' is empty") if !defined $pw;
        $pw =~ s/\r?\n\z//;
        return (undef, "passfile '$file' is empty") if !length $pw;
        return ($pw, undef);
    }
    my $pw = Irssi::settings_get_str('bot_auth_password');
    return (undef, 'no password set — /set bot_auth_passfile <file> (preferred) '
                 . 'or /set bot_auth_password <pass>') if !defined $pw || !length $pw;
    return ($pw, undef);
}

sub cmd_bot_auth {
    my ($data, $server, $witem) = @_;

    if (!$server || !$server->{connected}) {
        $server = $witem->{server} if $witem && $witem->{server};
        return Irssi::print('bot_auth: not connected to a server.')
            if !$server || !$server->{connected};
    }

    my ($bot_nick, @rest) = split /\s+/, ($data // '');
    return Irssi::print('Usage: /botcmd <bot_nick> <command> [args...]')
        if !defined $bot_nick || !length $bot_nick || !@rest;
    my $command_line = join(' ', @rest);

    my ($password, $err) = load_password();
    return Irssi::print("bot_auth: $err") if defined $err;

    my $b64;
    eval { $b64 = build_v1_payload($password, $command_line); 1 }
        or return Irssi::print("bot_auth: failed to build payload: $@");
    substr($password, 0, length($password), "\0" x length($password));

    # The server re-broadcasts our PRIVMSG prefixed with ":nick!user@host " and
    # the 512-byte limit (including CR-LF) counts that prefix.  A blob clipped
    # by the server reaches the bot as a GCM tag failure, indistinguishable
    # from a wrong password — so refuse locally instead.
    my $line   = "PRIVMSG $bot_nick :~A1 $b64";
    my $prefix = 1 + length($server->{nick} // '') + 1
               + length($server->{userhost} // 'user@host') + 1;
    $prefix = 100 if $prefix < 20;   # userhost unknown yet: assume the worst
    if ($prefix + length($line) + 2 > 512) {
        return Irssi::print(
            "bot_auth: '$command_line' is too long — the ~A1 blob would be "
          . 'truncated on the wire (' . ($prefix + length($line) + 2)
          . ' > 512 bytes). Shorten the command.');
    }

    $server->command("quote $line");
    Irssi::print("bot_auth: sent (~A1) '$command_line' to $bot_nick.");
}

Irssi::settings_add_str('bot_auth', 'bot_auth_password', '');
Irssi::settings_add_str('bot_auth', 'bot_auth_passfile', '');
Irssi::command_bind('botcmd', \&cmd_bot_auth);

Irssi::print("Bot Authenticator v$VERSION (~A1 / AES-256-GCM) loaded.");
Irssi::print('Dependency: CryptX.  Set /set bot_auth_passfile <file> (chmod 600) '
           . 'or /set bot_auth_password <pass>.');

1;
