use strict;
use warnings;
use Irssi;
use Irssi::Irc;
use Crypt::PBKDF2;
use Crypt::AuthEnc::GCM qw(gcm_encrypt_authenticate);
use Crypt::PRNG qw(random_bytes);
use MIME::Base64 qw(encode_base64);

# --- Script Information ---
our $VERSION = '3.0.0';
our %IRSSI = (
    authors     => 'rclemens',
    contact     => '',
    name        => 'Bot Authenticator (v1 / AES-256-GCM)',
    description => 'Generates an encrypted admin command (v1 / ~A1) for ircbot.',
    license     => 'Public Domain',
);

# Wire format:
#   PRIVMSG <bot> :~A1 <base64( salt[16] || iv[12] || ciphertext || tag[16] )>
# Plaintext under the cipher:
#   <unix_ts>:<nonce>:<command> [args...]
# Key derivation:
#   key = PBKDF2-HMAC-SHA256(admin_password, salt, iterations=100000, dkLen=32)
# Constraints enforced by the bot:
#   - timestamp must be within ±30 s of bot's wall clock
#   - nonce must not already be in the bot's admin_nonces ring (size 4096)
#   - hostmask of sender must match an active admin/oper record

sub build_v1_payload {
    my ($password, $command_line) = @_;

    my $salt  = random_bytes(16);
    my $iv    = random_bytes(12);

    my $pbkdf2 = Crypt::PBKDF2->new(
        hasher     => Crypt::PBKDF2->hasher_from_algorithm('HMACSHA2', 256),
        iterations => 100000,
        output_len => 32,
    );
    my $key = $pbkdf2->PBKDF2($salt, $password);

    # Nonce as a printable 64-bit unsigned decimal.  Stays well under uint64 max.
    my $nonce_bytes = random_bytes(8);
    my $nonce = unpack('Q>', $nonce_bytes);    # big-endian -> integer
    $nonce = $nonce & 0x7FFFFFFFFFFFFFFF;       # keep positive in 64-bit signed math

    my $ts = time();
    my $plaintext = sprintf("%d:%s:%s", $ts, $nonce, $command_line);

    my ($ciphertext, $tag) =
        gcm_encrypt_authenticate('AES', $key, $iv, '', $plaintext);

    my $blob = $salt . $iv . $ciphertext . $tag;
    return encode_base64($blob, '');           # no newline
}

# --- The /botcmd command ---
sub cmd_bot_auth {
    my ($data, $server, $witem) = @_;

    if (!$server || !$server->{connected}) {
        if ($witem && $witem->{server}) {
            $server = $witem->{server};
        } else {
            Irssi::print("Error: Not connected to a server.");
            return;
        }
    }

    my ($bot_nick, @rest) = split / /, $data;
    if (!$bot_nick || !@rest) {
        Irssi::print("Usage: /botcmd <bot_nick> <command> [arguments]");
        return;
    }
    my $command_line = join(' ', @rest);

    my $password = Irssi::settings_get_str('bot_auth_password');
    if (!$password) {
        Irssi::print("Error: Bot password not set. Use /set bot_auth_password your_secret_pass");
        return;
    }

    my $b64;
    eval { $b64 = build_v1_payload($password, $command_line); };
    if ($@ || !$b64) {
        Irssi::print("Error: failed to build v1 payload: $@");
        return;
    }

    my $raw_line_to_send = "PRIVMSG $bot_nick :~A1 $b64";
    $server->command("quote $raw_line_to_send");

    Irssi::print("Sent (~A1) '$command_line' to $bot_nick.");
}

# --- Setup ---
Irssi::settings_add_str('bot_auth', 'bot_auth_password', '');
Irssi::command_bind('botcmd', \&cmd_bot_auth);

Irssi::print("Bot Authenticator script (v$VERSION, AES-256-GCM) loaded.");
Irssi::print("Required CPAN modules: CryptX (Crypt::PBKDF2, Crypt::AuthEnc::GCM, Crypt::PRNG).");
Irssi::print("Install with: cpan CryptX");
