use strict;
use warnings;
use Irssi;
use Irssi::Irc;
use Digest::SHA qw(sha256_hex);

# --- Script Information ---
our $VERSION = '2.0.0';
our %IRSSI = (
    authors     => 'Gemini & rclemens',
    contact     => '',
    name        => 'Bot Authenticator',
    description => 'Generates a time-based hash to securely send commands to the IRC bot.',
    license     => 'Public Domain',
);

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

    my $nonce = int(rand(1000000));

    my ($bot_nick, $command, @args) = split / /, $data;

    if (!$bot_nick || !$command) {
        Irssi::print("Usage: /botcmd <bot_nick> <command> [arguments]");
        return;
    }

    my $password = Irssi::settings_get_str('bot_auth_password');
    if (!$password) {
        Irssi::print("Error: Bot password not set. Use /set bot_auth_password your_secret_pass");
        return;
    }

    my $time_minute = int(time() / 60);
    my $string_to_hash = "$password:$time_minute:$nonce";
    my $hash = sha256_hex($string_to_hash);

    my $full_command = join(' ', $command, @args);
    my $raw_line_to_send = "PRIVMSG $bot_nick :$nonce:$hash $full_command";

    # FIX: Use 'quote' to send the command as a raw line to the server
    $server->command("quote $raw_line_to_send");
    
    Irssi::print("Sent command '$full_command' to $bot_nick.");
}

# --- Setup ---
Irssi::settings_add_str('bot_auth', 'bot_auth_password', '');
Irssi::command_bind('botcmd', \&cmd_bot_auth);

Irssi::print("Bot Authenticator script (v1.2-final) loaded.");
