use strict;
use warnings;
use Irssi;
use Irssi::Irc;
use Digest::SHA qw(hmac_sha256);    # CORE module since Perl 5.10 — no CPAN install
use MIME::Base64 qw(encode_base64); # CORE
use IPC::Open2 qw(open2);

# bot_auth.pl — v1c (~A1c) admin-command client for ircbot.
#
# Strategy:
#   - PBKDF2 + HMAC-SHA256: done in pure Perl using Digest::SHA (CORE).
#   - AES-256-CBC: shelled out to openssl(1) via IPC::Open2. No CryptX needed.
#   - No CPAN modules required. Only requirement is openssl(1) in PATH.
#
# Setup:
#   /set bot_auth_password your_admin_password
#   /set bot_auth_openssl  /usr/bin/openssl              (optional override)
#
# Usage:
#   /botcmd <bot_nick> <command> [args...]

our $VERSION = '4.0.0';
our %IRSSI = (
    authors     => 'rclemens',
    contact     => '',
    name        => 'Bot Authenticator (v1c / openssl CLI)',
    description => 'Sends ~A1c admin commands. Uses Digest::SHA (core) + openssl(1). No CPAN modules required.',
    license     => 'Public Domain',
);

# --- Pure-Perl PBKDF2-HMAC-SHA256 (Digest::SHA is core) -----------------
sub pbkdf2_sha256 {
    my ($password, $salt, $iter, $len) = @_;
    my $out = '';
    my $blocks = int(($len + 31) / 32);
    for (my $i = 1; $i <= $blocks; $i++) {
        my $t = $salt . pack('N', $i);
        my $u = hmac_sha256($t, $password);
        my $f = $u;
        for (my $j = 1; $j < $iter; $j++) {
            $u = hmac_sha256($u, $password);
            $f ^= $u;
        }
        $out .= $f;
    }
    return substr($out, 0, $len);
}

# --- AES-256-CBC via openssl(1) -----------------------------------------
sub aes_cbc_encrypt {
    my ($openssl, $enc_key_hex, $iv_hex, $plaintext) = @_;
    my ($CHILD_OUT, $CHILD_IN);
    my $pid = open2($CHILD_OUT, $CHILD_IN,
        $openssl, 'enc', '-aes-256-cbc',
        '-K', $enc_key_hex,
        '-iv', $iv_hex);
    print $CHILD_IN $plaintext;
    close($CHILD_IN);
    local $/; my $ct = <$CHILD_OUT>;
    close($CHILD_OUT);
    waitpid($pid, 0);
    die "openssl enc failed" if !defined $ct || $? != 0;
    return $ct;
}

sub rand_bytes {
    my ($n) = @_;
    my $r;
    if (open(my $u, '<:raw', '/dev/urandom')) {
        read($u, $r, $n);
        close($u);
        return $r if length($r) == $n;
    }
    # Last-resort fallback for systems without /dev/urandom (rare on Unix).
    return join('', map { chr(int(rand(256))) } 1..$n);
}

sub cmd_bot_auth {
    my ($data, $server, $witem) = @_;
    if (!$server || !$server->{connected}) {
        $server = $witem->{server} if $witem && $witem->{server};
        return Irssi::print("Error: not connected.") unless $server;
    }

    my ($bot_nick, @rest) = split / /, $data;
    return Irssi::print("Usage: /botcmd <bot_nick> <command> [args]")
        if !$bot_nick || !@rest;
    my $command_line = join(' ', @rest);

    my $password = Irssi::settings_get_str('bot_auth_password');
    return Irssi::print("Error: /set bot_auth_password ...") if !$password;
    my $openssl = Irssi::settings_get_str('bot_auth_openssl') || 'openssl';

    my $salt = rand_bytes(16);
    my $iv   = rand_bytes(16);
    my $nonce_bytes = rand_bytes(8);
    # Mask top bit so it stays positive as an int64.
    substr($nonce_bytes, 0, 1) = chr(ord(substr($nonce_bytes, 0, 1)) & 0x7F);
    my $nonce = 0;
    $nonce = ($nonce << 8) | ord($_) for split //, $nonce_bytes;
    my $ts = time();

    my $keys = pbkdf2_sha256($password, $salt, 100000, 64);
    my $enc_key = substr($keys, 0, 32);
    my $mac_key = substr($keys, 32, 32);

    my $plaintext = sprintf("%d:%s:%s", $ts, $nonce, $command_line);

    my $ct;
    eval {
        $ct = aes_cbc_encrypt($openssl,
                              unpack('H*', $enc_key),
                              unpack('H*', $iv),
                              $plaintext);
    };
    return Irssi::print("Error: $@") if $@;

    my $mac = hmac_sha256($salt . $iv . $ct, $mac_key);
    my $blob = $salt . $iv . $ct . $mac;
    my $b64 = encode_base64($blob, '');

    $server->command("quote PRIVMSG $bot_nick :~A1c $b64");
    Irssi::print("Sent (~A1c) '$command_line' to $bot_nick.");
}

Irssi::settings_add_str('bot_auth', 'bot_auth_password', '');
Irssi::settings_add_str('bot_auth', 'bot_auth_openssl',  '');
Irssi::command_bind('botcmd', \&cmd_bot_auth);

Irssi::print("Bot Authenticator (v$VERSION, ~A1c / openssl CLI) loaded.");
Irssi::print("No CPAN modules required — only openssl(1) in PATH.");
Irssi::print("Set: /set bot_auth_password ...  (and optionally /set bot_auth_openssl /path/to/openssl)");
