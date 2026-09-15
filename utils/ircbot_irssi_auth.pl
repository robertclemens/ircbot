use strict;
use warnings;
use Irssi;
use Irssi::Irc;
use MIME::Base64 qw(encode_base64 decode_base64);   # core

# CryptX is loaded at runtime, not with `use`, so a missing dependency reports
# one actionable line in the irssi window instead of aborting the script with a
# compile error and an @INC dump.  Functions are called fully qualified, so
# nothing needs importing into this script's package.
our $CRYPTX_OK = eval {
    require Crypt::PK::Ed25519;     # sign / verify
    require Crypt::PK::X25519;      # ECDH
    require Crypt::KeyDerivation;   # hkdf
    require Crypt::AuthEnc::GCM;    # gcm_encrypt_authenticate / gcm_decrypt_verify
    require Crypt::PRNG;            # random_bytes
    require Crypt::Digest::SHA256;  # sha256 (fingerprints)
    1;
};
our $CRYPTX_ERR = $CRYPTX_OK ? '' : "$@";

sub cryptx_hint {
    return 'bot_auth: CryptX is not installed — this script cannot do the '
         . 'Curve25519/AES-GCM handshake without it.  Install one of:  '
         . 'sudo apt install libcryptx-perl  |  cpan CryptX  |  cpanm CryptX';
}

# ircbot_irssi_auth.pl — v2 (~A2/~A2A/~A2K) key-based admin-command client for
# ircbot, Irssi edition.  There are no passwords: each admin/oper has an
# Ed25519+X25519 keypair (ircbot/utils/keygen), and the bot only ever learns
# the *public* half.
#
# Protocol (must match commands.c / crypto.c exactly — see
# irchub/docs/passwordless.md §4): on the first command to a bot this script
# signs a "~A2A <sig> <ts>:<nonce>" request with your Ed25519 key; the bot
# replies with a NOTICE "~A2K <b64>" carrying its own public key, sealed
# (X25519 ECDH + HKDF-SHA256 + AES-256-GCM) to your X25519 key and bound to
# that request's ts:nonce.  Once that lockbox is opened and cached, every
# admin command travels as a fresh "~A2 <b64>" PRIVMSG: a per-command X25519
# ephemeral key is mixed with your static key so the bot can both decrypt and
# authenticate the sender.  ~A2K notices are protocol traffic and are always
# hidden from the chat window.
#
# Dependency: CryptX only (cpan CryptX, or: apt install libcryptx-perl).
# All crypto runs in-process: your private key material never appears in a
# command line, an environment variable, or a temp file, and this script
# never shells out to openssl(1) or any other external program.
#
# Setup:
#   1. Make a keypair with ircbot/utils/keygen (or irchub/bin/keygen); give
#      the bot admin the .public.b64 contents, keep the .private.b64 to
#      yourself and `chmod 600` it — this script warns (but still runs) if it
#      is not.
#   2. /set bot_auth_keyfile /home/you/NAME.private.b64
#   3. Optionally pin bots to their key:
#      /set bot_auth_pinfile /home/you/.ircbot_bot_pins   (chmod 600 on first write)
#      Leaving this empty (the default) disables pinning.
#   4. /botcmd <bot_nick> <command> [args...]
#
# Usage:
#   /botcmd   <bot_nick> <command> [args...]   - auto-authenticates, then sends
#   /botauth  <bot_nick>                       - drop the cached key, re-auth now
#   /botforget <bot_nick>                      - drop the cached key (and pin)
#
# DCC chat: `/botcmd <bot> dcc` makes the bot offer a passive DCC chat; accept
# it with /dcc chat <bot>.  irssi then listens (open its dcc_port range in
# your firewall, and set dcc_own_ip if you are behind NAT) and the bot
# connects to it.  While that chat is open, /botcmd sends each sealed command
# down the chat instead of by PRIVMSG, and the bot answers there.
#
# Compare a bot's key fingerprint (printed here on every successful auth)
# against that bot's own 'status' output or hub_admin's bot list before
# trusting it for the first time.

our $VERSION = '6.0.0';
our %IRSSI = (
    authors     => 'rclemens',
    contact     => '',
    name        => 'Bot Authenticator (v2 / key-based, passwordless)',
    description => 'Sends ~A2 admin commands to ircbot via Curve25519 + AES-256-GCM. No passwords.',
    license     => 'Public Domain',
);

# =============================================================================
# Pure protocol functions — no Irssi:: calls anywhere below this line down to
# the "Client-side state" section.  These are callable standalone after
# `do "ircbot_irssi_auth.pl"` against a stub Irssi package, for testing.
# =============================================================================

# ASCII-only lowercase: A-Z -> a-z, every other byte unchanged.
sub lc_ascii {
    my $s = shift;
    $s = '' unless defined $s;
    (my $t = $s) =~ tr/A-Z/a-z/;
    return $t;
}

# "ab12:cd34:ef56:7890" — first 8 bytes of SHA-256(pub64), where pub64 is the
# raw 64-byte combined public key (ed_pub(32) || x_pub(32)).
sub fingerprint {
    my ($pub64) = @_;
    my $h   = Crypt::Digest::SHA256::sha256($pub64);
    my $hex = unpack('H*', substr($h, 0, 8));
    return join(':', $hex =~ /(....)/g);
}

# Load the combined Ed25519+X25519 private key from $path (first line,
# standard base64 with padding, decoding to exactly 64 bytes: ed_priv(32) ||
# x_priv(32)).  Returns a hashref { ed_priv, x_priv, ed_pub, x_pub, pub64,
# warning }; dies with a one-line message on any failure.  `warning` is a
# mode-permission message (or undef) — the caller decides how to show it.
sub load_key {
    my ($path) = @_;
    open(my $fh, '<', $path) or die "keyfile '$path': $!\n";
    my $line = <$fh>;
    close($fh);
    die "keyfile '$path' is empty\n" if !defined $line;
    $line =~ s/^\s+|\s+$//g;
    die "keyfile '$path' is empty\n" if !length $line;

    my $raw = eval { decode_base64($line) };
    die "keyfile '$path': invalid base64\n" if !defined $raw || !length $raw;
    die "keyfile '$path': decoded key must be 64 bytes, got " . length($raw) . "\n"
        if length($raw) != 64;

    my $ed_priv = substr($raw, 0, 32);
    my $x_priv  = substr($raw, 32, 32);
    substr($raw, 0, length($raw), "\0" x length($raw));

    my $ed = Crypt::PK::Ed25519->new;
    $ed->import_key_raw($ed_priv, 'private');
    my $ed_pub = $ed->export_key_raw('public');

    my $x = Crypt::PK::X25519->new;
    $x->import_key_raw($x_priv, 'private');
    my $x_pub = $x->export_key_raw('public');

    my $pub64 = encode_base64($ed_pub . $x_pub, '');

    my $warning;
    my @st = stat($path);
    if (@st) {
        my $mode = $st[2] & 07777;
        $warning = sprintf("keyfile '%s' is mode %04o — chmod 600 it", $path, $mode)
            if $mode & 077;
    }

    return {
        ed_priv => $ed_priv,
        x_priv  => $x_priv,
        ed_pub  => $ed_pub,
        x_pub   => $x_pub,
        pub64   => $pub64,
        warning => $warning,
    };
}

# Build one ~A2A auth request.  Returns ($line, $tsn).
sub build_auth {
    my ($key, $botnick, $mynick) = @_;

    my $nonce = unpack('H*', Crypt::PRNG::random_bytes(8));   # 16 lowercase hex chars
    my $tsn   = sprintf('%d:%s', time(), $nonce);

    my $msg = "ircbot-A2A-v1\0" . lc_ascii($botnick) . "\0" . lc_ascii($mynick) . "\0" . $tsn;

    my $ed = Crypt::PK::Ed25519->new;
    $ed->import_key_raw($key->{ed_priv}, 'private');
    my $sig = $ed->sign_message($msg);   # 64 bytes

    my $line = '~A2A ' . encode_base64($sig, '') . ' ' . $tsn;
    return ($line, $tsn);
}

# Open a ~A2K lockbox.  $tsn must be the ts:nonce of the pending request this
# reply answers.  Returns the bot's raw 64-byte combined public key on
# success, or undef on any failure (malformed frame, bad point, wrong tag).
sub open_lockbox {
    my ($key, $botnick, $mynick, $tsn, $b64) = @_;

    my $frame = eval { decode_base64($b64) };
    return undef if !defined $frame || length($frame) != 124;

    my $eph = substr($frame, 0, 32);
    my $iv  = substr($frame, 32, 12);
    my $ct  = substr($frame, 44, 64);
    my $tag = substr($frame, 108, 16);

    my $x = Crypt::PK::X25519->new;
    $x->import_key_raw($key->{x_priv}, 'private');
    my $peer = Crypt::PK::X25519->new;
    eval { $peer->import_key_raw($eph, 'public'); 1 } or return undef;

    my $ss = eval { $x->shared_secret($peer) };
    return undef if !defined $ss || $ss eq ("\0" x 32);   # reject a low-order point

    my $info = "ircbot-A2K-v1" . $key->{x_pub};
    my $kmat = eval { Crypt::KeyDerivation::hkdf($ss, $eph, 'SHA256', 32, $info) };
    substr($ss, 0, length($ss), "\0" x length($ss));
    return undef if !defined $kmat;

    my $aad = "ircbot-A2K-v1\0" . lc_ascii($botnick) . "\0" . lc_ascii($mynick) . "\0" . $tsn;
    my $pt = eval { Crypt::AuthEnc::GCM::gcm_decrypt_verify('AES', $kmat, $iv, $aad, $ct, $tag) };
    substr($kmat, 0, length($kmat), "\0" x length($kmat));
    return undef if !defined $pt || length($pt) != 64;
    return $pt;
}

# Build one ~A2 sealed command.  $bot_pub64 is the bot's raw 64-byte combined
# public key (as returned by open_lockbox).  Returns the line to send; dies
# with a one-line message if the command must be refused (control byte, or
# the finished line would exceed the 400-char budget).
sub build_command {
    my ($key, $bot_pub64, $botnick, $mynick, $command) = @_;

    die "command contains a control character\n" if $command =~ /[\x00-\x1f\x7f]/;

    my $nonce = unpack('H*', Crypt::PRNG::random_bytes(8));
    my $pt    = sprintf('%d:%s:%s', time(), $nonce, $command);

    my $bot_x_pub = substr($bot_pub64, 32, 32);

    my $ephk = Crypt::PK::X25519->new;
    $ephk->generate_key;
    my $eph_pub = $ephk->export_key_raw('public');

    my $botpk = Crypt::PK::X25519->new;
    $botpk->import_key_raw($bot_x_pub, 'public');

    my $dh1 = $ephk->shared_secret($botpk);

    my $myx = Crypt::PK::X25519->new;
    $myx->import_key_raw($key->{x_priv}, 'private');
    my $dh2 = $myx->shared_secret($botpk);

    if ($dh1 eq ("\0" x 32) || $dh2 eq ("\0" x 32)) {
        substr($dh1, 0, length($dh1), "\0" x length($dh1));
        substr($dh2, 0, length($dh2), "\0" x length($dh2));
        die "key exchange produced a degenerate shared secret\n";
    }

    my $info = "ircbot-A2-v1" . $key->{x_pub} . $bot_x_pub;
    my $kmat = Crypt::KeyDerivation::hkdf($dh1 . $dh2, $eph_pub, 'SHA256', 32, $info);
    substr($dh1, 0, length($dh1), "\0" x length($dh1));
    substr($dh2, 0, length($dh2), "\0" x length($dh2));

    my $iv  = Crypt::PRNG::random_bytes(12);
    my $aad = "ircbot-A2-v1\0" . lc_ascii($botnick) . "\0" . lc_ascii($mynick);
    my ($ct, $tag) = Crypt::AuthEnc::GCM::gcm_encrypt_authenticate('AES', $kmat, $iv, $aad, $pt);

    substr($pt, 0, length($pt), "\0" x length($pt));
    substr($kmat, 0, length($kmat), "\0" x length($kmat));

    my $frame = $eph_pub . $iv . $ct . $tag;
    my $line  = '~A2 ' . encode_base64($frame, '');
    die "command is too long (" . length($line) . " > 400 chars on the wire)\n"
        if length($line) > 400;
    return $line;
}

# =============================================================================
# Client-side state and Irssi glue.  Everything below touches Irssi::.
# =============================================================================

use constant AUTH_TIMEOUT => 60;   # seconds a pending ~A2A stays valid
use constant MAX_QUEUE    => 5;    # queued commands per bot while authenticating

our %KEY_CACHE;   # "$net\x1e$bot_lc" => bot_pub64 (raw 64 bytes)
our %PENDING;     # same key         => [$tsn, $send_time]
our %QUEUE;       # same key         => [ $command_line, ... ]
our %DCC_NICK;    # same key         => our nick when we asked for the DCC chat

sub _ck { my ($net, $bot) = @_; return (defined $net ? $net : '') . "\x1e" . lc_ascii($bot); }

sub _expire_pending {
    my ($ck) = @_;
    my $p = $PENDING{$ck};
    return unless $p;
    return unless time() - $p->[1] > AUTH_TIMEOUT;
    delete $PENDING{$ck};
    my $q = delete $QUEUE{$ck};
    if ($q && @$q) {
        my (undef, $bot_lc) = split /\x1e/, $ck, 2;
        Irssi::print("bot_auth: auth with $bot_lc timed out; dropped "
                   . scalar(@$q) . ' queued command(s).');
    }
}

sub _load_key {
    my $path = Irssi::settings_get_str('bot_auth_keyfile');
    return (undef, 'no keyfile set — /set bot_auth_keyfile <path>')
        if !defined $path || !length $path;
    my $key = eval { load_key($path) };
    if ($@) {
        (my $e = $@) =~ s/\n\z//;
        return (undef, "keyfile error: $e");
    }
    return ($key, undef);
}

sub pin_lookup {
    my ($pinfile, $bot_lc) = @_;
    open(my $fh, '<', $pinfile) or return undef;
    while (my $line = <$fh>) {
        chomp $line;
        my ($nick, $val) = split ' ', $line, 2;
        next unless defined $nick && defined $val;
        return $val if $nick eq $bot_lc;
    }
    return undef;
}

sub pin_add {
    my ($pinfile, $bot_lc, $pub_b64) = @_;
    my $is_new = !-e $pinfile;
    open(my $fh, '>>', $pinfile) or return;
    print $fh "$bot_lc $pub_b64\n";
    close($fh);
    chmod(0600, $pinfile) if $is_new;
}

sub pin_remove {
    my ($pinfile, $bot_lc) = @_;
    open(my $fh, '<', $pinfile) or return;
    my @lines = <$fh>;
    close($fh);
    my @kept = grep {
        my ($nick) = split ' ', $_, 2;
        !(defined $nick && $nick eq $bot_lc);
    } @lines;
    if (@kept != @lines) {
        open(my $out, '>', $pinfile) or return;
        print $out @kept;
        close($out);
    }
}

sub _send_auth {
    my ($server, $bot_nick, $mynick, $key) = @_;
    my ($line, $tsn) = eval { build_auth($key, $bot_nick, $mynick) };
    if ($@ || !defined $line) {
        (my $e = $@) =~ s/\n\z//;
        Irssi::print("bot_auth: failed to build auth request: $e");
        return;
    }
    $PENDING{_ck($server->{tag}, $bot_nick)} = [$tsn, time()];
    $server->command("QUOTE PRIVMSG $bot_nick :$line");
    Irssi::print("bot_auth: authenticating with $bot_nick...");
}

# The open DCC chat with $bot_nick on this network, if any.
sub _dcc_chat {
    my ($server, $bot_nick) = @_;
    for my $dcc (Irssi::Irc::dccs()) {
        next unless $dcc->{type} eq 'CHAT' && $dcc->{starttime};
        next unless lc_ascii($dcc->{nick}) eq lc_ascii($bot_nick);
        next if $server && $dcc->{servertag} && $dcc->{servertag} ne $server->{tag};
        return $dcc;
    }
    return undef;
}

# A command goes down the bot's DCC chat when one is open, else by PRIVMSG.
# On the chat the bot takes the sender nick to be the one that asked for it.
sub _send_command {
    my ($server, $bot_nick, $mynick, $key, $bot_pub64, $command_line) = @_;
    my $ck  = _ck($server->{tag}, $bot_nick);
    my $dcc = _dcc_chat($server, $bot_nick);
    my $as  = $dcc ? ($DCC_NICK{$ck} // $mynick) : $mynick;
    my $line = eval { build_command($key, $bot_pub64, $bot_nick, $as, $command_line) };
    if ($@) {
        (my $e = $@) =~ s/\n\z//;
        Irssi::print("bot_auth: $e");
        return;
    }
    if ($dcc) {
        Irssi::Irc::dcc_chat_send($dcc, $line);
        return;
    }
    $DCC_NICK{$ck} = $mynick if $command_line =~ /^dcc(?:\s|$)/i;
    $server->command("QUOTE PRIVMSG $bot_nick :$line");
}

sub _handle_botcmd {
    my ($server, $bot_nick, $command_line) = @_;

    my ($key, $err) = _load_key();
    return Irssi::print("bot_auth: $err") if $err;
    Irssi::print("bot_auth: " . $key->{warning}) if $key->{warning};

    my $ck = _ck($server->{tag}, $bot_nick);
    _expire_pending($ck);

    my $bot_pub64 = $KEY_CACHE{$ck};
    if (defined $bot_pub64) {
        _send_command($server, $bot_nick, $server->{nick}, $key, $bot_pub64, $command_line);
        return;
    }

    my $q = ($QUEUE{$ck} //= []);
    if (@$q >= MAX_QUEUE) {
        Irssi::print("bot_auth: queue for $bot_nick is full (max " . MAX_QUEUE . '); dropping oldest.');
        shift @$q;
    }
    push @$q, $command_line;

    if ($PENDING{$ck}) {
        Irssi::print("bot_auth: already authenticating with $bot_nick; command queued.");
        return;
    }
    _send_auth($server, $bot_nick, $server->{nick}, $key);
}

sub cmd_botcmd {
    my ($data, $server, $witem) = @_;
    return Irssi::print(cryptx_hint()) if !$CRYPTX_OK;

    if (!$server || !$server->{connected}) {
        $server = $witem->{server} if $witem && $witem->{server};
        return Irssi::print('bot_auth: not connected to a server.')
            if !$server || !$server->{connected};
    }

    my ($bot_nick, @rest) = split /\s+/, ($data // '');
    return Irssi::print('Usage: /botcmd <bot_nick> <command> [args...]')
        if !defined $bot_nick || !length $bot_nick || !@rest;

    _handle_botcmd($server, $bot_nick, join(' ', @rest));
}

sub cmd_botauth {
    my ($data, $server, $witem) = @_;
    return Irssi::print(cryptx_hint()) if !$CRYPTX_OK;

    if (!$server || !$server->{connected}) {
        $server = $witem->{server} if $witem && $witem->{server};
        return Irssi::print('bot_auth: not connected to a server.')
            if !$server || !$server->{connected};
    }

    my ($bot_nick) = split /\s+/, ($data // '');
    return Irssi::print('Usage: /botauth <bot_nick>')
        if !defined $bot_nick || !length $bot_nick;

    my ($key, $err) = _load_key();
    return Irssi::print("bot_auth: $err") if $err;

    delete $KEY_CACHE{_ck($server->{tag}, $bot_nick)};
    _send_auth($server, $bot_nick, $server->{nick}, $key);
}

sub cmd_botforget {
    my ($data, $server, $witem) = @_;
    $server = $witem->{server} if !$server && $witem && $witem->{server};

    my ($bot_nick) = split /\s+/, ($data // '');
    return Irssi::print('Usage: /botforget <bot_nick>')
        if !defined $bot_nick || !length $bot_nick;

    my $net = $server ? $server->{tag} : '';
    my $ck  = _ck($net, $bot_nick);
    my $had = exists $KEY_CACHE{$ck};
    delete $KEY_CACHE{$ck};
    delete $PENDING{$ck};
    delete $QUEUE{$ck};
    delete $DCC_NICK{$ck};

    my $pinfile = Irssi::settings_get_str('bot_auth_pinfile');
    pin_remove($pinfile, lc_ascii($bot_nick)) if defined $pinfile && length $pinfile;

    Irssi::print("bot_auth: forgot $bot_nick" . ($had ? '' : ' (was not cached)') . '.');
}

# "event notice" args: ($server, $data, $nick, $address) — $nick/$address are
# already split from the sender prefix by Irssi.  $data is "<target> :<text>".
sub sig_notice {
    my ($server, $data, $nick, $address) = @_;
    return if !defined $data;
    my ($target, $text) = $data =~ /^(\S+)\s+:(.*)$/s;
    return if !defined $text;
    return unless $text =~ /^~A2K /;

    # Protocol traffic: always hidden, whether or not we can process it.
    Irssi::signal_stop();
    return if !$CRYPTX_OK;
    return if !$server;

    my $mynick = $server->{nick};
    my $ck     = _ck($server->{tag}, $nick);
    _expire_pending($ck);

    my $pend = delete $PENDING{$ck};
    return if !$pend;   # no matching request: drop silently
    my ($tsn) = @$pend;

    my ($key, $err) = _load_key();
    return Irssi::print("bot_auth: $err") if $err;

    my $b64 = substr($text, 5);
    my $bot_pub64 = open_lockbox($key, $nick, $mynick, $tsn, $b64);
    if (!defined $bot_pub64) {
        Irssi::print("bot_auth: ~A2K from $nick failed to decrypt/verify; ignored.");
        return;
    }

    my $pinfile = Irssi::settings_get_str('bot_auth_pinfile');
    if (defined $pinfile && length $pinfile) {
        my $bot_lc    = lc_ascii($nick);
        my $existing  = pin_lookup($pinfile, $bot_lc);
        my $got_b64   = encode_base64($bot_pub64, '');
        if (!defined $existing) {
            pin_add($pinfile, $bot_lc, $got_b64);
        } elsif ($existing ne $got_b64) {
            my $existing_raw = eval { decode_base64($existing) };
            Irssi::print(sprintf(
                "bot_auth: WARNING pinned-key mismatch for %s! pinned %s got %s "
              . "-- possible man-in-the-middle, or the bot was rekeyed. "
              . "Run /botforget %s to accept the new key.",
                $nick,
                (defined $existing_raw ? fingerprint($existing_raw) : '?'),
                fingerprint($bot_pub64), $nick));
            return;   # do NOT cache on a pin mismatch
        }
    }

    $KEY_CACHE{$ck} = $bot_pub64;
    Irssi::print("bot_auth: authenticated with $nick — key " . fingerprint($bot_pub64));

    my $q = delete $QUEUE{$ck};
    if ($q) {
        _send_command($server, $nick, $mynick, $key, $bot_pub64, $_) for @$q;
    }
}

sub timer_check {
    _expire_pending($_) for keys %PENDING;
}

# Registration is guarded so this file can be `do`-loaded under a minimal
# stub Irssi package (a test harness) without dying before the pure functions
# above (load_key/build_auth/open_lockbox/build_command/fingerprint) exist.
eval {
    Irssi::settings_add_str('bot_auth', 'bot_auth_keyfile', '');
    Irssi::settings_add_str('bot_auth', 'bot_auth_pinfile', '');
    Irssi::command_bind('botcmd',    \&cmd_botcmd);
    Irssi::command_bind('botauth',   \&cmd_botauth);
    Irssi::command_bind('botforget', \&cmd_botforget);
    Irssi::signal_add_first('event notice', \&sig_notice);
    Irssi::timeout_add(5000, \&timer_check, undef);

    Irssi::print("Bot Authenticator v$VERSION (~A2 / key-based, passwordless) loaded.");
    if ($CRYPTX_OK) {
        Irssi::print('Set /set bot_auth_keyfile <path> to your .private.b64, '
                   . 'then /botcmd <bot> <command>.');
    } else {
        Irssi::print(cryptx_hint());
        Irssi::print('/botcmd stays registered but will refuse to send until then.');
    }
    1;
} or warn "bot_auth: registration under a limited Irssi stub: $@";

1;
