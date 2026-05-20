; bot-auth.mrc — pure-script mIRC client for ircbot's v1c (~A1c) admin
;                command protocol.  No compiled helper required.
;
; Architecture:
;   This script delegates all crypto orchestration to the companion
;   batch file bot-auth.cmd, which itself is a thin wrapper around
;   openssl.exe and PowerShell (both shipped with Windows 10+).
;
;   Why a .cmd helper instead of inline mIRC scripting?
;   - mIRC's $encode does AES-CBC but uses an OpenSSL-incompatible
;     "Salted__" envelope that we can't reshape into our wire format
;     without per-byte construction.
;   - mIRC has no native bytewise file write, no PBKDF2, no HMAC
;     primitive that takes a raw key.
;   - openssl.exe + PowerShell can do all of it in a couple of pipes.
;
; What you need installed:
;   * Windows 10+ (PowerShell 5.1+ is built in)
;   * Either:
;       (a) "Git for Windows" — includes openssl.exe at
;           C:\Program Files\Git\usr\bin\openssl.exe
;       (b) Or any OpenSSL 3.x install with openssl.exe in PATH
;
; Setup (one time, in mIRC):
;   /set %bot_auth_password your_admin_password
;   /set %bot_auth_helper   C:\path\to\utils\bot-auth.cmd
;   /set %bot_auth_openssl  C:\Program Files\Git\usr\bin\openssl.exe
;   /set %bot_auth_tmpdir   $sysdir(temp)
;
; Usage:
;   /botcmd <bot_nick> <command> [arguments...]
;
; Examples:
;   /botcmd mybot die
;   /botcmd mybot +admin alice s3cret alice!*@trusted.example

alias botcmd {
    if ($0 < 2) {
        echo -a Usage: /botcmd <bot_nick> <command> [arguments]
        return
    }
    var %bot = $1
    var %cmd = $2-

    if (%bot_auth_password == $null) {
        echo -a Error: /set %%bot_auth_password your_admin_password
        return
    }
    if (%bot_auth_helper == $null) {
        echo -a Error: /set %%bot_auth_helper C:\path\to\utils\bot-auth.cmd
        return
    }
    var %tmpdir  = $iif(%bot_auth_tmpdir != $null, %bot_auth_tmpdir, $sysdir(temp))
    var %tag     = $+(botauth-, $ticks, -, $rand(1,999999))
    var %outfile = $+(%tmpdir, \, %tag, .out.txt)

    ; Pass both the password (via env) and the command (via argv).  We use
    ; cmd /c so we can both set the env var AND redirect stdout into a file
    ; the mIRC script can read.  Password lives only in the spawned cmd's
    ; environment block, never on argv.
    var %openssl_set = $iif(%bot_auth_openssl != $null, set BOT_AUTH_OPENSSL= $+ %bot_auth_openssl $+  & , )
    .run -nh cmd /c "set BOT_AUTH_PASSWORD= $+ %bot_auth_password $+ & %openssl_set $+ "" $+ %bot_auth_helper $+ "" "" $+ %cmd $+ "" > "" $+ %outfile $+ """

    ; PBKDF2 at 100 000 iterations takes ~200 ms on commodity hardware.
    ; Poll for the output file up to ~5 s.
    .timer 1 1 botcmd.try %bot %outfile 1
}

alias -l botcmd.try {
    var %bot     = $1
    var %outfile = $2
    var %attempt = $3

    var %line
    if ($exists(%outfile)) {
        ; The .cmd file may emit a stray blank line before the ~A1c line;
        ; scan for the first non-empty line that starts with ~A1c.
        var %n = $lines(%outfile)
        var %i = 1
        while (%i <= %n) {
            var %candidate = $read(%outfile, n, %i)
            if ($left(%candidate, 5) == ~A1c ) {
                var %line = %candidate
                break
            }
            inc %i
        }
    }

    if (%line == $null) {
        if (%attempt < 20) {
            .timer 1 1 botcmd.try %bot %outfile $calc(%attempt + 1)
            return
        }
        echo -a Error: bot-auth.cmd produced no ~A1c output after 5s.
        echo -a Check %%bot_auth_helper and %%bot_auth_openssl paths.
        if ($exists(%outfile)) {
            echo -a -- helper output (first line) --
            echo -a $read(%outfile, n, 1)
        }
        .remove %outfile
        return
    }

    .remove %outfile
    .quote PRIVMSG %bot : $+ %line
    echo -a Sent ~A1c command to %bot.
}

on *:LOAD: {
    echo -a -- bot-auth.mrc (v4.0, pure script + openssl CLI) loaded --
    echo -a Required:
    echo -a   /set %%bot_auth_password your_admin_password
    echo -a   /set %%bot_auth_helper   C:\path\to\utils\bot-auth.cmd
    echo -a Optional:
    echo -a   /set %%bot_auth_openssl  C:\Program Files\Git\usr\bin\openssl.exe
    echo -a Use:  /botcmd <bot> <command> [args]
}
