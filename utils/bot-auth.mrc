; bot-auth.mrc — mIRC script to generate a v1 (~A1) AES-256-GCM admin command
;                payload for ircbot.
;
; Why a helper:
;   mIRC's native $encode does not support AES-GCM (only AES-CBC).  This
;   script shells out to the bash helper (bot-auth.sh) via /run, captures
;   its output, and sends the resulting line via /quote.
;
; Setup:
;   1) Install Git Bash, WSL, or any POSIX sh on Windows, plus python3 with
;      'cryptography' (pip install cryptography) OR perl with CryptX.
;   2) Place bot-auth.sh somewhere reachable, e.g. C:\ircbot\bot-auth.sh
;   3) /set %bot_auth_helper c:\ircbot\bot-auth.sh
;   4) /set %bot_auth_password <your admin password>          ; KEEP THIS SECRET
;   5) /set %bot_auth_tmpdir   c:\Users\<you>\AppData\Local\Temp
;
; Usage:
;   /botcmd <bot_nick> <command> [arguments]
; e.g.:
;   /botcmd mybot die
;   /botcmd mybot +admin alice s3cret alice!*@trusted.example

alias botcmd {
    if ($0 < 2) {
        echo -a Usage: /botcmd <bot_nick> <command> [arguments]
        return
    }
    var %bot   = $1
    var %cmd   = $2-

    if (%bot_auth_helper == $null) {
        echo -a Error: %%bot_auth_helper is not set. /set %%bot_auth_helper c:\path\to\bot-auth.sh
        return
    }
    if (%bot_auth_password == $null) {
        echo -a Error: %%bot_auth_password is not set. /set %%bot_auth_password your_admin_password
        return
    }
    var %tmpdir = $iif(%bot_auth_tmpdir != $null, %bot_auth_tmpdir, $sysdir(temp))
    var %outfile = %tmpdir $+ \botauth- $+ $ticks $+ - $+ $rand(1,99999) $+ .txt

    ; Build the helper invocation. We export the password via env so it
    ; never appears in argv.  Helper writes "~A1 <b64>" to stdout, we
    ; redirect into %outfile, then read and quote it.
    var %quoted_cmd = $qt(%cmd)
    var %sh = bash -c "export BOT_AUTH_PASSWORD=' $+ %bot_auth_password $+ '; ' $+ %bot_auth_helper $+ ' " $+ %quoted_cmd $+ " > ' $+ %outfile $+ '"

    ; /run is fire-and-forget; we wait briefly then read the file.
    .run -h cmd /c %sh
    .timer 1 1 botcmd.send %bot %outfile
}

alias -l botcmd.send {
    var %bot     = $1
    var %outfile = $2
    var %line    = $read(%outfile, n, 1)
    if (%line == $null) {
        ; retry once after a slightly longer wait — Windows /run can lag
        .timer 1 2 botcmd.send.retry %bot %outfile
        return
    }
    .remove %outfile
    if ($left(%line,4) != ~A1 ) {
        echo -a Error: helper produced unexpected output: %line
        return
    }
    .quote PRIVMSG %bot : $+ %line
    echo -a Sent ~A1 command to %bot via helper.
}

alias -l botcmd.send.retry {
    var %bot     = $1
    var %outfile = $2
    var %line    = $read(%outfile, n, 1)
    .remove %outfile
    if (%line == $null) {
        echo -a Error: helper produced no output. Check %%bot_auth_helper.
        return
    }
    if ($left(%line,4) != ~A1 ) {
        echo -a Error: helper produced unexpected output: %line
        return
    }
    .quote PRIVMSG %bot : $+ %line
    echo -a Sent ~A1 command to %bot via helper.
}

on *:LOAD: {
    echo -a bot-auth.mrc loaded — use /botcmd <bot> <command> [args]
    echo -a Required mIRC variables: %%bot_auth_helper (path to bot-auth.sh)
    echo -a                          %%bot_auth_password (your admin pass)
}
