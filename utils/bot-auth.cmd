@echo off
REM ============================================================================
REM bot-auth.cmd  --  Windows batch counterpart to bot-auth.sh.  Builds a v1c
REM                  (~A1c) AES-256-CBC + HMAC-SHA256 admin command payload
REM                  for ircbot.  No compiled helper, no Python, no Perl
REM                  modules: only openssl.exe (shipped with Git for Windows).
REM
REM Usage:
REM     set BOT_AUTH_PASSWORD=hunter2
REM     bot-auth.cmd "die"
REM     bot-auth.cmd "+admin alice s3cret alice!*@trusted.example"
REM
REM Output (stdout, one line):
REM     ~A1c <base64-blob>
REM
REM Required environment variables:
REM     BOT_AUTH_PASSWORD    - the admin/oper password (required)
REM     BOT_AUTH_OPENSSL     - path to openssl.exe (optional; defaults to PATH)
REM ============================================================================

setlocal EnableExtensions EnableDelayedExpansion

if "%~1"=="" (
    echo Usage: %~nx0 "<command line, with args>" 1>&2
    exit /b 1
)
if not defined BOT_AUTH_PASSWORD (
    echo Error: BOT_AUTH_PASSWORD not set 1>&2
    exit /b 2
)
set "CMD=%~1"

set "OPENSSL=openssl.exe"
if defined BOT_AUTH_OPENSSL set "OPENSSL=%BOT_AUTH_OPENSSL%"

REM Use a per-run temp prefix so concurrent calls don't clobber each other.
set "TS=%RANDOM%%RANDOM%"
set "PFX=%TEMP%\botauth-%TS%"

REM ---- 1) Generate random material ------------------------------------------
for /f "tokens=*" %%a in ('"%OPENSSL%" rand -hex 16')         do set "SALT=%%a"
for /f "tokens=*" %%a in ('"%OPENSSL%" rand -hex 16')         do set "IV=%%a"
for /f "tokens=*" %%a in ('"%OPENSSL%" rand -hex 8')          do set "NONCE_HEX=%%a"

REM Convert nonce hex -> decimal, masking top bit so it stays positive
REM as a 64-bit signed integer.  cmd has no 64-bit arithmetic, so we use
REM PowerShell for the conversion (PowerShell ships with Windows since 7.x).
for /f "tokens=*" %%a in ('powershell -NoProfile -Command "[uint64]('0x' + '%NONCE_HEX%') -band 0x7FFFFFFFFFFFFFFF"') do set "NONCE=%%a"
for /f "tokens=*" %%a in ('powershell -NoProfile -Command "[int][double]::Parse((Get-Date -UFormat %%s))"') do set "TS_EPOCH=%%a"

REM ---- 2) Derive 64 bytes via PBKDF2 ----------------------------------------
"%OPENSSL%" kdf -keylen 64 -kdfopt digest:SHA256 -kdfopt pass:"%BOT_AUTH_PASSWORD%" -kdfopt hexsalt:%SALT% -kdfopt iter:100000 -binary PBKDF2 > "%PFX%.keys" 2>nul
if errorlevel 1 (
    echo Error: PBKDF2 failed.  Needs OpenSSL 3.0+. 1>&2
    del /q "%PFX%.keys" 2>nul
    exit /b 3
)

REM Split 64 bytes into enc_key (first 32) and mac_key (last 32).
powershell -NoProfile -Command ^
    "$b=[IO.File]::ReadAllBytes('%PFX%.keys');" ^
    "[IO.File]::WriteAllBytes('%PFX%.enc.bin', $b[0..31]);" ^
    "[IO.File]::WriteAllBytes('%PFX%.mac.bin', $b[32..63]);" ^
    "Write-Output (([BitConverter]::ToString($b[0..31]) -replace '-','').ToLower()) | Out-File -Encoding ASCII '%PFX%.enc.hex';" ^
    "Write-Output (([BitConverter]::ToString($b[32..63]) -replace '-','').ToLower()) | Out-File -Encoding ASCII '%PFX%.mac.hex'"
set /p ENC_KEY=<"%PFX%.enc.hex"
set /p MAC_KEY=<"%PFX%.mac.hex"
del /q "%PFX%.keys" "%PFX%.enc.bin" "%PFX%.mac.bin" "%PFX%.enc.hex" "%PFX%.mac.hex" 2>nul

REM ---- 3) Encrypt plaintext "<ts>:<nonce>:<command>" via AES-256-CBC -------
> "%PFX%.pt" set /p =%TS_EPOCH%:%NONCE%:%CMD%<nul
"%OPENSSL%" enc -aes-256-cbc -K %ENC_KEY% -iv %IV% -in "%PFX%.pt" -out "%PFX%.ct"
if errorlevel 1 (
    echo Error: AES-CBC encrypt failed. 1>&2
    del /q "%PFX%.pt" "%PFX%.ct" 2>nul
    exit /b 4
)
del /q "%PFX%.pt"

REM ---- 4) HMAC-SHA256(mac_key, salt || iv || ciphertext) -------------------
REM Build the input file: salt+iv as binary, then append ciphertext.
powershell -NoProfile -Command ^
    "$salt=[Convert]::FromHexString('%SALT%');" ^
    "$iv=[Convert]::FromHexString('%IV%');" ^
    "$ct=[IO.File]::ReadAllBytes('%PFX%.ct');" ^
    "$buf = $salt + $iv + $ct;" ^
    "[IO.File]::WriteAllBytes('%PFX%.macin', $buf)"

for /f "tokens=2 delims= " %%a in ('"%OPENSSL%" dgst -sha256 -mac HMAC -macopt hexkey:%MAC_KEY% "%PFX%.macin"') do set "HMAC=%%a"
del /q "%PFX%.macin"

REM ---- 5) Assemble salt || iv || ciphertext || hmac and base64-wrap --------
powershell -NoProfile -Command ^
    "$salt=[Convert]::FromHexString('%SALT%');" ^
    "$iv=[Convert]::FromHexString('%IV%');" ^
    "$ct=[IO.File]::ReadAllBytes('%PFX%.ct');" ^
    "$mac=[Convert]::FromHexString('%HMAC%');" ^
    "$blob = $salt + $iv + $ct + $mac;" ^
    "Write-Output ('~A1c ' + [Convert]::ToBase64String($blob))"

del /q "%PFX%.ct" 2>nul
endlocal
