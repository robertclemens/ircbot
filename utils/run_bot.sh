#!/bin/bash

#########################################################################################
# Set your config password
CONFIG_PASS="configpassword"

# Define the variables as you have them in bot.h
PID_FILE=".ircbot.pid" # PID file name, must match bot.h #define PID_FILE
ENV_VAR="BOT_PASS"     # ENV variable name, must match bot.h #define CONFIG_PASS_ENV_VAR
#########################################################################################


# Navigate to the bot's directory
cd "$(dirname "$0")"

# Check if the lock file exists
if [ -e "$PID_FILE" ]; then
    # If the lock file exists, check if the process is still running
    PID=$(cat "$PID_FILE")
    if ps -p "$PID" > /dev/null; then
        echo "Bot is already running (PID: $PID). Exiting."
        exit 1
    else
        # The process is not running, but the lock file was left behind. Remove it.
        echo "Found stale lock file. Removing."
        rm -f "$PID_FILE"
    fi
fi

# Set the password and run the bot
$ENV_VAR="$CONFIG_PASS" ./ircbot &
