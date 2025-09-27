#!/bin/bash

##########################################
# Set your config password
CONFIG_PASS="configpassword"

# Define the lock file path.
# This should be correct unless
# you edited bot.h for the PID_FILE value
PID_FILE=".ircbot.pid"

###########################################


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
BOT_PASS="$CONFIG_PASS" ./ircbot &
