#!/bin/bash

# user_greet.sh
# This script greets the logged-in user and shows the current date and time.

# '$USER' is a built-in variable containing the current username.
USER_NAME=$USER

# 'date' prints the current system date and time.
CURRENT_DATE=$(date)

echo "Hello, $USER_NAME!"
echo "Today is $CURRENT_DATE."
echo "Welcome to your terminal!"
