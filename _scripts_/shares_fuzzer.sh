#!/bin/bash

TARGET="_target_" # Don't forget to update the target
WORDLIST="/root/Desktop/wordlists/shares.txt"

# Check if the wordlist file exists
if [ ! -f "$WORDLIST" ]; then
    echo "[*] Wordlist not found: $WORDLIST"
    exit 1
fi

# Loop through each share in the wordlist
while read -r SHARE; do
    smbclient //$TARGET/$SHARE -N -c "ls" &>/dev/null
    if [ $? -eq 0 ]; then
        echo "[+] Anonymous access allowed for: $SHARE"
    fi
done < "$WORDLIST"