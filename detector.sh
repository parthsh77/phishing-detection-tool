#!/bin/bash


if [ -z "$1" ]; then
    echo "Usage: $0 <URL>"
    exit 1
fi

URL=$1
DOMAIN=$(echo "$URL" | awk -F/ '{print $3}')


if grep -Fxq "$DOMAIN" blacklist.txt; then
    echo "Domain is in the phishing blacklist!"
else
    echo "Domain is not in the blacklist."
fi

echo "Running WHOIS lookup for $DOMAIN..."
whois "$DOMAIN" | grep -Ei "creation date|expiry date|registrar"

echo "Checking SSL certificate for $DOMAIN..."
openssl s_client -connect "$DOMAIN:443" -servername "$DOMAIN" < /dev/null 2>/dev/null | openssl x509 -noout -dates
