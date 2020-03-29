#!/bin/bash
while read LINE; do
  curl -o "$LINE" --silent --head --write-out "%{http_code} $LINE\n" "$LINE"
done < "$1"
