# Pivoting

## With MSF
```bash
# at meterpreter stage
ifconfig
run autoroute -s <target_network>
background

use auxiliary/scanner/portscan/tcp
set RHOSTS <target_2>
set PORTS 1-1000
run

sessions -i 1
portfwd add -l <local_port> -p <remote_port> -r <target_2>
portfwd list

nmap -sS -sV -p <local_port> localhost
```
