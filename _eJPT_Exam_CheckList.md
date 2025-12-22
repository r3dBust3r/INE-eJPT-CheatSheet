# eJPT Exam CheckList

## Information Gathering & Reconnaissance
The most common reason for failing is missing a hidden service.

- [ ] **Identify the Network Range:** Check your IP and find the target subnet.
- [ ] **Host Discovery:** Use `fping` or `nmap -sn` to find live hosts.
- [ ] **Service Scanning:** Run a full TCP port scan (`-p-`).
- [ ] Run a targeted UDP scan for common ports (DNS, SNMP, DHCP).
- [ ] Version detection (`-sV`) and default scripts (`-sC`).
- [ ] **Analyze the Output:** Look for "low-hanging fruit" like Telnet, FTP, or old versions of SMB.

## Enumeration (The "Make or Break" Phase)
Go deep into every open port you found.

### **HTTP/HTTPS (Web):**
- [ ] Directory busting (`gobuster`, `dirsearch`, or `ffuf`). Scan for extensions like `.php`, `.txt`, `.bak`, `.old`, `.zip`, `.config`, `.xml`.
- [ ] Check `robots.txt` and source code for comments/credentials.
- [ ] Manual Inspection: **View Source** (look for comments/hidden paths).
- [ ] Identify CMS (WordPress, Joomla) using `wpscan` or `whatweb`.
- [ ] Vulnerability Scanning: Run `nikto -h [URL]` for quick wins.
- [ ] Login Forms: Try default credentials (`admin:admin`, `guest:guest`, `root:root`).

### **SMB (139/445):**
- [ ] List shares (`smbclient -L`).
- [ ] Check for null sessions/anonymous logins.
- [ ] Enumerate users/groups (`enum4linux` or `rpclient`).
- [ ] Vulnerability Check: Check for EternalBlue or BlueKeep.

### **SNMP (161):**
- [ ] Brute-force community strings (e.g., `public`, `private`).
- [ ] Enumerate processes and network info (`snmpwalk`).

### **FTP (21):**
- [ ] Check for anonymous login.
- [ ] Check for directory listing and "hidden" files.
- [ ] Check if you can upload files (write access).
- [ ] Check if it's an exploitable version.

### **SSH (22):**
- [ ] Usually secure, but check for old versions
- [ ] Try credentials found elsewhere.


## Exploitation & Vulnerability Assessment
Only attempt exploitation once you have a clear target.

- [ ] **Search for Exploits:** Use `searchsploit` or Google for the specific version numbers found.
- [ ] **Metasploit vs. Manual:** First, check if a Metasploit module exists.
- [ ] **Brute Forcing:** If you found usernames but no exploit, try `hydra` on SSH, FTP, HTTP, MySQL, etc.
- [ ] **Manual Exploits:** If using a `.py` or `.c` exploit from Exploit-DB, read the code to see if you need to change something.
- [ ] **Verify Findings:** If a question asks for a specific file content (e.g., `flag.txt`), ensure you have a stable shell to read it.

## Post-Exploitation & Pivoting
The eJPT often requires you to move from one machine to another.

- [ ] **System Info:** Check `whoami`, `hostname`, and OS version.
- [ ] **Local Enumeration:** Look for configuration files or cleartext passwords in `/home` or `C:\Users`.
- [ ] **Network Pivoting:**
- [ ] Check for other network interfaces (`ifconfig` or `ip route`).
- [ ] Set up an **Autoroute** in Metasploit if you find a second subnet.
- [ ] Use **Port Forwarding** to access services hidden behind the first machine.
- [ ] `hostname` (Does it match the exam question?)
- [ ] **The Pivot Find:** **CRITICAL.** Run `ip route`, `ifconfig`, or `ip a`. Look for a subnet you haven't scanned yet.
- [ ] Metasploit: `run autoroute -s [new_subnet]` and use the `auxiliary/server/socks_proxy`.
- [ ] Manual: Use `chisel` or SSH local port forwarding.

## Data Recovery & Answer Verification

- [ ] **Question Alignment:** Open the exam questions. Does a question ask for a specific user's password? Check your notes for hashes or cleartext.
- [ ] **Flag Hunting:**
- [ ] Linux: `find / -name "*.txt" | grep flag`
- [ ] Windows: `dir /s /p C:\flag.txt`
- [ ] **Final Check:** Ensure you have answered **every** multiple-choice question based on the data you extracted.


## The "Golden Rules" for the eJPT

- [ ] **Read Every Question First:** Sometimes the questions give hints about what services to look for.
- [ ] **Don't Overthink:** The eJPT is a "Junior" exam. If you’re trying a complex binary exploitation, you’ve likely missed a simple web vulnerability or a default password.
- [ ] **Double-Check Answers:** Ensure you aren't mixing up "Host A" findings with "Host B" answers.
- [ ] **Check Routing:** If you can't "see" a machine, check your routing table (`ip route`). You might need to add a static route to the internal network.

## Troubleshooting (The "Emergency" List)

* [ ] **Shell Keep-Alive:** If your shell keeps dying, check if there is a firewall or an automated script killing processes. Try a different port.
* [ ] **Routing Errors:** If you can't ping a machine in a pivoted network, remember: **ICMP (ping) often doesn't travel through a SOCKS proxy.** Use Nmap through `proxychains`.
* [ ] **False Negatives:** If Nmap says a port is closed but you suspect it's open, try `nmap -Pn` (ignore ping) or a different scan type (`-sS` vs `-sT`).

### Tip:
If you get stuck on a network issue, keep this logic in mind:

**Scanning -> Enumeration -> Exploitation -> Pivoting.**
