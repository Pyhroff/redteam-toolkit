# Wordlists

Don't store large wordlists in git. Download them separately.

## Recommended: SecLists

```bash
# Clone the entire SecLists repo (large — ~1GB)
git clone https://github.com/danielmiessler/SecLists.git

# Or download individual files:
# Passwords
curl -O https://raw.githubusercontent.com/danielmiessler/SecLists/master/Passwords/Common-Credentials/10-million-password-list-top-1000.txt

# Subdomains
curl -O https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/DNS/subdomains-top1million-5000.txt

# Web directories
curl -O https://raw.githubusercontent.com/danielmiessler/SecLists/master/Discovery/Web-Content/directory-list-2.3-small.txt
```

## Quick test wordlists (create these for local lab testing)

**passwords.txt** — put your lab VM's actual passwords in here to verify cracking works  
**subdomains.txt** — common subdomain prefixes: www, mail, dev, admin, api, vpn, ftp, test  
**dirs.txt** — common web paths: admin, login, dashboard, api, backup, config, uploads, .git

## Kali Linux built-in paths

If you're on Kali or have rockyou installed:
```
/usr/share/wordlists/rockyou.txt
/usr/share/seclists/
/usr/share/wordlists/dirbuster/
```
