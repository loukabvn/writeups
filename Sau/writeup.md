# [Sau](https://app.hackthebox.com/machines/Sau) - 03/08/2023 - HackTheBox write-up

## User flag

### Discovery

Starting with ̀`nmap` we can found 3 distinct services :
```
Nmap scan report for 10.10.11.224
Host is up (0.034s latency).
Not shown: 65531 closed tcp ports (conn-refused)
PORT      STATE    SERVICE
22/tcp    open     ssh
80/tcp    filtered http
55555/tcp open     unknown
```

A SSH, a filtered HTTP server and a unknown service on port 55555. By visiting *http://10.10.11.224:55555/* we can found that this last service is an HTTP server too.

It's a *requests-baskets* service. We can create endpoints and then all the requests send to this endpoints are logged in the corresponding page. This services doesn't expose too much functionalities so I search instead for CVE in the *requests-baskets* in version 1.2.1.

### Searching for vulnerability

Quickly we can found one, all the requests send to the created basket can be forwarded without verification (CVE-2023-27163). So we can access to the other filtered HTTP server on port 80. Here we found a *Maltrail* service, who inspect the traffic to find any malicious requests.

This service is in version 0.53 and is also vulnerable to a RCE on the login page.

### Exploitation

So, by exploiting both vulnerabilities we can forward all the traffic send to a basket to the *Maltrail* service, and then use the RCE to start a reverse shell with the server.

After connecting to the reverse shell, we are logged as user *puma* and so we can directly read the user flag.

## Root flag

### Searching for elevating privileges

The root flag was pretty easy, by running `sudo -l` we can found that the following command is runnable as `root` user:
```bash
$ sudo -l
[...]
    (ALL: ALL NOPASSWD) /usr/bin/systemctl status trail.service
```

### Exploitation

After some we can found that in the command `systemctl` we can run a shell inside (because it used the `less` command).

So we just need to run the command `!sh` in the previous command and we got a root shell.
