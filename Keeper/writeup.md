# [Keeper](https://app.hackthebox.com/machines/Keeper) - 21/08/2023 - HackTheBox write-up

## User flag

### Discovery

A first `nmap` does not give us any hints, just an HTTP and a SSH server. At the IP we found a *Requests Tracker* application in version 4.4.4.

### Search for vulnerability

There is a login page, where I tried some default credentials. It didn't work so I've search for CVEs.

I don't find any CVEs, and I think about default credentials of the *Requests Tracker* application. I found the default credentials : `root:password`, and it works, I can connect as `root`.

### Exploitation

Once connected, we can find a ticket, about a *Keepass* crash. We can also find a comment with the default password of a newly created account : `lnorgaard:Welcome2023!`.

There isn't other interesting things so, I tried this credentials to the SSH server and it works, we could connect as `lnorgaard` and get the user flag.

## Root flag

Now here, we can found an archive with a Keepass password database (`passcodes.kdbx`) and a crash dump with a running Keepass application (`KeePassDumpFull.dmp`). After running `linpeas`, I didn't find anything else interesting, so it must be with this files only.

### Search for vulnerability

After some researches, I found the CVE-2023-32784, affecting Keepass 2.X before 2.54. This CVE allows an attacker to exploit a dump with KeePass running, to found the master key.

### Exploitation

So, I've found an exploit in Python ([link](https://github.com/vdohney/keepass-password-dumper)), and I ran it and found this :
```bash
$ python CVE-2023-32784.py ./KeePassDumpFull.dmp
2023-08-21 14:55:39,060 [.] [main] Opened ./KeePassDumpFull.dmp
Possible password: ●,dgr●d med fl●de
Possible password: ●ldgr●d med fl●de
Possible password: ●`dgr●d med fl●de
Possible password: ●-dgr●d med fl●de
Possible password: ●'dgr●d med fl●de
Possible password: ●]dgr●d med fl●de
Possible password: ●Adgr●d med fl●de
Possible password: ●Idgr●d med fl●de
Possible password: ●:dgr●d med fl●de
Possible password: ●=dgr●d med fl●de
Possible password: ●_dgr●d med fl●de
Possible password: ●cdgr●d med fl●de
Possible password: ●Mdgr●d med fl●de
```

The account found before was Danish, so after a few researches and help of Google Translate I've found that the password is : `rødgrød med fløde`, a Danish speciality.

We can now decrypt the KeePass database with the key and we found an entry with a password and some comments. The password doesn't work but there is a SSH private key in the comments. I had some problems with OpenSSH because it's a key in PuTTY format. But after converting the key with `puttygen`, I can connect to the SSH server as root and get the root flag.
