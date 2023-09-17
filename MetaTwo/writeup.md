## [MetaTwo](https://app.hackthebox.com/machines/MetaTwo) - 07/04/2023 - HackTheBox write-up

### User flag

#### Discovery

When we start the challenge, we obtain an IP: `10.10.11.186`. We can start with a `nmap`:

We find 3 open ports:
    - 21 ftp
    - 22 ssh
    - 80 http

If we try to access `http://10.10.11.186`, we are redirected to `metapress.htb` (tip: we need to add the domain name to `/etc/hosts`).

#### Search for vulnerability

The web server hosts a WordPress application (version 5.6.2). When running a `wpscan` on the server we can find that it's vulnerable to a lot of CVEs (29).

We can't try it all, so we explore the site to find the vulnerability.

The WP app offer only one possibility: register for an event using the `bookingpress-appointement` (version 1.0.10) plugin.
When searching for `bookingpress-appointement Wordpress CVE` on the net we can find that the plugin is vulnerable to a SQL injection before version 1.0.11
([CVE-2022-21661](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2022-21661)).

Our version is just before, so we can deduce that it's probably this CVE to exploit.

#### Exploitation

When register for an event with this plugin, the server generate a request with a lot of parameter and this event will be store in a database.
The parameter `total_service` isn't correctly escaped and we can exploit it with a union SQLi. We will need the nonce of the plugin to send the request.

With `sqlmap` we can confirm this and then, dump the tables :
```bash
sqlmap -r post_req.txt -p total_service
sqlmap -r post_req.txt -p total_service --tables
sqlmap -r post_req.txt -p total_service -T wp_users --dump
```

We obtain a table with two users and their passwords :
```
admin   | $P$BGrGrgf2wToBS79i07Rk9sN4Fzk.TV.
manager | $P$B4aNM28N0E.tMy/JIcnVMZbGcU16Q70
```

With `john` we can try to crack both of the hashes. It uses PHPASS hash format (MD5 with key stretching).
Quickly we can find `manager` password : `partylikearockstar`, but we cannot crack the admin password, it would be to easy.

Now, we have an account on the WordPress server. We can authenticate at `http://metapress.htb/wp-login.php`.

### Root flag

#### Discovery

The manager have a limited access to the application. We can the do the following actions :
    - Update our profile
    - Upload a media file (video, music, image...)
    - ...

The interesting part of this is probably the upload file functionality, other options may not be useful.
After trying some classics file upload vulnerability test, I realised that it wasn't so simple, WordPress isn't so broken.

#### Search for vulnerability

If we return to the `wpscan`, there is an interesting CVE with the media upload functionality ([CVE-2021-29447](https://cve.mitre.org/cgi-bin/cvename.cgi?name=CVE-2021-29447)).
It's exploitable between version 5.6.0 and 5.7.0 of WordPress, so it's probably this vulnerability to exploit.

It's an XXE (External XML Entity), we can read arbitrary file on the server by inject a malicious XML payload in a WAV file.

#### Exploitation

After searching, we can find a POC of this vulnerability explaining how it works and a link to a GitHub with a script to create the WAV
exploit ([article](https://dl.packetstormsecurity.net/2106-exploits/CVE-2021-29447.pdf) and [POC](https://github.com/Vulnmachines/wordpress_cve-2021-29447/blob/main/CVE-2021-29447.zip)).

We need to specify the file on the server to read in the WAV file and start a server on our machine or on a server we control to host the malicious XML file.

We can create a server in PHP, in a specified directory, with :
```php
php -S 0.0.0.0:8001 -t www
```

Now, we can read any file on the server. To find other credentials and secrets we can read the file `wp-config.php`.
With the CVE after uploading the WAV file, we receive the content of the file base64 encoded on our server.

Once decoded we can read the following :
```php
define( 'FTP_USER', 'metapress.htb' );
define( 'FTP_PASS', '9NYS_ii@FyL_p5M2NvJ' );
```

We can find in this file credentials of an account to connect to the FTP server we find before with the `nmap`.
Now we can connect to the server and read any file more easily than with the XXE vulnerability.

On the FTP server we find two directories : `blog` and `mailer`. After searching in `blog` we didn't find anything but in `mailer` we can find a file `send_email.php` with others credentials :
```php
$mail->Username = "jnelson@metapress.htb";                 
$mail->Password = "Cb4_JmWM8zUZWMu@Ys";
```

This credentials looks like FTP or SSH credentials so we can try those protocols. It works with SSH, so we now have an access to the server directly with SSH, and we obtain the user flag.

Now, we have to find the root flag to own the system. In the user directory we can find many dotfiles. We find a `.config`, `.passpie`, with `.ssh` and `.keys`. Users use `passpie`, a CLI password database.

We find keys, enciphered message and finally a PGP file probably containing the `passpie` data. Then we have to try to crack it with `john`, and it succeeds, with the password `blink182`.

We can now open the `passpie` database and get the `root` password. The `root` user cannot connect with SSH to the server so we switch with `su root` and get the flag.
