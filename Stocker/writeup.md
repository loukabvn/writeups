## [Stocker](https://app.hackthebox.com/machines/Stocker) - 19/04/2023 - HackTheBox write-up

### User flag

#### Discovery

When we start the challenge, we obtain an IP: `10.10.11.196`. We can start with a `nmap`:

We find 3 open ports:
    - 22/tcp : ssh
    - 80/tcp : http
    - 68/udp : dhcpc

The port 22 and 68 are not exploitable, so we are going to search on the website. After some fuzzing, with
`dirsearch` and `wfuzz` we didn't find any interesting pages, so I try to find subdomains with `gobuster`.

I found the subdomain [`dev.stocker.htb`](http://dev.stocker.htb) with a login page. The site use Express on an
Nginx server. After researches I found it uses MongoDB with NoSQL so I'll try NoSQL injection.

#### Exploitation

First, we can try to send an invalid JSON payload to see if JSON is parsed :
```json
{"username": "test",}
```

[!] Warning : don't forget to change the `Content-Type` to `application/json` or it will not work.

Now, we can use the NoSQL syntax to bypass the authentication, it works with the following payload :
```json
{"username": {"$ne":"test"},"password": {"$ne":"test"}}
```

We have an access to the `/stock` page.

#### Discovery

On this page, we can buy articles. We add articles to our cart and then when we can get a PDF file who resume our command.

It's the only page and functionality, so we will need to exploit the PDF itself.

#### Exploitation

After some researches I find this documentation about XSS with dynamic PDF [link](https://exploit-notes.hdks.org/exploit/web/security-risk/xss-with-dynamic-pdf/).

We can use it to find the path of the application on the system and then to read files. After some tries with files I find a password in the file `/var/www/dev/index.js` :
```
mongodb://dev:pass...
```

By looking at the file `/etc/passwd` before I found that there is only one classic user named `angoose`. So we can try to connect to the server by SSH with him :
```bash
ssh angoose@10.10.11.196
```

And it works ! We can now get the user flag.

### Root flag

#### Discovery

The root flag was found pretty quickly. With `sudo -l` we see :
```
(PASSWD) /usr/bin/node /usr/local/bin/*.js
```

We can execute JavaScript file with `node` in this directory as root user.

#### Exploitation

So we will just write a JS script to read the root flag :
```js
const fs = require('fs');

try {
  const data = fs.readFileSync('/root/root.txt', 'utf8');
  console.log(data);
} catch (err) {
  console.error(err);
}
```

The problem is : we cannot write file to directory `/usr/local/bin/` to run it with Node. But, this is an example of a bad sudoers rule : we can execute any JS script on the system with this, just with :
```bash
node /usr/local/bin/../../../home/angoose/read-flag.js
```

Finished, we just get the root flag.
