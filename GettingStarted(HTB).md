# GettingStarted(HTB)
Lessons and Tutorials Covered

## NCAT
# netcat can be used to connect to any listening port and interact with the service running on that port.
> ncat ip port 
> nc -nv ip port

## NMAP
# port scanner
> nmap -sV -sC -p- 10.129.42.253
> nmap -sV --script=banner -p21 10.10.10.0/24
> nmap -sC -sV -p21 10.129.42.253

> locate scripts/citrix
> nmap --script <script name> -p<port> <host>
  
  ## Connecting 
  # ftp = 
  ftp -p 10.129.42.253
  
  
  

* File Inclusion / Directory Traversal (HTB Academy)
* Linux Fundermentals (HTB Academy)
* Login Attacks (HTB Academy)
* Metasploit (HTB Academy)
* Nmap (HTB Academy)
* Web Enumeration
* Windows Fundermentals (HTB Academy)

##### Connect to VPN
> sudo openvpn user.ovpn
