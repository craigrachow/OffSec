## Identifying Hashes
# install hashid
pip install hashid
# install Hashcat
sudo apt install hashcat

# Hashid Usage
hashid '$DCC2$10240#tom#e4e938d12fe5974dc42a90120bd9c90f' -m


# Hashcat Syntax
hashcat -a 0 -m <hash type> <hash file> <wordlist>
hashcat -a 0 -m 1400 sha256_hash_example /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
for 2 wordlists
hashcat -a 1 -m 1400 sha256_hash_example something.txt rockyou.txt  
  maskattack
  hashcat -a 3 -m 0 50a742905949102c961929823a2e8ca0 -1 02 'HASHCAT?l?l?l?l?l20?1?d'
  hybrid hash or mash
  hashcat -a 6 -m 0 hybrid_hash /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt '?d?s'
  hashcat -a 7 -m 0 978078e7845f2fb2e20399d9e80475bc1c275e06 -1 01 '?d?s' /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
  
  hashcat -a 7 -m 0 46244749d1e8fb99c37ad4f14fccb601ed4ae283 -1 01 '$2020' /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt
  
  
  
## Questions ##
#  Crack the following SHA1 hash using the techniques taught for generating a custom rule: 46244749d1e8fb99c37ad4f14fccb601ed4ae283. Modify the example rule in the beginning of the section to append 2020 to the end of each password attempt.
  echo 'so0 si1 se3 ss5 sa@ c $2 $0 $2 $0' > rule3.txt
   hashcat -a 0 -m 100 46244749d1e8fb99c37ad4f14fccb601ed4ae283 /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou-75.txt -r rule3.txt

#Crack the following hash: 7106812752615cdfe427e01b98cd4083
  hashcat -a 0 -m 1000 -g 1000 7106812752615cdfe427e01b98cd4083 /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou
  
#Extract the hash from the attached 7-Zip file, crack the hash, and submit the value of the flag.txt file contained inside the archive.
  Follow this site https://infinitelogins.com/2020/04/29/how-to-crack-encrypted-7z-archives/
  unzip Misc_hashes.zip THEN export has from hashcat.7z file
  locate 7z2john.pl THEN /usr/share/john/7z2john.pl hashcat.7z > hashN  IF ERROR sudo apt install libcompress-raw-lzma-perl -y
  remove first 10 characters from hash file.
  hashcat -m 11600 hashN /usr/share/wordlists/rockyou.txt
  7z x hashcat.7z



  
  
    Cheat Sheet
The cheat sheet is a useful command reference for this module.

Command	Description
 pip install hashid	Install the hashid tool
hashid <hash> OR hashid <hashes.txt>	Identify a hash with the hashid tool
hashcat --example-hashes	View a list of Hashcat hash modes and example hashes
hashcat -b -m <hash mode>	Perform a Hashcat benchmark test of a specific hash mode
hashcat -b	Perform a benchmark of all hash modes
hashcat -O	Optimization: Increase speed but limit potential password length
hashcat -w 3	Optimization: Use when Hashcat is the only thing running, use 1 if running hashcat on your desktop. Default is 2
hashcat -a 0 -m <hash type> <hash file> <wordlist>	Dictionary attack
hashcat -a 1 -m <hash type> <hash file> <wordlist1> <wordlist2>	Combination attack
hashcat -a 3 -m 0 <hash file> -1 01 'ILFREIGHT?l?l?l?l?l20?1?d'	Sample Mask attack
hashcat -a 7 -m 0 <hash file> -1=01 '20?1?d' rockyou.txt	Sample Hybrid attack
crunch <minimum length> <maximum length> <charset> -t <pattern> -o <output file>	Make a wordlist with Crunch
python3 cupp.py -i	Use CUPP interactive mode
kwp -s 1 basechars/full.base keymaps/en-us.keymap routes/2-to-10-max-3-direction-changes.route	Kwprocessor example
cewl -d <depth to spider> -m <minimum word length> -w <output wordlist> <url of website>	Sample CeWL command
hashcat -a 0 -m 100 hash rockyou.txt -r rule.txt	Sample Hashcat rule syntax
./cap2hccapx.bin input.cap output.hccapx	cap2hccapx syntax
hcxpcaptool -z pmkidhash_corp cracking_pmkid.cap	hcxpcaptoolsyntax
  
  
  
  
Very good 
https://cheatsheet.haax.fr/
https://hashcat.net/wiki/doku.php?id=example_hashes
Cracking MIC
Hashcat-Utils - Installation
git clone https://github.com/hashcat/hashcat-utils.git
CRAIG Rachow@htb[/htb]$ cd hashcat-utils/src
CRAIG Rachow@htb[/htb]$ make



./cap2hccapx.bin 


usage: ./cap2hccapx.bin input.cap output.hccapx [filter by essid] [additional network essid:bssid]
Cap2hccapx - Convert To Crackable File
CRAIG Rachow@htb[/htb]$ ./cap2hccapx.bin corp_capture1-01.cap mic_to_crack.hccapx
hashcat -a 0 -m 22000 mic_to_crack.hccapx /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt.


Cracking PMKID
sudo apt install hcxtools.
git clone https://github.com/ZerBea/hcxtools.git
CRAIG Rachow@htb[/htb]$ cd hcxtools
CRAIG Rachow@htb[/htb]$ make && make install
Sudo apt install hcxtools -y

hcxpcaptool -z pmkidhash_corp cracking_pmkid.cap   OR   hcxpcapngtool cracking_pmkid.cap -o pmkidhash_corp2

Check file to see hash cat pmkidhash_corp
hashcat -a 0 -m 22000 pmkidhash_corp /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt




What type of hash did your colleague obtain from the SQL injection attack? SHA-1
hashid 0c67ac18f50c5e6b9398bfe1dc3e156163ba10ef 

What is the cleartext password for the hash obtained from SQL injection in example 1?
hashcat -a 0 -m 100 0c67ac18f50c5e6b9398bfe1dc3e156163ba10ef /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt

What is the cleartext password value for the NetNTLMv2 hash?
bjones::INLANEFREIGHT:699f1e768bd69c00:5304B6DB9769D974A8F24C4F4309B6BC:0101000000000000C0653150DE09D2010409DF59F277926E000000000200080053004D004200330001001E00570049004E002D00500052004800340039003200520051004100460056000400140053004D00420033002E006C006F00630061006C0003003400570049004E002D00500052004800340039003200520051004100460056002E0053004D00420033002E006C006F00630061006C000500140053004D00420033002E006C006F00630061006C0007000800C0653150DE09D20106000400020000000800300030000000000000000000000000300000B14866125D55255DD82C994C0D8AC3D9FF1A3EFDAECBE908F1F91C7BD4B05CF50A001000000000000000000000000000000000000900280063006900660073002F003100390032002E003100360038002E003100390035002E00310032003900000000000000000000000000
hashcat -a 0 -m 5600 ntlm.txt /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt

Crack the TGS ticket obtained from the Kerberoasting attack.
$krb5tgs$23$*sql_svc$INLANEFREIGHT.LOCAL$mssql/inlanefreight.local~1443*$80be357f5e68b4f64a185397bf72cf1c$579d028f0f91f5791683844c3a03f48972cb9013eddf11728fc19500679882106538379cbe1cb503677b757bcb56f9e708cd173a5b04ad8fc462fa380ffcb4e1b4feed820fa183109e2653b46faee565af76d5b0ee8460a3e0ad48ea098656584de67974372f4a762daa625fb292556b407c0c97fd629506bd558dede0c950a039e2e3433ee956fc218a54b148d3e5d1f99781ad4e419bc76632e30ea2c1660663ba9866230c790ba166b865d5153c6b85a184fbafd5a4af6d3200d67857da48e20039bbf31853da46215cbbc5ebae6a3b0225b6651ec8cc792c8c3d5893a8d014f9d297ac297288e76d27a1ed2942d6997f6b24198e64fea9ff5a94badd53cc12a73e9505e4dab36e4bd1ef7fe5a08e527d9046b49e730d83d8af395f06fe35d360c59ab8ebe2c3b7553acf8d40c296b86c1fb26fdf43fa8be2ac4a92152181b81afb1f4773936b0ccc696f21e8e0fe7372252b3c24d82038c62027abc34a4204fb6e52bf71290fdf0db60b1888f8369a7917821f6869b6e51bda15f1fd7284ca1c37fb2dc46c367046a15d093cc501f3155f1e63040313cc8db2a8437ee6dc8ceb04bf924427019b396667f0532d995e3d655b9fb0ef8e61b31e523d81914d9eb177529783c29788d486139e1f3d29cbe4d2f881c61f74ff32a9233134ec69f26082e8aaa0c0e99006a5666c24fccfd195796a0be97cecb257259a640641f8c2d58d2d94452ec00ad84078afc1f7f72f3b9e8210b5db73bf70cd13ef172ef3b233c987d5ec7ea12a4d4921a43fb670c9f48aaae9e1d48ec7be58638a8b2f89a62b56775deddbbc971803316470ee416d8a6c0c8d17982396f6c0c0eeec425d5c599fb60b5c39f8e9ceff4ee25c5bc953178972de616edae61586bb868e463f420e9e09c083662bcf6f0f522f78630792e02e6986f5dd042dfb70100ab59d8a01093b3d89949ea19fe9c596a8681e2a71abe75debd62b985d03d488442aa41cc8993eff0224de62221d39be8bf1d8b26f8f8768e90e5b4b886adaf02a19f55e6d1fd11b004d4e7b170c4f7feaa04b8dad207d6f863d50a251d9a9ce66951de41a3690fec6144e73428d4718cc7ec5eeeff841b4329a7ba51624f678557b6eafc55af026314cbf9dd9ca232977da3cce204899f3048101e0010f42d0076cd494526beea862c72ee48749ba071bcdd1a96c64a0d8f48c6acad7730121021be6323f69505aad8fb6281b7ac4a607d1d241f1fbffc70c4a74c997bb2fb77c452c0077efdea2a6c00704a8bee28326b5e554e1faa48a33963ce2c2e0e2446b4504a05d541bbaf531e1644ad92a2feae5b2eb8851b067e7bd8d7d23d82e63d368983ba44f52901cba7e05cfa35e832ec445a7de50eca670fa90
hashcat -a 0 -m 13100 kerb.txt /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt


What is the cleartext password value for the MS Cache 2 hash?
$DCC2$10240#backup_admin#62dabbde52af53c75f37df260af1008e
hashcat -a 0 -m 2100 ad.txt /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt


After cracking the NTLM password hashes contained in the NTDS.dit file, perform an analysis of the results and find out the MOST common password in the INLANEFREIGHT.LOCAL domain.
Eg of password line  = INLANEFREIGHT\Nicholas.Jackson:1122:aad3b435b51404eeaad3b435b51404ee:db3a9af5e74be03220d213b47ef25b53:::
hashcat -a 0 -m 1000 --username -o cracked.txt DC01.inlanefreight.local.ntds /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt

+ 1  Crack the following hash: 978078e7845f2fb2e20399d9e80475bc1c275e06 using the mask ?d?s.
hashcat -a 6 -m 100 978078e7845f2fb2e20399d9e80475bc1c275e06 /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou.txt '?d?s'









