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
