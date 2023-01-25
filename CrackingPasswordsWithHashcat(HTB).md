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
  hashcat -a 0 -m 1000 7106812752615cdfe427e01b98cd4083 /opt/useful/SecLists/Passwords/Leaked-Databases/rockyou
  
  
  
  
  
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
