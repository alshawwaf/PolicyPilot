#!/usr/bin/env python3
"""Capture how a REAL vCenter encodes its root folder in a WaitForUpdatesEx response.

Replays the minimal handshake (RetrieveServiceContent -> Login -> CreateFilter -> WaitForUpdatesEx)
with a filter scoped to JUST the root folder, requesting exactly the properties CloudGuard asks for
(name, parent, childEntity, childType). Prints the raw <objectSet> XML so we can match the wire
format byte-for-byte in the simulator.

stdlib only. Usage:
    python3 capture_vcenter_root.py <vcenter-host-or-ip> <username> '<password>'
Nothing is stored; credentials are used only for this one live session and never written out.
"""
import re
import ssl
import sys
from http.client import HTTPSConnection

if len(sys.argv) < 4:
    sys.exit("usage: python3 capture_vcenter_root.py <host> <username> '<password>'")
HOST, USER, PWD = sys.argv[1], sys.argv[2], sys.argv[3]

_CTX = ssl._create_unverified_context()  # lab vCenter, self-signed cert
_cookie = None
_ENV = ('<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" '
        'xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:urn="urn:vim25">'
        "<soapenv:Body>{}</soapenv:Body></soapenv:Envelope>")


def _esc(s: str) -> str:
    return s.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")


def soap(inner: str) -> str:
    global _cookie
    conn = HTTPSConnection(HOST, 443, context=_CTX, timeout=30)
    headers = {"Content-Type": "text/xml; charset=utf-8", "SOAPAction": '"urn:vim25/8.0.0.1"'}
    if _cookie:
        headers["Cookie"] = _cookie
    conn.request("POST", "/sdk", _ENV.format(inner), headers)
    resp = conn.getresponse()
    setc = resp.getheader("Set-Cookie")
    if setc:
        _cookie = setc.split(";")[0]
    body = resp.read().decode("utf-8", "replace")
    conn.close()
    return body


sc = soap('<urn:RetrieveServiceContent><urn:_this type="ServiceInstance">ServiceInstance'
          "</urn:_this></urn:RetrieveServiceContent>")
root = re.search(r'<rootFolder type="Folder">([^<]+)</rootFolder>', sc)
pc = re.search(r'<propertyCollector type="PropertyCollector">([^<]+)</propertyCollector>', sc)
sm = re.search(r'<sessionManager type="SessionManager">([^<]+)</sessionManager>', sc)
if not (root and pc and sm):
    sys.exit("RetrieveServiceContent failed:\n" + sc[:1000])
root, pc, sm = root.group(1), pc.group(1), sm.group(1)
print(f"rootFolder={root}  propertyCollector={pc}")

login = soap(f'<urn:Login><urn:_this type="SessionManager">{sm}</urn:_this>'
             f"<urn:userName>{_esc(USER)}</urn:userName><urn:password>{_esc(PWD)}</urn:password></urn:Login>")
if "<urn:LoginResponse" not in login and "LoginResponse" not in login:
    sys.exit("Login failed:\n" + login[:1000])
print("login OK\n")

# Filter scoped to ONLY the root folder (no traversal), exactly CloudGuard's Folder propSet.
cf = soap(f'<urn:CreateFilter><urn:_this type="PropertyCollector">{pc}</urn:_this><urn:spec>'
          "<urn:propSet><urn:type>Folder</urn:type><urn:all>false</urn:all>"
          "<urn:pathSet>name</urn:pathSet><urn:pathSet>parent</urn:pathSet>"
          "<urn:pathSet>childEntity</urn:pathSet><urn:pathSet>childType</urn:pathSet></urn:propSet>"
          f'<urn:objectSet><urn:obj type="Folder">{root}</urn:obj><urn:skip>false</urn:skip>'
          "</urn:objectSet></urn:spec><urn:partialUpdates>false</urn:partialUpdates></urn:CreateFilter>")
if "returnval" not in cf:
    sys.exit("CreateFilter failed:\n" + cf[:1000])

wu = soap(f'<urn:WaitForUpdatesEx><urn:_this type="PropertyCollector">{pc}</urn:_this>'
          "<urn:version></urn:version><urn:options></urn:options></urn:WaitForUpdatesEx>")

print("===== REAL vCenter root-folder objectSet (paste this back) =====")
m = re.search(r"<(?:\w+:)?objectSet>.*?</(?:\w+:)?objectSet>", wu, re.S)
print(m.group(0) if m else wu)

soap(f'<urn:Logout><urn:_this type="SessionManager">{sm}</urn:_this></urn:Logout>')
