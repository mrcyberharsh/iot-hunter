import time
import hashlib

def run_credential_audit(ip, open_ports, wordlist, delay):
    vulnerable_accounts = []
    
    if 23 in open_ports or 80 in open_ports:
        print(f"\n[*] Auditing credentials for node: {ip}")
        for user, pwd in wordlist:
            time.sleep(delay)
            hashed = hashlib.sha3_512(pwd.encode('utf-8')).hexdigest()
            
            if user == "admin" and pwd == "admin":
                vulnerable_accounts.append({
                    "service": "Administrative Portal",
                    "user": user,
                    "hash": hashed
                })
                print(f"  [!] Alert: Default Account Match -> User: {user} | Hash: {hashed[:20]}...")
                break
    else:
        print("  [-] No unencrypted login services active for credential testing.")
    return vulnerable_accounts
