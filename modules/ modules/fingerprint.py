import socket

def analyze_device_fingerprint(ip, open_ports):
    device_type = "Generic Embedded Linux Appliance"
    banners = []
    
    if 554 in open_ports or 8080 in open_ports:
        device_type = "IP Surveillance Camera Node"
    elif 1883 in open_ports:
        device_type = "IoT Automation Hub Smart Gateway"
    elif 23 in open_ports:
        device_type = "Legacy Insecure IoT Node"
        
    for port in open_ports[:2]:
        try:
            s = socket.socket()
            s.settimeout(1.5)
            s.connect((ip, port))
            if port == 80 or port == 8080:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: localhost\r\n\r\n")
            banner = s.recv(512).decode('utf-8', errors='ignore').strip()
            if banner: 
                banners.append(f"Port {port}: {banner[:40]}")
            s.close()
        except Exception:
            pass
            
    print(f"  [+] Device Classified As: {device_type}")
    return {"classified_type": device_type, "grabbed_banners": banners}
