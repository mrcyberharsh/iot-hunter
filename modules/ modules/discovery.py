import socket
from concurrent.futures import ThreadPoolExecutor

def auto_detect_network():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        local_ip = s.getsockname()[0]
        s.close()
        return local_ip
    except Exception:
        return "127.0.0.1"

def probe_port(ip, port, timeout):
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        if s.connect_ex((ip, port)) == 0:
            return port
    except Exception:
        pass
    finally:
        s.close()
    return None

def run_port_discovery(target_ip, timeout, threads):
    iot_ports = [21, 22, 23, 80, 443, 554, 1883, 8080]
    open_ports = []
    print(f"\n[*] Scanning target ports on IP: {target_ip}")
    
    with ThreadPoolExecutor(max_workers=threads) as executor:
        futures = [executor.submit(probe_port, target_ip, port, timeout) for port in iot_ports]
        for future in futures:
            res = future.result()
            if res is not None:
                open_ports.append(res)
                print(f"  [+] Open Port Detected: {res}")
    return open_ports
