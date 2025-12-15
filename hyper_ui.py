

# Real IntelProbe scan and AI analysis (no simulation)
import socket
import threading
import requests
from datetime import datetime
from sklearn.ensemble import IsolationForest
import numpy as np

def port_scan(host, port, timeout=1):
    """Scan a single port on a host"""
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        result = sock.connect_ex((host, port))
        sock.close()
        return port if result == 0 else None
    except:
        return None

def real_scan(target="127.0.0.1", ports=[22, 23, 53, 80, 110, 135, 139, 443, 993, 995]):
    """Real port scanning using socket library"""
    print(f"Scanning {target} on ports {ports}...")
    open_ports = []
    
    def scan_port(port):
        if port_scan(target, port):
            open_ports.append(port)
    
    threads = []
    for port in ports:
        thread = threading.Thread(target=scan_port, args=(port,))
        threads.append(thread)
        thread.start()
    
    for thread in threads:
        thread.join()
    
    # Try to get hostname
    try:
        hostname = socket.gethostbyaddr(target)[0]
    except:
        hostname = "Unknown"
    
    results = [{
        'host': target,
        'hostname': hostname,
        'state': 'up' if open_ports else 'filtered',
        'tcp_ports': sorted(open_ports),
    }]
    
    return results

def ai_anomaly_detection(port_counts):
    # Use IsolationForest to detect anomalies in port counts
    X = np.array(port_counts).reshape(-1, 1)
    clf = IsolationForest(random_state=42)
    clf.fit(X)
    preds = clf.predict(X)
    anomalies = [i for i, p in enumerate(preds) if p == -1]
    return anomalies

def main():
    print("IntelProbe Real Scan & AI Analysis")
    print("-----------------------------------")
    scan_results = real_scan()
    port_counts = [len(r['tcp_ports']) for r in scan_results]
    print("\nScan Results:")
    for r in scan_results:
        print(f"Host: {r['host']} ({r['hostname']}) | State: {r['state']} | TCP Ports: {r['tcp_ports']}")
    print("\nAI Anomaly Detection (IsolationForest):")
    anomalies = ai_anomaly_detection(port_counts)
    if anomalies:
        print(f"Anomalous hosts detected at indices: {anomalies}")
        for idx in anomalies:
            r = scan_results[idx]
            print(f"- Host: {r['host']} ({r['hostname']}) | TCP Ports: {r['tcp_ports']}")
    else:
        print("No anomalies detected in port counts.")

if __name__ == "__main__":

    main()

